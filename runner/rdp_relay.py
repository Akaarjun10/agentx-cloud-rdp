#!/usr/bin/env python3
"""
Runner-side RDP relay: bridges the local RDP server (127.0.0.1:3389) to the
Cloudflare Durable Object over one outbound WebSocket.

Two client modes, auto-detected from the first binary frame after attach:
  - RDCleanPath (browser WASM client, ironrdp-web): the first frame is a
    DER-encoded RDCleanPathPdu (SEQUENCE, version 3390) wrapping the client's
    X.224 Connection Request. The relay performs the RDCleanPath handshake:
    forwards the X.224 to 3389, completes a TLS handshake to capture the
    server certificate, and replies with the DER-encoded RDCleanPath response
    (X.224 confirm + server cert chain). Afterwards it is a plain byte pump
    while the browser does TLS + CredSSP end-to-end with the RDP server.
  - Raw RDP (mstsc via client/rdp_client_proxy.py): the first frame is a
    TPKT X.224 request. The relay opens TCP immediately and pumps bytes.

Wire protocol with the DO is unchanged (text JSON control frames, binary
data frames); mode detection is purely local to this relay.

Env: WORKER_URL (https://<name>.workers.dev), RELAY_SECRET.
"""

import asyncio
import json
import os
import sys

try:
    import websockets
except ImportError:
    sys.exit("websockets package missing: pip install websockets")

RDP_HOST, RDP_PORT = "127.0.0.1", 3389
WORKER_URL = os.environ["WORKER_URL"].rstrip("/")
RELAY_SECRET = os.environ["RELAY_SECRET"]
RELAY_WS = (
    WORKER_URL.replace("https://", "wss://").replace("http://", "ws://")
    + "/rdp?secret="
    + RELAY_SECRET
)
CHUNK = 65536
RDCLEANPATH_VERSION = 3390  # BASE_VERSION (3389) + 1


# ---------------------------------------------------------------- minimal DER

def _der_tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 128:
        ln = bytes([n])
    else:
        lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(lb)]) + lb
    return bytes([tag]) + ln + content


def _der_read(buf: bytes, pos: int):
    """Parse one TLV at pos. Returns (tag, content, next_pos)."""
    tag = buf[pos]
    pos += 1
    first = buf[pos]
    pos += 1
    if first & 0x80:
        cnt = first & 0x7F
        if cnt == 0 or cnt > 4:
            raise ValueError("bad DER length")
        length = int.from_bytes(buf[pos:pos + cnt], "big")
        pos += cnt
    else:
        length = first
    content = buf[pos:pos + length]
    if len(content) != length:
        raise ValueError("truncated DER")
    return tag, content, pos + length


def parse_rdcleanpath_request(data: bytes):
    """Parse a client RDCleanPathPdu request. Returns dict or None."""
    try:
        if not data or data[0] != 0x30:  # must start with SEQUENCE
            return None
        tag, content, pos = _der_read(data, 0)
        if tag != 0x30 or pos != len(data):
            return None
        fields = {}
        p = 0
        while p < len(content):
            ctag, ccontent, p = _der_read(content, p)
            if (ctag & 0xC0) != 0x80:  # must be context-specific
                return None
            n = ctag & 0x1F
            itag, icontent, ipos = _der_read(ccontent, 0)
            if ipos != len(ccontent):  # EXPLICIT wraps exactly one TLV
                return None
            if n == 0 and itag == 0x02:  # [0] version INTEGER
                fields["version"] = int.from_bytes(icontent, "big", signed=True)
            elif n == 2 and itag == 0x0C:  # [2] destination UTF8String
                fields["destination"] = icontent.decode("utf-8", "replace")
            elif n == 3 and itag == 0x0C:  # [3] proxy_auth UTF8String
                fields["proxy_auth"] = icontent.decode("utf-8", "replace")
            elif n == 5 and itag == 0x0C:  # [5] preconnection_blob UTF8String
                fields["preconnection_blob"] = icontent.decode("utf-8", "replace")
            elif n == 6 and itag == 0x04:  # [6] x224_connection_pdu OCTET STRING
                fields["x224"] = bytes(icontent)
            # other fields are not sent by the client; ignore them
        if fields.get("version") != RDCLEANPATH_VERSION or "x224" not in fields:
            return None
        return fields
    except Exception:
        return None


def build_rdcleanpath_response(x224_resp: bytes, cert_der: bytes,
                              server_addr: str = "127.0.0.1") -> bytes:
    """Build the proxy->client RDCleanPathPdu response (DER)."""
    ver = _der_tlv(0xA0, _der_tlv(0x02, RDCLEANPATH_VERSION.to_bytes(2, "big")))
    x224 = _der_tlv(0xA6, _der_tlv(0x04, x224_resp))
    chain = _der_tlv(0xA7, _der_tlv(0x30, _der_tlv(0x04, cert_der)))
    addr = _der_tlv(0xA9, _der_tlv(0x0C, server_addr.encode()))
    return _der_tlv(0x30, ver + x224 + chain + addr)


def build_rdcleanpath_error() -> bytes:
    """Build a generic RDCleanPath error PDU (DER)."""
    err_inner = _der_tlv(0x30, _der_tlv(0xA0, _der_tlv(0x02, b"\x01")))
    ver = _der_tlv(0xA0, _der_tlv(0x02, RDCLEANPATH_VERSION.to_bytes(2, "big")))
    return _der_tlv(0x30, ver + _der_tlv(0xA1, err_inner))


# ------------------------------------------------- blocking handshake helpers

def _recvall(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read from RDP server")
        buf += chunk
    return buf


def rdcleanpath_handshake(x224_req: bytes, timeout: float = 15.0):
    """
    Perform the proxy side of the RDCleanPath handshake on a throwaway
    connection: send the client's X.224, read the server's X.224 confirm,
    then complete a TLS handshake to capture the server certificate.
    Returns (x224_resp, cert_der). Raises on failure.
    Runs in a thread (blocking sockets); the session itself uses a fresh
    connection afterwards so the client owns the TLS handshake end-to-end.
    """
    import socket
    import ssl

    s = socket.create_connection((RDP_HOST, RDP_PORT), timeout=timeout)
    try:
        s.sendall(x224_req)
        hdr = _recvall(s, 4)
        if hdr[0] != 0x03:  # TPKT version
            raise ValueError("RDP server did not answer X.224 with TPKT")
        total = int.from_bytes(hdr[2:4], "big")
        if total < 4 or total > 65535:
            raise ValueError("bad TPKT length in X.224 response")
        x224_resp = hdr + _recvall(s, total - 4)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(s, server_hostname=None)
        try:
            tls.do_handshake()
            cert_der = tls.getpeercert(binary_form=True)
        finally:
            try:
                tls.close()  # also closes the underlying socket
            except Exception:
                pass
        if not cert_der:
            raise ValueError("RDP server presented no certificate")
        return x224_resp, cert_der
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        raise


async def _read_tpkt_async(reader) -> bytes:
    hdr = await reader.readexactly(4)
    if hdr[0] != 0x03:
        raise ValueError("not a TPKT frame")
    total = int.from_bytes(hdr[2:4], "big")
    if total < 4 or total > 65535:
        raise ValueError("bad TPKT length")
    return hdr + await reader.readexactly(total - 4)


# ------------------------------------------------------------------ relay

async def run_once():
    # NOTE: websockets library ping/pong is DISABLED (ping_interval=None).
    # Cloudflare DO WebSockets do not reliably answer ping frames, and a
    # ping_timeout would falsely kill a healthy uplink. The relay's reconnect
    # loop in main() handles real drops. A periodic application heartbeat
    # below keeps the DO from going idle.
    async with websockets.connect(
        RELAY_WS, max_size=64 * 1024 * 1024, ping_interval=None, ping_timeout=None,
        open_timeout=30,
    ) as ws:
        print("relay: connected to DO", flush=True)

        reader = writer = None
        pump_task = None
        gen = 0  # attach generation; stale pumps must not signal local_closed
        awaiting_first_frame = False

        async def tcp_pump(my_gen):
            try:
                while True:
                    data = await reader.read(CHUNK)
                    if not data:
                        break
                    await ws.send(data)
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            finally:
                # Only report local_closed if this pump is still the current
                # generation (a detach() cancels the pump without reporting).
                if my_gen == gen:
                    try:
                        await ws.send(json.dumps({"type": "local_closed"}))
                    except Exception:
                        pass

        async def start_pump():
            nonlocal reader, writer, pump_task, gen
            if writer is not None:
                return True
            try:
                reader, writer = await asyncio.open_connection(RDP_HOST, RDP_PORT)
            except Exception as e:
                print(f"relay: local RDP unreachable: {e}", flush=True)
                try:
                    await ws.send(json.dumps({"type": "local_closed"}))
                except Exception:
                    pass
                return False
            gen += 1
            pump_task = asyncio.create_task(tcp_pump(gen))
            return True

        async def do_rdcleanpath(fields) -> bool:
            """Run the RDCleanPath handshake, then bridge a fresh connection."""
            nonlocal reader, writer, pump_task, gen
            x224_req = fields["x224"]
            print("relay: RDCleanpath client detected, handshaking", flush=True)
            try:
                x224_resp, cert_der = await asyncio.to_thread(
                    rdcleanpath_handshake, x224_req
                )
            except Exception as e:
                print(f"relay: RDCleanPath handshake failed: {e}", flush=True)
                try:
                    await ws.send(build_rdcleanpath_error())
                except Exception:
                    pass
                return False
            try:
                await ws.send(build_rdcleanpath_response(x224_resp, cert_der))
            except Exception as e:
                print(f"relay: failed to send RDCleanPath response: {e}", flush=True)
                return False
            # Fresh connection for the actual session: replay the X.224 so the
            # server is waiting for the client's TLS handshake, then pump bytes.
            try:
                reader, writer = await asyncio.open_connection(RDP_HOST, RDP_PORT)
                writer.write(x224_req)
                await writer.drain()
                await _read_tpkt_async(reader)  # server confirm; discard
            except Exception as e:
                print(f"relay: session connection failed: {e}", flush=True)
                try:
                    await ws.send(json.dumps({"type": "local_closed"}))
                except Exception:
                    pass
                reader = writer = None
                return False
            gen += 1
            pump_task = asyncio.create_task(tcp_pump(gen))
            print("relay: RDCleanPath handshake done, session bridged", flush=True)
            return True

        async def handle_first_frame(data: bytes):
            nonlocal awaiting_first_frame
            awaiting_first_frame = False
            fields = parse_rdcleanpath_request(data)
            if fields is not None:
                await do_rdcleanpath(fields)
                return
            # Raw RDP client (mstsc via proxy): open TCP and forward as-is.
            if await start_pump():
                try:
                    writer.write(data)
                    await writer.drain()
                except Exception:
                    pass
                print("relay: raw RDP client bridged", flush=True)

        async def attach():
            nonlocal awaiting_first_frame
            if writer is not None or awaiting_first_frame:
                return
            # Don't open TCP yet: the first binary frame tells us whether this
            # is an RDCleanPath (browser) or raw RDP (mstsc) client.
            awaiting_first_frame = True
            print("relay: client attached, detecting mode", flush=True)

        async def detach():
            nonlocal reader, writer, pump_task, gen, awaiting_first_frame
            gen += 1  # invalidate the current pump's local_closed report
            awaiting_first_frame = False
            if pump_task is not None:
                pump_task.cancel()
                pump_task = None
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
                reader = writer = None

        async def heartbeat():
            # Periodic liveness marker in the log + keeps the DO active.
            # Runs until cancelled when run_once() exits.
            try:
                while True:
                    await asyncio.sleep(60)
                    print("relay: heartbeat (uplink alive)", flush=True)
            except asyncio.CancelledError:
                pass

        hb_task = asyncio.create_task(heartbeat())
        try:
            async for msg in ws:  # single consumer: binary=data, text=control
                if isinstance(msg, bytes):
                    if awaiting_first_frame:
                        await handle_first_frame(msg)
                    elif writer is not None:
                        try:
                            writer.write(msg)
                            await writer.drain()
                        except Exception:
                            pass
                    continue
                try:
                    ctl = json.loads(msg)
                except Exception:
                    continue
                t = ctl.get("type")
                if t == "attach":
                    await attach()
                elif t == "detach":
                    await detach()
                    print("relay: client detached", flush=True)
        finally:
            hb_task.cancel()
            await detach()


async def main():
    backoff = 2
    while True:
        try:
            await run_once()
            print("relay: uplink closed cleanly, reconnecting", flush=True)
        except Exception as e:
            print(f"relay: uplink lost ({type(e).__name__}: {e}), retrying in {backoff}s",
                  flush=True)
        except BaseException as e:
            # CancelledError/SystemExit etc: log and re-raise so the process
            # does not silently spin.
            print(f"relay: fatal ({type(e).__name__}: {e})", flush=True)
            raise
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 60)


if __name__ == "__main__":
    asyncio.run(main())
