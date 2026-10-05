#!/usr/bin/env python3
"""
WebSocket-to-RDP bridge for Cloudflare Tunnel.

Listens on 127.0.0.1:8080 for WebSocket connections (forwarded by cloudflared).
For each client, performs the RDCleanPath handshake with the local RDP server
(127.0.0.1:3389), terminating TLS at the proxy, then bridges plaintext RDP
over the WebSocket.

This replaces the fragile Durable Object relay architecture. cloudflared
handles reconnection automatically; no singleton to fight over.

Usage: python ws_rdp_bridge.py
Env: BRIDGE_PORT (default 8080), RDP_HOST (default 127.0.0.1), RDP_PORT (default 3389)
"""

import asyncio
import os
import socket
import ssl
import sys

try:
    import websockets
except ImportError:
    sys.exit("websockets package missing: pip install websockets")

RDP_HOST = os.environ.get("RDP_HOST", "127.0.0.1")
RDP_PORT = int(os.environ.get("RDP_PORT", "3389"))
BRIDGE_PORT = int(os.environ.get("BRIDGE_PORT", "8080"))
CHUNK = 65536
RDCLEANPATH_VERSION = 3390


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
    tag = buf[pos]; pos += 1
    first = buf[pos]; pos += 1
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
    try:
        if not data or data[0] != 0x30:
            return None
        tag, content, pos = _der_read(data, 0)
        if tag != 0x30 or pos != len(data):
            return None
        fields = {}
        p = 0
        while p < len(content):
            ctag, ccontent, p = _der_read(content, p)
            if (ctag & 0xC0) != 0x80:
                return None
            n = ctag & 0x1F
            itag, icontent, ipos = _der_read(ccontent, 0)
            if ipos != len(ccontent):
                return None
            if n == 0 and itag == 0x02:
                fields["version"] = int.from_bytes(icontent, "big")
            elif n == 2 and itag == 0x0C:
                fields["target"] = icontent.decode()
            elif n == 3 and itag == 0x0C:
                fields["auth"] = icontent.decode()
            elif n == 1:
                # [1] wraps the X.224 (tag varies, take raw inner content)
                fields["x224"] = icontent
            elif n == 5 and itag == 0x0C:
                fields["preconnection_blob"] = icontent.decode("utf-8", "replace")
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
    inner = _der_tlv(0xA0, _der_tlv(0x02, (0).to_bytes(2, "big")))
    return _der_tlv(0x30, inner)


def rdcleanpath_handshake(x224_req: bytes):
    """Perform RDCleanPath handshake with the RDP server.
    Returns (x224_response, cert_der, tls_socket)."""
    # 1. Open TCP to RDP server, send X.224, read response
    sock = socket.create_connection((RDP_HOST, RDP_PORT), timeout=15)
    sock.sendall(x224_req)
    # Read TPKT header (4 bytes) to get length
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("EOF reading X.224 response header")
        hdr += chunk
    total_len = int.from_bytes(hdr[2:4], "big")
    resp = hdr
    while len(resp) < total_len:
        chunk = sock.recv(total_len - len(resp))
        if not chunk:
            raise ConnectionError("EOF reading X.224 response")
        resp += chunk

    # 2. Grab the server's TLS certificate via a throwaway TLS handshake
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Reconnect for the cert grab (the first socket is at X.224 stage)
    cert_sock = socket.create_connection((RDP_HOST, RDP_PORT), timeout=15)
    cert_sock.sendall(x224_req)
    # Read and discard the X.224 response
    hdr = b""
    while len(hdr) < 4:
        hdr += cert_sock.recv(4 - len(hdr))
    total_len = int.from_bytes(hdr[2:4], "big")
    discard = hdr
    while len(discard) < total_len:
        discard += cert_sock.recv(total_len - len(discard))
    # Now do TLS handshake to get the cert
    tls_for_cert = ctx.wrap_socket(cert_sock, server_hostname=RDP_HOST)
    cert_der = tls_for_cert.getpeercert(binary_form=True)
    tls_for_cert.close()

    # 3. Do the real TLS handshake on the original socket
    tls_sock = ctx.wrap_socket(sock, server_hostname=RDP_HOST)
    tls_sock.setblocking(True)
    return resp, cert_der, tls_sock


async def handle_client(ws):
    """Handle one browser WebSocket client."""
    print(f"bridge: client connected from {ws.remote_address}", flush=True)
    tls_sock = None
    try:
        # First frame must be the RDCleanPath request (binary)
        first = await ws.recv()
        if isinstance(first, str):
            print("bridge: expected binary RDCleanPath request, got text", flush=True)
            return
        fields = parse_rdcleanpath_request(first)
        if not fields:
            print("bridge: invalid RDCleanPath request", flush=True)
            await ws.send(build_rdcleanpath_error())
            return

        print("bridge: RDCleanPath handshake starting", flush=True)
        try:
            x224_resp, cert_der, tls_sock = await asyncio.to_thread(
                rdcleanpath_handshake, fields["x224"]
            )
        except Exception as e:
            print(f"bridge: handshake failed: {e}", flush=True)
            await ws.send(build_rdcleanpath_error())
            return

        resp = build_rdcleanpath_response(x224_resp, cert_der)
        await ws.send(resp)
        print(f"bridge: handshake complete, bridging ({len(resp)}b response)", flush=True)

        # Bridge: WS -> TLS socket, TLS socket -> WS
        async def ws_to_tls():
            try:
                async for msg in ws:
                    if isinstance(msg, bytes):
                        await asyncio.to_thread(tls_sock.sendall, msg)
                    # Ignore text frames (shouldn't happen)
            except Exception:
                pass

        async def tls_to_ws():
            try:
                while True:
                    data = await asyncio.to_thread(tls_sock.recv, CHUNK)
                    if not data:
                        break
                    await ws.send(data)
            except Exception:
                pass

        await asyncio.gather(ws_to_tls(), tls_to_ws())
    except Exception as e:
        print(f"bridge: client handler error: {e}", flush=True)
    finally:
        if tls_sock:
            try:
                tls_sock.close()
            except Exception:
                pass
        print("bridge: client disconnected", flush=True)


async def main():
    print(f"bridge: listening on 127.0.0.1:{BRIDGE_PORT}, RDP at {RDP_HOST}:{RDP_PORT}",
          flush=True)
    async with websockets.serve(handle_client, "127.0.0.1", BRIDGE_PORT,
                                max_size=64 * 1024 * 1024):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
