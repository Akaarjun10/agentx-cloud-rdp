#!/usr/bin/env python3
"""
Local RDP client proxy.

Listens on 127.0.0.1:13389 and forwards the RDP TCP stream over a WebSocket
to the Cloudflare Worker (/rdp-client?token=CLIENT_TOKEN), which bridges it
to whichever Windows runner is currently up.

Usage:
    pip install websockets
    WORKER_URL=https://<name>.<sub>.workers.dev CLIENT_TOKEN=<token> python rdp_client_proxy.py

Then point your RDP client at  localhost:13389
    Windows : mstsc  ->  Computer: localhost:13389
    macOS   : Microsoft Remote Desktop -> PC name: localhost:13389
    Android : Termux can run this proxy; then use any RDP app -> localhost:13389

Log in as user  runneradmin  with your RDP_PASSWORD.

The proxy auto-reconnects with backoff; on runner handoff the Worker closes
the socket (1001) and the proxy re-attaches to the successor automatically.
Your RDP client may show a brief reconnect at each ~6h handoff.
"""

import asyncio
import os
import sys

try:
    import websockets
except ImportError:
    sys.exit("websockets package missing: pip install websockets")

LISTEN_HOST, LISTEN_PORT = "127.0.0.1", 13389
WORKER_URL = os.environ.get("WORKER_URL", "").rstrip("/")
CLIENT_TOKEN = os.environ.get("CLIENT_TOKEN", "")
if not WORKER_URL or not CLIENT_TOKEN:
    sys.exit("WORKER_URL and CLIENT_TOKEN env vars are required")

CLIENT_WS = (
    WORKER_URL.replace("https://", "wss://").replace("http://", "ws://")
    + "/rdp-client?token="
    + CLIENT_TOKEN
)
CHUNK = 65536


async def bridge(reader, writer):
    """Bridge one RDP TCP connection to the Worker.

    The WebSocket is re-established as needed while the TCP side is alive
    (this is what makes runner handoffs seamless). When the RDP client
    goes away, the bridge ends instead of spinning.
    """
    backoff = 2
    tcp_alive = True
    try:
        while tcp_alive:
            try:
                async with websockets.connect(
                    CLIENT_WS, max_size=64 * 1024 * 1024, ping_interval=20, ping_timeout=20
                ) as ws:
                    print("proxy: attached to runner", flush=True)
                    backoff = 2

                    async def tcp_to_ws():
                        nonlocal tcp_alive
                        try:
                            while True:
                                data = await reader.read(CHUNK)
                                if not data:  # RDP client disconnected
                                    tcp_alive = False
                                    break
                                await ws.send(data)
                        except Exception:
                            tcp_alive = False

                    async def ws_to_tcp():
                        try:
                            async for msg in ws:
                                if isinstance(msg, bytes):
                                    writer.write(msg)
                                    await writer.drain()
                        except Exception:
                            pass

                    # When either direction ends, stop the other: otherwise
                    # gather() would wait forever on the surviving one and
                    # the bridge task would leak after a client disconnect.
                    t1 = asyncio.create_task(tcp_to_ws())
                    t2 = asyncio.create_task(ws_to_tcp())
                    _done, pending = await asyncio.wait(
                        {t1, t2}, return_when=asyncio.FIRST_COMPLETED
                    )
                    for p in pending:
                        p.cancel()
                    for d in _done:
                        try:
                            d.result()
                        except Exception:
                            pass
                    if tcp_alive:
                        print("proxy: detached (runner handoff?), re-attaching...", flush=True)
                    # else: TCP is gone — fall out of the loop
            except Exception as e:
                if not tcp_alive:
                    break
                print(f"proxy: uplink lost ({e}), retrying in {backoff}s", flush=True)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_client(reader, writer):
    await bridge(reader, writer)


async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    print(f"proxy: listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    print(f"proxy: relaying via {WORKER_URL}", flush=True)
    print("proxy: point your RDP client at localhost:13389 (user: runneradmin)", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
