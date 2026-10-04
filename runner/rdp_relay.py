#!/usr/bin/env python3
"""
Runner-side RDP relay: bridges the local RDP server (127.0.0.1:3389) to the
Cloudflare Durable Object over one outbound WebSocket.

Protocol (mirrors relay.py conventions — single consumer loop):
  DO -> runner (text JSON): {"type":"attach"}   — a client connected; open TCP to 3389
  DO -> runner (text JSON): {"type":"detach"}   — client gone; close the TCP
  DO -> runner (binary): raw bytes to write into the local RDP socket
  runner -> DO (binary): raw bytes read from the local RDP socket
  runner -> DO (text JSON): {"type":"local_closed"} — local RDP socket died

The local TCP connection to 3389 exists ONLY while a client is attached, so
a newly connecting client always gets a fresh RDP handshake (never mid-stream
bytes). On runner swap the DO closes the old uplink; this relay reconnects
with backoff and waits for the next attach.

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


async def run_once():
    async with websockets.connect(
        RELAY_WS, max_size=64 * 1024 * 1024, ping_interval=20, ping_timeout=20
    ) as ws:
        print("relay: connected to DO", flush=True)

        reader = writer = None
        pump_task = None
        gen = 0  # attach generation; stale pumps must not signal local_closed

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

        async def attach():
            nonlocal reader, writer, pump_task, gen
            if writer is not None:
                return
            try:
                reader, writer = await asyncio.open_connection(RDP_HOST, RDP_PORT)
            except Exception as e:
                print(f"relay: local RDP unreachable: {e}", flush=True)
                try:
                    await ws.send(json.dumps({"type": "local_closed"}))
                except Exception:
                    pass
                return
            gen += 1
            pump_task = asyncio.create_task(tcp_pump(gen))
            print("relay: client attached, local RDP bridged", flush=True)

        async def detach():
            nonlocal reader, writer, pump_task, gen
            gen += 1  # invalidate the current pump's local_closed report
            if pump_task is not None:
                pump_task.cancel()
                pump_task = None
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
                reader = writer = None

        try:
            async for msg in ws:  # single consumer: binary=data, text=control
                if isinstance(msg, bytes):
                    if writer is not None:
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
            await detach()


async def main():
    backoff = 2
    while True:
        try:
            await run_once()
        except Exception as e:
            print(f"relay: uplink lost ({e}), retrying in {backoff}s", flush=True)
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 60)


if __name__ == "__main__":
    asyncio.run(main())
