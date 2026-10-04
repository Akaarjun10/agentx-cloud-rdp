/**
 * AgentX cloud RDP PoC — Cloudflare Worker + Durable Object relay.
 *
 * Architecture (no third-party tunnel service):
 *
 *   RDP client --TCP--> client/rdp_client_proxy.py --WSS + CLIENT_TOKEN--> Worker
 *   GitHub Windows runner: RDP 127.0.0.1:3389 <--TCP--> rdp_relay.py
 *                          --WSS + RELAY_SECRET--> same DO
 *
 * Both sides meet at the RdpRelay Durable Object (singleton "rdp-main").
 * Binary WebSocket frames are raw RDP TCP bytes, bridged both ways.
 * Text frames are control JSON: {type:"attach"} / {type:"detach"} (DO->runner)
 * and {type:"local_closed"} (runner->DO).
 *
 * The runner only opens its local 3389 TCP connection while a client is
 * attached, so every client attach starts with a fresh RDP handshake.
 * When a successor runner opens its uplink, the DO swaps it in and closes
 * the old client socket (1001) — the client proxy reconnects automatically.
 *
 * Secrets (wrangler secret / dashboard): RELAY_SECRET, CLIENT_TOKEN.
 * Binding: RDP_RELAY -> RdpRelay (Durable Object, SQLite backend).
 */

const DO_NAME = "rdp-main";

export class RdpRelay {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.uplink = null; // WebSocket to the current runner
    this.client = null; // WebSocket to the current client proxy
  }

  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname;

    // ---- Runner uplink: persistent WebSocket, authenticated by RELAY_SECRET ----
    if (path === "/rdp") {
      if (req.headers.get("upgrade") !== "websocket") {
        return new Response("websocket required", { status: 400 });
      }
      if (url.searchParams.get("secret") !== this.env.RELAY_SECRET) {
        return new Response("unauthorized", { status: 401 });
      }
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.accept();

      // A successor runner replaces the old uplink.
      if (this.uplink) { try { this.uplink.close(1000, "replaced"); } catch (e) {} }
      // The client must re-attach to the new runner; it reconnects on 1001.
      if (this.client) { try { this.client.close(1001, "runner replaced"); } catch (e) {} }
      this.client = null;
      this.uplink = server;

      server.addEventListener("message", (ev) => this.onUplinkMessage(ev.data));
      const drop = () => { if (this.uplink === server) this.uplink = null; };
      server.addEventListener("close", drop);
      server.addEventListener("error", drop);

      return new Response(null, { status: 101, webSocket: client });
    }

    // ---- Public health: reveals only whether a runner is connected ----
    if (path === "/health") {
      return Response.json({ ok: true, rdp: this.uplink !== null, ts: Date.now() });
    }

    // ---- Client auth gate ----
    if (url.searchParams.get("token") !== this.env.CLIENT_TOKEN) {
      return new Response("unauthorized", { status: 401 });
    }
    if (!this.uplink) {
      return Response.json({ error: "rdp offline" }, { status: 503 });
    }

    // ---- Client proxy WebSocket: bridge raw RDP bytes through the runner ----
    if (path === "/rdp-client") {
      if (req.headers.get("upgrade") !== "websocket") {
        return new Response("websocket required", { status: 400 });
      }
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.accept();

      // One active client at a time (PoC scope); a new one supersedes.
      if (this.client) { try { this.client.close(1000, "superseded"); } catch (e) {} }
      this.client = server;

      server.addEventListener("message", (ev) => {
        if (this.uplink) {
          try { this.uplink.send(ev.data); } catch (e) {}
        }
      });
      const cleanup = (sendDetach) => {
        if (this.client === server) this.client = null;
        if (sendDetach && this.uplink) {
          try { this.uplink.send(JSON.stringify({ type: "detach" })); } catch (e) {}
        }
      };
      server.addEventListener("close", () => cleanup(true));
      server.addEventListener("error", () => cleanup(true));

      try {
        this.uplink.send(JSON.stringify({ type: "attach" }));
      } catch (e) {
        cleanup(false);
        return new Response("runner unavailable", { status: 502 });
      }
      return new Response(null, { status: 101, webSocket: client });
    }

    return new Response("not found", { status: 404 });
  }

  onUplinkMessage(data) {
    if (typeof data === "string") {
      let msg;
      try { msg = JSON.parse(data); } catch (e) { return; }
      // Runner's local RDP socket died: reset the client so it reconnects
      // and triggers a fresh attach (and a fresh RDP handshake).
      if (msg.type === "local_closed" && this.client) {
        try { this.client.close(1001, "rdp reset"); } catch (e) {}
      }
      return;
    }
    // Binary: raw RDP bytes runner -> client.
    if (this.client) {
      try { this.client.send(data); } catch (e) {}
    }
  }
}

export default {
  async fetch(req, env) {
    const id = env.RDP_RELAY.idFromName(DO_NAME);
    const stub = env.RDP_RELAY.get(id);
    return stub.fetch(req);
  },
};
