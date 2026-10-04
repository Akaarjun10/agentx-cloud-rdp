# AgentX Cloud RDP — PoC

EXPERIMENTAL. A Windows machine in the cloud that never dies: RDP on a
GitHub Actions Windows runner, exposed through a Cloudflare Worker at ONE
stable URL, with **full Chrome data preserved across every handoff**.

```
Your RDP client ──TCP──▶ client/rdp_client_proxy.py ──wss + CLIENT_TOKEN──▶ Cloudflare Worker
         (localhost:13389)                                                        │  RdpRelay DO
                                                                                  │  (singleton "rdp-main")
                                                                                  ▼
                                                        GitHub Windows runner: rdp_relay.py ─┬─▶ 127.0.0.1:3389 (RDP)
                                                                                             └─▶ Chrome (restored profile)
```

No third-party tunnel service. The runner opens a single outbound
WebSocket; the Durable Object relays raw RDP bytes between the client
proxy and whichever runner is currently connected. Successor runners just
open a new uplink — the DO swaps it in and the client proxy re-attaches
automatically (brief reconnect at each ~6h handoff).

## What survives a handoff

At ~5h17m, before GitHub's 6h job kill, the runner:

1. saves the open-tab list (CDP fallback),
2. closes Chrome cleanly and zips the **entire Chrome profile**
   (cookies, logins, history, extensions, sessions) plus `C:\rdp-persist`,
3. uploads the zip to the Actions cache,
4. dispatches its own successor via the API.

The successor restores the cache **before** opening its relay uplink, so
when you reconnect you get the same desktop, same Chrome, same tabs,
still logged in. Anything you keep in `C:\rdp-persist` (Desktop files,
downloads you care about) comes along too.

## Setup

### 1. Deploy the Worker (one command, your Cloudflare account)

```bash
cd worker
CF_API_TOKEN=<token> CF_ACCOUNT_ID=<account id> \
  RELAY_SECRET=<random> CLIENT_TOKEN=<random> \
  python3 deploy-worker.py
```

It prints the public URL, e.g. `https://agentx-rdp-relay.<sub>.workers.dev`.
`RELAY_SECRET` / `CLIENT_TOKEN`: generate with `openssl rand -hex 32`.

### 2. Repo secrets

| Secret         | Value                                              |
|----------------|----------------------------------------------------|
| `WORKER_URL`   | the Worker's public URL from step 1                |
| `RELAY_SECRET` | must match the Worker's `RELAY_SECRET`             |
| `CLIENT_TOKEN` | must match the Worker's `CLIENT_TOKEN`             |
| `RDP_PASSWORD` | strong password (12+ chars) for the `runneradmin` RDP login |

### 3. Launch

Actions tab → **windows-rdp** → Run workflow. The `rdp-watchdog`
(every 30 min) re-dispatches automatically if the chain ever breaks, so
after the first launch it runs itself.

## Accessing the desktop

```bash
pip install websockets
WORKER_URL=https://<your>.workers.dev CLIENT_TOKEN=<token> \
  python3 client/rdp_client_proxy.py
```

Then connect your RDP client to **`localhost:13389`**:

- Windows: `mstsc` → Computer: `localhost:13389`
- macOS: Microsoft Remote Desktop → `localhost:13389`
- Android: run the proxy in Termux, then any RDP app → `localhost:13389`

Log in as `runneradmin` with your `RDP_PASSWORD`. You land on the
console session where Chrome is already running with your restored
profile. Keep anything you want to keep in `C:\rdp-persist`.

## Files

- `.github/workflows/windows-rdp.yml` — the self-chaining RDP runner
- `.github/workflows/rdp-watchdog.yml` — re-dispatches if the chain breaks
- `runner/enable_rdp.ps1` — enables RDP for `runneradmin`, firewall, waits for 3389
- `runner/rdp_relay.py` — bridges local 3389 to the DO over one outbound WSS
- `runner/snapshot.ps1` — Chrome profile + persist-folder snapshot/restore
- `worker/worker.js` — Worker + RdpRelay Durable Object (raw RDP byte relay)
- `worker/deploy-worker.py` — deploys via the Cloudflare API
- `client/rdp_client_proxy.py` — local proxy: `localhost:13389` → Worker

## Notes

- **ToS**: like the browser PoC, this pattern is against GitHub's Actions
  ToS for production use — dummy account only. Never run this on the
  account that builds/releases AgentX.
- **Cost**: Windows runners consume minutes at 2× the Linux rate. Public
  repo = unlimited minutes (with the ToS caveat above); private repos burn
  quota fast.
- **Handoff**: expect a brief RDP reconnect roughly every 6 hours while
  the successor boots and restores state (usually 3–8 minutes).
- **One client at a time** in this PoC; a second connection supersedes.
- The workflow commits `.heartbeat` on every run to keep the repo active
  (GitHub pauses scheduled workflows after 60 days of inactivity).
- NLA stays enabled; the relay is gated by `RELAY_SECRET` (runner side)
  and `CLIENT_TOKEN` (client side). There is no public tunnel URL — the
  only surface is the Worker.
