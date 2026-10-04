#!/usr/bin/env python3
"""
Deploy the RDP relay Worker + RdpRelay Durable Object via the Cloudflare API.

Stdlib only. Uploads worker.js as an ES module with the RDP_RELAY Durable
Object binding and the new_sqlite_classes migration (required on the free
plan), then optionally sets the RELAY_SECRET / CLIENT_TOKEN secrets.

Env:
  CF_API_TOKEN   Cloudflare API token (Workers + D1/DO write scope)
  CF_ACCOUNT_ID  Cloudflare account ID
  WORKER_NAME    optional, default "agentx-rdp-relay"
  RELAY_SECRET   optional — uploaded as a Worker secret if set
  CLIENT_TOKEN   optional — uploaded as a Worker secret if set

Prints the public workers.dev URL on success.
"""

import json
import os
import sys
import urllib.request
import uuid

API_TOKEN = os.environ.get("CF_API_TOKEN")
ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID")
WORKER_NAME = os.environ.get("WORKER_NAME", "agentx-rdp-relay")
if not API_TOKEN or not ACCOUNT_ID:
    sys.exit("CF_API_TOKEN and CF_ACCOUNT_ID env vars are required")

BASE = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"


def api(method, path, data=None, content_type="application/json"):
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": content_type,
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "worker.js"), encoding="utf-8") as f:
    script = f.read()

metadata = {
    "main_module": "worker.js",
    "compatibility_date": "2024-06-01",
    "bindings": [
        {
            "type": "durable_object_namespace",
            "name": "RDP_RELAY",
            "class_name": "RdpRelay",
        }
    ],
    "migrations": {"new_sqlite_classes": ["RdpRelay"], "tag": "v1"},
}

boundary = uuid.uuid4().hex
body = b""


def part(name, value, filename=None, ctype=None):
    global body
    body += f"--{boundary}\r\n".encode()
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename:
        disp += f'; filename="{filename}"'
    body += disp.encode() + b"\r\n"
    if ctype:
        body += f"Content-Type: {ctype}\r\n".encode()
    body += b"\r\n"
    body += value.encode("utf-8") if isinstance(value, str) else value
    body += b"\r\n"


part("metadata", json.dumps(metadata), ctype="application/json")
part("script", script, filename="worker.js", ctype="application/javascript+module")
body += f"--{boundary}--\r\n".encode()

res = api(
    "PUT",
    f"/workers/scripts/{WORKER_NAME}",
    data=body,
    content_type=f"multipart/form-data; boundary={boundary}",
)
if not res.get("success"):
    sys.exit(f"deploy failed: {json.dumps(res)[:500]}")
print(f"worker '{WORKER_NAME}' deployed")

for secret_name in ("RELAY_SECRET", "CLIENT_TOKEN"):
    value = os.environ.get(secret_name)
    if value:
        res = api(
            "PUT",
            f"/workers/scripts/{WORKER_NAME}/secrets",
            data=json.dumps({"name": secret_name, "text": value}).encode(),
        )
        if res.get("success"):
            print(f"secret {secret_name} set")
        else:
            print(f"warning: failed to set {secret_name}: {json.dumps(res)[:200]}")

sub = api("GET", "/workers/subdomain")
subdomain = (sub.get("result") or {}).get("subdomain")
if subdomain:
    print(f"public URL: https://{WORKER_NAME}.{subdomain}.workers.dev")
    print("health:     curl https://{}.{}.workers.dev/health".format(WORKER_NAME, subdomain))
