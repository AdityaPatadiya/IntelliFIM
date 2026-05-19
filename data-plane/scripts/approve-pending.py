#!/usr/bin/env python3
# data-plane/scripts/approve-pending.py
"""Poll GET /approvals until a PENDING row appears (timeout 60s), then POST
/approve on it and print the final row JSON.

Usage:
    python data-plane/scripts/approve-pending.py [--base-url http://127.0.0.1:8200]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def _http_get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_post(url: str) -> dict:
    req = urllib.request.Request(url, method="POST", data=b"")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        return {"_http_status": exc.code, "_body": body}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8200")
    parser.add_argument("--timeout-seconds", type=int, default=60)
    args = parser.parse_args()

    deadline = time.monotonic() + args.timeout_seconds
    pending_id: str | None = None
    while time.monotonic() < deadline:
        body = _http_get(f"{args.base_url}/approvals?state=PENDING")
        approvals = body.get("approvals", [])
        if approvals:
            pending_id = approvals[0]["id"]
            print(f"found PENDING approval id={pending_id}", file=sys.stderr)
            break
        time.sleep(2)

    if pending_id is None:
        print(f"timeout: no PENDING approvals appeared in {args.timeout_seconds}s", file=sys.stderr)
        return 1

    print(f"POST {args.base_url}/approvals/{pending_id}/approve", file=sys.stderr)
    result = _http_post(f"{args.base_url}/approvals/{pending_id}/approve")
    print(json.dumps(result, indent=2))
    if result.get("state") == "EXECUTED":
        return 0
    print(f"unexpected state: {result.get('state')!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
