#!/usr/bin/env python3
# data-plane/scripts/approve-pending.py
"""Poll GET /approvals until a PENDING row appears (timeout 60s), then POST
/approve on it and print the final row JSON.

Reads ADMIN_EMAIL and ADMIN_PASSWORD from env (matches the compose env vars),
logs in to the auth-backend at AUTH_BACKEND_URL, and forwards the JWT on
every orchestrator call.

Usage:
    ADMIN_EMAIL=admin@intellifim.local ADMIN_PASSWORD=changeme \
        python data-plane/scripts/approve-pending.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


def _http_get(url: str, token: str | None = None) -> dict:
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_post(url: str, body: dict | None = None, token: str | None = None) -> dict:
    data = json.dumps(body or {}).encode("utf-8")
    req = urllib.request.Request(url, method="POST", data=data)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body_str = exc.read().decode("utf-8")
        return {"_http_status": exc.code, "_body": body_str}


def _login(auth_url: str, email: str, password: str) -> str:
    try:
        body = _http_post(f"{auth_url}/auth/login", {"email": email, "password": password})
    except urllib.error.URLError as exc:
        print(f"auth-backend unreachable at {auth_url}: {exc}", file=sys.stderr)
        sys.exit(3)
    if "_http_status" in body:
        print(f"login failed: {body['_http_status']} {body['_body']}", file=sys.stderr)
        sys.exit(4)
    return body["access_token"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8200",
                        help="orchestrator REST API base URL")
    parser.add_argument("--auth-url", default=os.environ.get("AUTH_BACKEND_URL", "http://127.0.0.1:8000"),
                        help="auth-backend base URL")
    parser.add_argument("--timeout-seconds", type=int, default=60)
    args = parser.parse_args()

    email = os.environ.get("ADMIN_EMAIL")
    password = os.environ.get("ADMIN_PASSWORD")
    if not email or not password:
        print("ADMIN_EMAIL and ADMIN_PASSWORD env vars are required", file=sys.stderr)
        return 5

    print(f"logging in as {email} at {args.auth_url}", file=sys.stderr)
    token = _login(args.auth_url, email, password)

    deadline = time.monotonic() + args.timeout_seconds
    pending_id: str | None = None
    while time.monotonic() < deadline:
        body = _http_get(f"{args.base_url}/approvals?state=PENDING", token=token)
        approvals = body.get("approvals", [])
        if approvals:
            pending_id = approvals[0]["id"]
            print(f"found PENDING approval id={pending_id}", file=sys.stderr)
            break
        time.sleep(2)

    if pending_id is None:
        print(f"timeout: no PENDING approvals appeared in {args.timeout_seconds}s",
              file=sys.stderr)
        return 1

    print(f"POST {args.base_url}/approvals/{pending_id}/approve", file=sys.stderr)
    result = _http_post(f"{args.base_url}/approvals/{pending_id}/approve", token=token)
    print(json.dumps(result, indent=2))
    if result.get("state") == "EXECUTED":
        return 0
    print(f"unexpected state: {result.get('state')!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
