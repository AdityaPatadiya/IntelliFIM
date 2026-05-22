#!/usr/bin/env python3
"""End-to-end smoke for the reporting service.

Logs into auth-backend, generates a 24h-window report via reporting,
downloads it to /tmp, and reports exit codes per failure mode.

Exit codes:
  0 success
  1 login failed
  2 generate failed
  3 download failed
  4 missing creds env (ADMIN_EMAIL / ADMIN_PASSWORD)
  5 reporting unreachable / auth-backend unreachable
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone


AUTH_URL = os.environ.get("AUTH_URL", "http://127.0.0.1:8000")
REPORTING_URL = os.environ.get("REPORTING_URL", "http://127.0.0.1:8300")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")


def _post(url: str, body: dict, *, token: str | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        method="POST",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read())
        except Exception:
            payload = {"error": str(e)}
        return e.code, payload


def _get_raw(url: str, *, token: str) -> tuple[int, bytes, str]:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read(), r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("Content-Type", "")


def main() -> int:
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        print("missing ADMIN_EMAIL or ADMIN_PASSWORD in env", file=sys.stderr)
        return 4

    # 1. Login
    try:
        status, body = _post(
            f"{AUTH_URL}/auth/login",
            {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
    except urllib.error.URLError as e:
        print(f"auth-backend unreachable: {e}", file=sys.stderr)
        return 5
    if status != 200 or "access_token" not in body:
        print(f"login failed: status={status} body={body}", file=sys.stderr)
        return 1
    token = body["access_token"]
    print(f"login ok (user={body.get('user', {}).get('username')})")

    # 2. Generate a 24h-window report
    now = datetime.now(tz=timezone.utc)
    body = {
        "name": "smoke",
        "range_start": (now - timedelta(hours=24)).isoformat(),
        "range_end": now.isoformat(),
    }
    try:
        status, body = _post(f"{REPORTING_URL}/reports/generate", body, token=token)
    except urllib.error.URLError as e:
        print(f"reporting unreachable: {e}", file=sys.stderr)
        return 5
    if status != 201 or "id" not in body:
        print(f"generate failed: status={status} body={body}", file=sys.stderr)
        return 2
    print(f"generated id={body['id']} size_bytes={body['size_bytes']} "
          f"approvals={body['approvals_count']} scores={body['scores_count']}")

    # 3. Download
    rid = body["id"]
    status, pdf_bytes, ctype = _get_raw(
        f"{REPORTING_URL}/reports/{rid}/download", token=token
    )
    if status != 200:
        print(f"download failed: status={status}", file=sys.stderr)
        return 3
    if not pdf_bytes.startswith(b"%PDF-"):
        print(f"downloaded file is not a PDF (content-type={ctype})", file=sys.stderr)
        return 3
    out_path = f"/tmp/intellifim-smoke-{rid}.pdf"
    with open(out_path, "wb") as f:
        f.write(pdf_bytes)
    print(f"downloaded {len(pdf_bytes)} bytes -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
