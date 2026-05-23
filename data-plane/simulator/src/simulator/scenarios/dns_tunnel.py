"""dns-tunnel scenario — zeek.dns burst with random-base32 subdomains."""
from __future__ import annotations

import base64
import os
import subprocess


NAME = "dns-tunnel"
DESCRIPTION = "50 DNS queries with long random subdomains under exfil.tunnel.invalid"

QUERY_COUNT = 50
DOMAIN = "exfil.tunnel.invalid"


def _random_label() -> str:
    """20 random bytes → base32 → lowercase (32 chars, DNS-label-safe)."""
    return base64.b32encode(os.urandom(20)).decode("ascii").lower().rstrip("=")


def run(target_host: str) -> None:
    for _ in range(QUERY_COUNT):
        fqdn = f"{_random_label()}.{DOMAIN}"
        subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", fqdn, f"@{target_host}"],
            check=False,
            timeout=5,
        )
