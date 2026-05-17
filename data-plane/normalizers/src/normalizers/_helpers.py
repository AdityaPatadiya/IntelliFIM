"""Per-source normalizer helpers.

These three functions are shared by every per-source normalizer module.
Centralising them here ensures a single source of truth for the project
conventions: SHA-256 hashes are lowercase hex, timestamps are UTC
tz-aware, missing-or-empty integer fields collapse to None.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone


def maybe_int(value: str | int | None) -> int | None:
    """Convert string-or-int to int; treat None and "" as missing."""
    if value is None or value == "":
        return None
    return int(value)


def maybe_lower(value: str | None) -> str | None:
    """Lowercase the string, pass None through unchanged."""
    if value is None:
        return None
    return value.lower()


def parse_utc(value: str) -> datetime:
    """Parse an ISO 8601 timestamp string into a UTC tz-aware datetime.

    Refuses tz-less input — `astimezone()` on a naive datetime would
    silently apply the system local time of the normalizer container,
    which would corrupt cross-host correlation downstream.
    """
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp missing tz: {value!r}")
    return parsed.astimezone(timezone.utc)


def parse_unix_utc(value: float) -> datetime:
    """Parse a UNIX-style float timestamp (seconds since epoch) into a UTC tz-aware datetime.

    Zeek emits its `ts` field as a float; the canonical schema requires
    a tz-aware datetime, so we normalise to UTC at the boundary.
    """
    return datetime.fromtimestamp(value, tz=timezone.utc)


def _zeek_host_id() -> str:
    """Read ZEEK_HOST_ID from env, default to 'zeek-sensor'.

    In v1 demo Compose, Zeek monitors the victim-server's netns while Wazuh
    runs in a different container with its own agent_id. For the correlation
    engine to pair file ↔ network events from the same logical host, the
    operator overrides ZEEK_HOST_ID to match the Wazuh agent_id (e.g. "001").
    """
    return os.environ.get("ZEEK_HOST_ID", "zeek-sensor")


# Zeek runs centrally on a SPAN port (no per-host concept). All Zeek normalizers
# emit canonical events with this value as host_id. Overridable via env so the
# operator can align with the Wazuh agent_id of the monitored host.
ZEEK_HOST_ID = _zeek_host_id()
