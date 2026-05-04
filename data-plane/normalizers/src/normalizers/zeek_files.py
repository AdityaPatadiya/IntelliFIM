from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from intellifim_schemas import CanonicalEvent

from normalizers._helpers import ZEEK_HOST_ID, maybe_lower, parse_unix_utc


def _first(items: list | None) -> str | None:
    """Return the first element of a list, or None for empty/missing input."""
    if not items:
        return None
    return items[0]


def transform(raw: dict) -> CanonicalEvent:
    # files.log carries IPs as arrays (tx_hosts, rx_hosts) because a single
    # file may be seen across multiple connections. v1 takes the first
    # entry, which matches the typical 1:1 case.
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="network.file_transfer",
        source="zeek.files",
        timestamp=parse_unix_utc(raw["ts"]),
        ingest_timestamp=datetime.now(tz=timezone.utc),
        host_id=ZEEK_HOST_ID,
        src_ip=_first(raw.get("tx_hosts")),
        dst_ip=_first(raw.get("rx_hosts")),
        file_path=raw.get("filename"),
        file_hash_sha256=maybe_lower(raw.get("sha256")),
        file_size_bytes=raw.get("seen_bytes"),
        raw=raw,
    )
