from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from intellifim_schemas import CanonicalEvent

from normalizers._helpers import ZEEK_HOST_ID, parse_unix_utc


def transform(raw: dict) -> CanonicalEvent:
    # Assumes Zeek's json-streaming-logs policy: fields like id.orig_h arrive
    # as flat keys with literal dots, not as nested objects.
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="network.http_request",
        source="zeek.http",
        timestamp=parse_unix_utc(raw["ts"]),
        ingest_timestamp=datetime.now(tz=timezone.utc),
        host_id=ZEEK_HOST_ID,
        src_ip=raw.get("id.orig_h"),
        src_port=raw.get("id.orig_p"),
        dst_ip=raw.get("id.resp_h"),
        dst_port=raw.get("id.resp_p"),
        # protocol is application-layer. raw fields like "method" / "host" / "uri"
        # are HTTP-specific; "http" is the canonical application name we report.
        protocol="http",
        raw=raw,
    )
