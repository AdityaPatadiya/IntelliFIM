from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from intellifim_schemas import CanonicalEvent

from normalizers._helpers import maybe_int, maybe_lower, parse_utc

_EVENT_TYPE_MAP = {
    "added": "file.created",
    "modified": "file.modified",
    "deleted": "file.deleted",
}


def transform(raw: dict) -> CanonicalEvent:
    syscheck = raw["syscheck"]
    audit = syscheck.get("audit", {}) or {}
    user = audit.get("user", {}) or {}
    process = audit.get("process", {}) or {}
    agent = raw.get("agent", {}) or {}

    return CanonicalEvent(
        event_id=uuid4(),
        event_type=_EVENT_TYPE_MAP[syscheck["event"]],
        source="wazuh.fim",
        timestamp=parse_utc(raw["timestamp"]),
        ingest_timestamp=datetime.now(tz=timezone.utc),
        host_id=agent["id"],
        host_name=agent.get("name"),
        user=user.get("name"),
        user_uid=maybe_int(user.get("id")),
        process_name=process.get("name"),
        process_pid=maybe_int(process.get("id")),
        file_path=syscheck.get("path"),
        file_hash_sha256=maybe_lower(syscheck.get("sha256_after")),
        file_size_bytes=maybe_int(syscheck.get("size_after")),
        raw=raw,
    )
