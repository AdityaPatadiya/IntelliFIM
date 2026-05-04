from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from intellifim_schemas import CanonicalEvent

from normalizers._helpers import maybe_int, parse_utc

# Wazuh ships preconfigured rules for these. IDs may shift between minor
# versions; map by rule.groups membership for resilience.
_GROUP_TO_EVENT_TYPE = {
    "authentication_success": "auth.login_success",
    "authentication_failed": "auth.login_failed",
    "sudo": "auth.sudo",
    "logout": "auth.logout",
}


def _classify(rule: dict) -> str | None:
    # First match wins. Wazuh's stock auth rules carry exactly one of these
    # groups; if a custom rule layers two, the leftmost listed wins.
    for group in rule.get("groups", []):
        if group in _GROUP_TO_EVENT_TYPE:
            return _GROUP_TO_EVENT_TYPE[group]
    return None


def transform(raw: dict) -> CanonicalEvent:
    rule = raw.get("rule", {}) or {}
    data = raw.get("data", {}) or {}
    agent = raw.get("agent", {}) or {}

    event_type = _classify(rule)
    if event_type is None:
        raise ValueError(
            f"unrecognised auth rule groups: {rule.get('groups')} "
            f"(rule.id={rule.get('id')!r})"
        )

    # Sudo events: actor is srcuser (the invoker), not dstuser (root).
    if event_type == "auth.sudo":
        user = data.get("srcuser") or data.get("dstuser")
    else:
        user = data.get("dstuser")

    return CanonicalEvent(
        event_id=uuid4(),
        event_type=event_type,
        source="wazuh.auth",
        timestamp=parse_utc(raw["timestamp"]),
        ingest_timestamp=datetime.now(tz=timezone.utc),
        host_id=agent["id"],
        host_name=agent.get("name"),
        user=user,
        user_uid=maybe_int(data.get("uid")),
        src_ip=data.get("srcip"),
        raw=raw,
    )
