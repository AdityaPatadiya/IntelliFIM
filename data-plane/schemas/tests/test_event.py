from datetime import datetime, timezone
from ipaddress import IPv4Address
from uuid import uuid4

import pytest
from pydantic import ValidationError

from intellifim_schemas import CanonicalEvent


def _minimal_event_dict() -> dict:
    return {
        "event_id": str(uuid4()),
        "event_type": "file.modified",
        "source": "wazuh.fim",
        "timestamp": datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc).isoformat(),
        "ingest_timestamp": datetime(2026, 5, 4, 12, 0, 1, tzinfo=timezone.utc).isoformat(),
        "host_id": "agent-001",
    }


# --- positive cases ---

def test_canonical_event_required_fields_only():
    event = CanonicalEvent.model_validate(_minimal_event_dict())
    assert event.event_type == "file.modified"
    assert event.source == "wazuh.fim"
    assert event.host_id == "agent-001"
    assert event.schema_version == "1.0.0"
    assert event.user is None
    assert event.raw == {}


def test_canonical_event_serialization_roundtrip():
    payload = _minimal_event_dict()
    payload.update({
        "user": "alice",
        "user_uid": 1001,
        "file_path": "/etc/shadow",
        "file_hash_sha256": "a" * 64,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 49152,
        "dst_port": 443,
        "protocol": "tcp",
        "raw": {"original": "wazuh-event"},
    })
    event = CanonicalEvent.model_validate(payload)
    serialized = event.model_dump_json()
    rebuilt = CanonicalEvent.model_validate_json(serialized)
    assert rebuilt == event
    assert rebuilt.src_ip == IPv4Address("10.0.0.1")


def test_canonical_event_accepts_zero_file_size_and_root_uid():
    """Empty files are valid (size=0). Root is valid (uid=0)."""
    payload = _minimal_event_dict()
    payload.update({"file_size_bytes": 0, "user_uid": 0})
    event = CanonicalEvent.model_validate(payload)
    assert event.file_size_bytes == 0
    assert event.user_uid == 0


# --- negative cases (enum / IP / required field) ---

def test_canonical_event_rejects_unknown_event_type():
    payload = _minimal_event_dict()
    payload["event_type"] = "file.weird"
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_unknown_source():
    payload = _minimal_event_dict()
    payload["source"] = "syslog.unknown"
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_invalid_ip():
    payload = _minimal_event_dict()
    payload["src_ip"] = "not-an-ip"
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_missing_required_field():
    payload = _minimal_event_dict()
    del payload["host_id"]
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


# --- negative cases (constraint pinning) ---

def test_canonical_event_rejects_unknown_field():
    """extra='forbid' is the contract — unknown fields must be rejected."""
    payload = _minimal_event_dict()
    payload["mystery_field"] = "boom"
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_negative_file_size():
    payload = _minimal_event_dict()
    payload["file_size_bytes"] = -1
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_negative_user_uid():
    payload = _minimal_event_dict()
    payload["user_uid"] = -1
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_invalid_pid():
    """PID 0 is the kernel scheduler; real processes start at 1."""
    payload = _minimal_event_dict()
    payload["process_pid"] = 0
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_port_out_of_range():
    for bad_port in (0, 65536, -1):
        payload = _minimal_event_dict()
        payload["src_port"] = bad_port
        with pytest.raises(ValidationError):
            CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_invalid_sha256():
    """Must be exactly 64 lowercase hex chars."""
    for bad_hash in ("hello", "a" * 63, "A" * 64, "g" * 64, "a" * 65):
        payload = _minimal_event_dict()
        payload["file_hash_sha256"] = bad_hash
        with pytest.raises(ValidationError):
            CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_naive_timestamp():
    """Timestamps must carry tzinfo to be unambiguous across hosts."""
    payload = _minimal_event_dict()
    payload["timestamp"] = datetime(2026, 5, 4, 12, 0, 0).isoformat()  # no tzinfo
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)
