from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from intellifim_schemas import CanonicalEvent, CorrelatedEvent


def _file_event() -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="file.modified",
        source="wazuh.fim",
        timestamp=datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc),
        ingest_timestamp=datetime(2026, 5, 4, 12, 0, 1, tzinfo=timezone.utc),
        host_id="host-001",
        file_path="/etc/shadow",
    )


def _network_event() -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="network.flow",
        source="zeek.conn",
        timestamp=datetime(2026, 5, 4, 12, 0, 30, tzinfo=timezone.utc),
        ingest_timestamp=datetime(2026, 5, 4, 12, 0, 31, tzinfo=timezone.utc),
        host_id="host-001",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=49152,
        dst_port=443,
        protocol="tcp",
    )


def test_correlated_event_basic_roundtrip():
    triggering = _file_event()
    co = _network_event()
    event = CorrelatedEvent(
        correlation_id=uuid4(),
        correlation_type="file_with_network",
        correlated_at=datetime.now(tz=timezone.utc),
        window_seconds=60,
        host_id="host-001",
        triggering_event=triggering,
        co_occurring_events=[co],
    )
    serialized = event.model_dump_json()
    rebuilt = CorrelatedEvent.model_validate_json(serialized)
    assert rebuilt == event
    assert rebuilt.triggering_event.event_type == "file.modified"
    assert len(rebuilt.co_occurring_events) == 1


def test_correlated_event_rejects_unknown_field():
    """extra='forbid' is the contract — unknown fields must be rejected."""
    payload = {
        "correlation_id": str(uuid4()),
        "correlation_type": "file_with_network",
        "correlated_at": datetime.now(tz=timezone.utc).isoformat(),
        "window_seconds": 60,
        "host_id": "host-001",
        "triggering_event": _file_event().model_dump(mode="json"),
        "co_occurring_events": [_network_event().model_dump(mode="json")],
        "mystery_field": "boom",
    }
    with pytest.raises(ValidationError):
        CorrelatedEvent.model_validate(payload)


def test_correlated_event_rejects_unknown_correlation_type():
    payload = {
        "correlation_id": str(uuid4()),
        "correlation_type": "rule_match",  # v2; not allowed in v1
        "correlated_at": datetime.now(tz=timezone.utc).isoformat(),
        "window_seconds": 60,
        "host_id": "host-001",
        "triggering_event": _file_event().model_dump(mode="json"),
        "co_occurring_events": [_network_event().model_dump(mode="json")],
    }
    with pytest.raises(ValidationError):
        CorrelatedEvent.model_validate(payload)


def test_correlated_event_requires_at_least_one_co_occurring():
    """Emitting a 'correlation' with zero co-occurring events is meaningless."""
    payload = {
        "correlation_id": str(uuid4()),
        "correlation_type": "file_with_network",
        "correlated_at": datetime.now(tz=timezone.utc).isoformat(),
        "window_seconds": 60,
        "host_id": "host-001",
        "triggering_event": _file_event().model_dump(mode="json"),
        "co_occurring_events": [],
    }
    with pytest.raises(ValidationError):
        CorrelatedEvent.model_validate(payload)


def test_correlated_event_rejects_zero_window_seconds():
    payload = {
        "correlation_id": str(uuid4()),
        "correlation_type": "file_with_network",
        "correlated_at": datetime.now(tz=timezone.utc).isoformat(),
        "window_seconds": 0,
        "host_id": "host-001",
        "triggering_event": _file_event().model_dump(mode="json"),
        "co_occurring_events": [_network_event().model_dump(mode="json")],
    }
    with pytest.raises(ValidationError):
        CorrelatedEvent.model_validate(payload)


def test_correlated_event_rejects_naive_correlated_at():
    payload = {
        "correlation_id": str(uuid4()),
        "correlation_type": "file_with_network",
        "correlated_at": datetime(2026, 5, 4, 12, 0, 0).isoformat(),  # no tz
        "window_seconds": 60,
        "host_id": "host-001",
        "triggering_event": _file_event().model_dump(mode="json"),
        "co_occurring_events": [_network_event().model_dump(mode="json")],
    }
    with pytest.raises(ValidationError):
        CorrelatedEvent.model_validate(payload)
