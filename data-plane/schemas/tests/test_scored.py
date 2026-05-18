from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from intellifim_schemas import CanonicalEvent, ScoredEvent


def _source_event() -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="file.modified",
        source="wazuh.fim",
        timestamp=datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc),
        ingest_timestamp=datetime(2026, 5, 17, 12, 0, 1, tzinfo=timezone.utc),
        host_id="host-001",
        file_path="/etc/shadow",
    )


def _base_payload() -> dict:
    return {
        "score_id": str(uuid4()),
        "scored_at": datetime.now(tz=timezone.utc).isoformat(),
        "model_version": "isolation-forest-v1",
        "anomaly_score": 0.72,
        "is_anomaly": True,
        "threshold": 0.5,
        "host_id": "host-001",
        "source_event": _source_event().model_dump(mode="json"),
        "features": {"hour_of_day": 12.0, "src_port": 0.0},
    }


def test_scored_event_basic_roundtrip():
    src = _source_event()
    event = ScoredEvent(
        score_id=uuid4(),
        scored_at=datetime(2026, 5, 17, 12, 0, 2, tzinfo=timezone.utc),
        model_version="isolation-forest-v1",
        anomaly_score=0.72,
        is_anomaly=True,
        threshold=0.5,
        host_id="host-001",
        source_event=src,
        features={"hour_of_day": 12.0, "src_port": 0.0},
    )
    serialized = event.model_dump_json()
    rebuilt = ScoredEvent.model_validate_json(serialized)
    assert rebuilt == event
    assert rebuilt.source_event.event_type == "file.modified"
    assert rebuilt.features["hour_of_day"] == 12.0


def test_scored_event_rejects_unknown_field():
    payload = _base_payload()
    payload["mystery_field"] = "boom"
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)


def test_scored_event_rejects_unknown_model_version():
    payload = _base_payload()
    payload["model_version"] = "lstm-v1"  # v2; not allowed in v1
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)


def test_scored_event_rejects_anomaly_score_out_of_range():
    payload = _base_payload()
    payload["anomaly_score"] = 1.5
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)
    payload["anomaly_score"] = -0.01
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)


def test_scored_event_rejects_threshold_out_of_range():
    payload = _base_payload()
    payload["threshold"] = -0.1
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)
    payload["threshold"] = 1.01
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)


def test_scored_event_rejects_naive_scored_at():
    payload = _base_payload()
    payload["scored_at"] = datetime(2026, 5, 17, 12, 0, 0).isoformat()  # no tz
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)
