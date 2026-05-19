from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from intellifim_schemas import ThreatScoreUpdate


def _base_payload() -> dict:
    return {
        "update_id": str(uuid4()),
        "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        "host_id": "host-001",
        "score": 42.5,
        "window_seconds": 300,
        "contributions_in_window": 7,
        "last_event_id": str(uuid4()),
        "last_score_delta": 10,
        "last_reason": "moderate anomaly",
    }


def test_threat_score_update_basic_roundtrip():
    event = ThreatScoreUpdate(
        update_id=uuid4(),
        computed_at=datetime(2026, 5, 18, 12, 0, 0, tzinfo=timezone.utc),
        host_id="host-001",
        score=42.5,
        window_seconds=300,
        contributions_in_window=7,
        last_event_id=uuid4(),
        last_score_delta=10,
        last_reason="moderate anomaly",
    )
    rebuilt = ThreatScoreUpdate.model_validate_json(event.model_dump_json())
    assert rebuilt == event


def test_threat_score_update_rejects_unknown_field():
    payload = _base_payload()
    payload["mystery_field"] = "boom"
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)


def test_threat_score_update_rejects_score_out_of_range():
    payload = _base_payload()
    payload["score"] = 100.01
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)
    payload["score"] = -0.01
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)


def test_threat_score_update_rejects_last_score_delta_out_of_range():
    payload = _base_payload()
    payload["last_score_delta"] = 101
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)
    payload["last_score_delta"] = -1
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)


def test_threat_score_update_rejects_non_positive_window():
    payload = _base_payload()
    payload["window_seconds"] = 0
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)
    payload["window_seconds"] = -10
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)


def test_threat_score_update_rejects_naive_computed_at():
    payload = _base_payload()
    payload["computed_at"] = datetime(2026, 5, 18, 12, 0, 0).isoformat()
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)
