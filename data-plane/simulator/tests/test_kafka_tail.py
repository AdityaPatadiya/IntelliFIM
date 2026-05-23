"""kafka_tail tests — dual-mode _extract_update + match-filter shape."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from intellifim_schemas import ThreatScoreUpdate

from simulator.kafka_tail import _extract_update, _is_match


_T = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _make_update(host_id: str = "001", score: float = 42.0) -> ThreatScoreUpdate:
    return ThreatScoreUpdate(
        update_id=uuid4(),
        computed_at=_T,
        host_id=host_id,
        score=score,
        window_seconds=300,
        contributions_in_window=1,
        last_event_id=uuid4(),
        last_score_delta=int(score),
        last_reason="test",
    )


def test_extract_update_typed_fast_path():
    upd = _make_update()
    result = _extract_update(upd)
    assert result is upd


def test_extract_update_bytes_path(fake_message_cls):
    upd = _make_update(host_id="042", score=77.0)
    raw = upd.model_dump_json().encode()
    result = _extract_update(fake_message_cls(value=raw))
    assert isinstance(result, ThreatScoreUpdate)
    assert result.host_id == "042"
    assert result.score == 77.0


def test_extract_update_malformed_returns_none(fake_message_cls):
    assert _extract_update(fake_message_cls(value=b"not-json")) is None
    assert _extract_update(fake_message_cls(value=b'{"host_id":"001"}')) is None


def test_is_match_threshold_and_host():
    high = _make_update(host_id="001", score=42.0)
    low = _make_update(host_id="001", score=10.0)
    wrong_host = _make_update(host_id="999", score=99.0)

    assert _is_match(high, host_id="001", threshold=30.0) is True
    assert _is_match(low, host_id="001", threshold=30.0) is False
    assert _is_match(wrong_host, host_id="001", threshold=30.0) is False
    # threshold edge: score == threshold is a match
    edge = _make_update(host_id="001", score=30.0)
    assert _is_match(edge, host_id="001", threshold=30.0) is True
