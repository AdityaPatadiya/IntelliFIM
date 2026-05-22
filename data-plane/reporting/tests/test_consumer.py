"""Consumer tests — dual-mode _extract_score + run-one-iteration shape."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from intellifim_schemas import ThreatScoreUpdate

from reporting.consumer import _extract_score
from reporting.store import ReportingStore


@dataclass
class FakeMessage:
    """Stand-in for aiokafka.ConsumerRecord — only needs .value bytes."""
    value: bytes


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
        last_score_delta=10,
        last_reason="r",
    )


def test_extract_score_typed_fast_path():
    upd = _make_update()
    result = _extract_score(upd)
    assert result is upd   # identity — fast path returns the instance


def test_extract_score_bytes_path():
    upd = _make_update()
    raw = upd.model_dump_json().encode()
    result = _extract_score(FakeMessage(value=raw))
    assert isinstance(result, ThreatScoreUpdate)
    assert result.host_id == upd.host_id
    assert result.score == upd.score


def test_extract_score_malformed_returns_none():
    # garbage JSON
    assert _extract_score(FakeMessage(value=b"not-json")) is None
    # well-formed JSON but missing required fields
    assert _extract_score(FakeMessage(value=b'{"host_id":"001"}')) is None


@pytest.mark.asyncio
async def test_consumer_writes_to_store(tmp_path):
    """`process_one` writes a valid update into the store."""
    from reporting.consumer import KafkaScoreConsumer

    store = ReportingStore(
        db_path=str(tmp_path / "reporting.db"),
        reports_dir=str(tmp_path / "reports"),
    )
    await store.init_schema()
    try:
        consumer = KafkaScoreConsumer(
            store=store, bootstrap="ignored", topic="threat.scores", group_id="g"
        )
        upd = _make_update(host_id="999", score=77.0)
        await consumer.process_one(FakeMessage(value=upd.model_dump_json().encode()))
        rows = await store.query_scores(
            start=_T.replace(year=2029), end=_T.replace(year=2031)
        )
        assert len(rows) == 1
        assert rows[0].host_id == "999"
        assert rows[0].score == 77.0

        # Malformed message must NOT raise; partition must keep moving.
        await consumer.process_one(FakeMessage(value=b"garbage"))
        rows2 = await store.query_scores(
            start=_T.replace(year=2029), end=_T.replace(year=2031)
        )
        assert len(rows2) == 1   # still only one row
    finally:
        await store.aclose()
