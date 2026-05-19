import os
import tempfile
from datetime import datetime, timezone
from typing import Any

from orchestrator.engine import OrchestratorEngine
from orchestrator.store import ApprovalStore
from orchestrator.tier import Tier, classify


_T0 = datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc)


def _now() -> datetime:
    return _T0


class FakeConsumer:
    def __init__(self, events: list):
        self._events = list(events)
    def __aiter__(self): return self
    async def __anext__(self):
        if not self._events:
            raise StopAsyncIteration
        return self._events.pop(0)


class FakeMessage:
    def __init__(self, value: bytes | None):
        self.value = value


async def _make_store():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    store = ApprovalStore(path)
    await store.init_schema()
    return store, path


async def _cleanup(store, path):
    await store.aclose()
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def test_classify_below_threshold_returns_ignore():
    assert classify(0.0, low=30.0, high=70.0) is Tier.IGNORE
    assert classify(29.9, low=30.0, high=70.0) is Tier.IGNORE


def test_classify_at_low_threshold_returns_low_urgency():
    assert classify(30.0, low=30.0, high=70.0) is Tier.LOW_URGENCY
    assert classify(50.0, low=30.0, high=70.0) is Tier.LOW_URGENCY
    assert classify(69.9, low=30.0, high=70.0) is Tier.LOW_URGENCY


def test_classify_at_high_threshold_returns_high_urgency():
    assert classify(70.0, low=30.0, high=70.0) is Tier.HIGH_URGENCY
    assert classify(100.0, low=30.0, high=70.0) is Tier.HIGH_URGENCY


async def test_engine_ignores_low_score(make_threat_score_update):
    update = make_threat_score_update(score=10.0)
    store, path = await _make_store()
    try:
        engine = OrchestratorEngine(
            consumer=FakeConsumer([update]), store=store,
            tier_low=30.0, tier_high=70.0, now=_now,
        )
        await engine.run()
        assert await store.list(state="PENDING") == []
    finally:
        await _cleanup(store, path)


async def test_engine_inserts_low_priority(make_threat_score_update):
    update = make_threat_score_update(score=45.0)
    store, path = await _make_store()
    try:
        engine = OrchestratorEngine(
            consumer=FakeConsumer([update]), store=store,
            tier_low=30.0, tier_high=70.0, now=_now,
        )
        await engine.run()
        rows = await store.list(state="PENDING")
        assert len(rows) == 1
        assert rows[0].priority == "low"
        assert rows[0].host_id == update.host_id
        assert rows[0].score == 45.0
    finally:
        await _cleanup(store, path)


async def test_engine_inserts_high_priority(make_threat_score_update):
    update = make_threat_score_update(score=80.0)
    store, path = await _make_store()
    try:
        engine = OrchestratorEngine(
            consumer=FakeConsumer([update]), store=store,
            tier_low=30.0, tier_high=70.0, now=_now,
        )
        await engine.run()
        rows = await store.list(state="PENDING")
        assert len(rows) == 1
        assert rows[0].priority == "high"
    finally:
        await _cleanup(store, path)


async def test_engine_dedupes_while_pending(make_threat_score_update):
    """Second update for same host while PENDING -> ignored."""
    u1 = make_threat_score_update(score=45.0, host_id="001")
    u2 = make_threat_score_update(score=80.0, host_id="001")
    store, path = await _make_store()
    try:
        engine = OrchestratorEngine(
            consumer=FakeConsumer([u1, u2]), store=store,
            tier_low=30.0, tier_high=70.0, now=_now,
        )
        await engine.run()
        rows = await store.list(state="PENDING")
        assert len(rows) == 1
        assert rows[0].priority == "low"  # first update wins; no promotion in v1
    finally:
        await _cleanup(store, path)


async def test_engine_accepts_value_bytes(make_threat_score_update):
    """Production-realistic path: consumer yields a message with .value bytes."""
    update = make_threat_score_update(score=45.0)
    consumer = FakeConsumer([FakeMessage(update.model_dump_json().encode("utf-8"))])
    store, path = await _make_store()
    try:
        engine = OrchestratorEngine(
            consumer=consumer, store=store,
            tier_low=30.0, tier_high=70.0, now=_now,
        )
        await engine.run()
        rows = await store.list(state="PENDING")
        assert len(rows) == 1
    finally:
        await _cleanup(store, path)


async def test_engine_drops_malformed_json(make_threat_score_update):
    consumer = FakeConsumer([
        FakeMessage(b'{"not":"a ThreatScoreUpdate"}'),
        FakeMessage(None),
    ])
    store, path = await _make_store()
    try:
        engine = OrchestratorEngine(
            consumer=consumer, store=store,
            tier_low=30.0, tier_high=70.0, now=_now,
        )
        await engine.run()
        rows = await store.list(state=None)  # all rows
        assert rows == []
    finally:
        await _cleanup(store, path)
