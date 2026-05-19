from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import fakeredis.aioredis

from intellifim_schemas import ThreatScoreUpdate

from policy.engine import PolicyEngine
from policy.redis_store import RedisScoreStore


_T0 = datetime(2026, 5, 18, 12, 0, 0, tzinfo=timezone.utc)


def _now_at(offset: int):
    def _now() -> datetime:
        return _T0 + timedelta(seconds=offset)
    return _now


class FakeConsumer:
    def __init__(self, events: list):
        self._events = list(events)
    def __aiter__(self): return self
    async def __anext__(self):
        if not self._events:
            raise StopAsyncIteration
        return self._events.pop(0)


class FakeProducer:
    def __init__(self):
        self.published: list[tuple[str, bytes, bytes | None]] = []
    async def send_and_wait(self, topic: str, value: bytes, key: bytes | None = None):
        self.published.append((topic, value, key))


class FakeMessage:
    def __init__(self, value: bytes | None):
        self.value = value


class FakeOpa:
    def __init__(self, response: dict | None):
        self._response = response
        self.calls = 0
    async def query(self, event):
        self.calls += 1
        return self._response


async def _make_store():
    """RedisScoreStore backed by fakeredis."""
    store = RedisScoreStore("redis://localhost:6379/0")
    await store.aclose()
    store._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return store


async def test_engine_emits_update_on_happy_path(make_scored_event):
    event = make_scored_event(anomaly_score=0.85)
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"score_delta": 25, "reason": "strong anomaly"})
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()

        assert len(producer.published) == 1
        topic, value, key = producer.published[0]
        assert topic == "threat.scores"
        assert key == b"host-001"
        update = ThreatScoreUpdate.model_validate_json(value)
        assert update.host_id == "host-001"
        assert update.score == 25.0
        assert update.contributions_in_window == 1
        assert update.last_score_delta == 25
        assert update.last_reason == "strong anomaly"
        assert update.window_seconds == 300
    finally:
        await store.aclose()


async def test_engine_accepts_scored_event_value_bytes(make_scored_event):
    """Production-realistic path: consumer yields a message with .value bytes."""
    event = make_scored_event()
    consumer = FakeConsumer([FakeMessage(event.model_dump_json().encode("utf-8"))])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"score_delta": 10, "reason": "moderate"})
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert len(producer.published) == 1
        update = ThreatScoreUpdate.model_validate_json(producer.published[0][1])
        assert update.last_event_id == event.source_event.event_id
    finally:
        await store.aclose()


async def test_engine_skips_on_opa_failure(make_scored_event):
    event = make_scored_event()
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa(None)  # OPA returns None
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert producer.published == []
        # And nothing was written to Redis
        count = await store._client.zcard("threat_score:host:host-001")
        assert count == 0
    finally:
        await store.aclose()


async def test_engine_skips_on_redis_append_failure(make_scored_event, monkeypatch):
    event = make_scored_event()
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"score_delta": 5, "reason": "weak"})
    try:
        async def broken_append(*args, **kwargs):
            return False  # simulate Redis error path
        monkeypatch.setattr(store, "append_contribution", broken_append)
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert producer.published == []
    finally:
        await store.aclose()


async def test_engine_drops_malformed_json(make_scored_event):
    consumer = FakeConsumer([
        FakeMessage(b'{"not":"a scored event"}'),
        FakeMessage(None),
    ])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"score_delta": 0, "reason": "benign"})
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert producer.published == []
        assert opa.calls == 0  # OPA was never queried
    finally:
        await store.aclose()


async def test_engine_continues_after_producer_failure(make_scored_event):
    e1 = make_scored_event(anomaly_score=0.85)
    e2 = make_scored_event(anomaly_score=0.4)
    consumer = FakeConsumer([e1, e2])
    store = await _make_store()
    opa = FakeOpa({"score_delta": 5, "reason": "weak"})

    class FlakyProducer:
        def __init__(self):
            self.calls = 0
            self.published: list[Any] = []
        async def send_and_wait(self, topic, value, key=None):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("simulated kafka outage")
            self.published.append((topic, value, key))

    producer = FlakyProducer()
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert producer.calls == 2
        assert len(producer.published) == 1
    finally:
        await store.aclose()


async def test_engine_score_accumulates_across_events(make_scored_event):
    """Two events from same host → score is sum of both deltas."""
    e1 = make_scored_event(anomaly_score=0.85)
    e2 = make_scored_event(anomaly_score=0.6)
    consumer = FakeConsumer([e1, e2])
    producer = FakeProducer()
    store = await _make_store()
    # Return different deltas for each call
    class SequentialOpa:
        def __init__(self):
            self._responses = [
                {"score_delta": 25, "reason": "strong"},
                {"score_delta": 10, "reason": "moderate"},
            ]
        async def query(self, event):
            return self._responses.pop(0)
    opa = SequentialOpa()
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert len(producer.published) == 2
        first = ThreatScoreUpdate.model_validate_json(producer.published[0][1])
        second = ThreatScoreUpdate.model_validate_json(producer.published[1][1])
        assert first.score == 25.0
        assert first.contributions_in_window == 1
        assert second.score == 35.0  # 25 + 10
        assert second.contributions_in_window == 2
    finally:
        await store.aclose()


async def test_engine_skips_on_malformed_opa_decision(make_scored_event):
    """OPA returns a dict missing score_delta → engine logs and skips, no publish, no Redis write."""
    event = make_scored_event()
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"reason": "missing delta"})  # missing score_delta key
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert producer.published == []
        count = await store._client.zcard("threat_score:host:host-001")
        assert count == 0
    finally:
        await store.aclose()


async def test_engine_clamps_out_of_range_score_delta(make_scored_event):
    """OPA returns score_delta=150 (out of [0,100]) → engine clamps to 100, publishes valid update."""
    event = make_scored_event()
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"score_delta": 150, "reason": "overflow tier"})
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert len(producer.published) == 1
        update = ThreatScoreUpdate.model_validate_json(producer.published[0][1])
        assert update.last_score_delta == 100  # clamped from 150
        assert update.score == 100.0  # also clamped by score=min(100, ...) clamp
    finally:
        await store.aclose()
