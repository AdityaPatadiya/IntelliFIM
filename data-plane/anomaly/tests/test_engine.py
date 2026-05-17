from datetime import datetime, timezone
from typing import Any

import pytest

from intellifim_schemas import ScoredEvent

from anomaly.engine import AnomalyEngine
from anomaly.train import train


_T0 = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)


def _now_at(seconds_offset: int):
    def _now() -> datetime:
        from datetime import timedelta
        return _T0 + timedelta(seconds=seconds_offset)
    return _now


class FakeConsumer:
    def __init__(self, events: list):
        self._events = list(events)

    def __aiter__(self):
        return self

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
    """Mimics aiokafka ConsumerRecord — only .value is used by _extract_event."""
    def __init__(self, value: bytes | None):
        self.value = value


def _fit_model(make_event):
    """Train a small IsolationForest for use in engine tests."""
    events = [
        make_event(event_type="file.modified", source="wazuh.fim")
        for _ in range(10)
    ] + [
        make_event(
            event_type="network.flow", source="zeek.conn",
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=49152 + i, dst_port=443, protocol="tcp",
        )
        for i in range(10)
    ]
    return train(events)


async def test_engine_scores_event_and_publishes(make_event):
    bundle = _fit_model(make_event)
    event = make_event(event_type="file.modified", source="wazuh.fim")
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    engine = AnomalyEngine(
        consumer=consumer, producer=producer,
        output_topic="events.scored",
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        model_version=bundle["model_version"],
        threshold=0.5,
        now=_now_at(0),
    )
    await engine.run()

    assert len(producer.published) == 1
    topic, value, key = producer.published[0]
    assert topic == "events.scored"
    assert key == b"host-001"
    rebuilt = ScoredEvent.model_validate_json(value)
    assert rebuilt.model_version == "isolation-forest-v1"
    assert rebuilt.host_id == "host-001"
    assert 0.0 <= rebuilt.anomaly_score <= 1.0
    assert rebuilt.threshold == 0.5
    assert rebuilt.source_event.event_id == event.event_id
    assert set(rebuilt.features.keys()) == set(bundle["feature_names"])


async def test_engine_threshold_boundary_inclusive(make_event):
    """is_anomaly must be True when anomaly_score == threshold (>= boundary)."""
    bundle = _fit_model(make_event)
    event = make_event()
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    engine = AnomalyEngine(
        consumer=consumer, producer=producer,
        output_topic="events.scored",
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        model_version=bundle["model_version"],
        threshold=0.0,  # everything is_anomaly at this threshold
        now=_now_at(0),
    )
    await engine.run()
    rebuilt = ScoredEvent.model_validate_json(producer.published[0][1])
    assert rebuilt.is_anomaly is True


async def test_engine_accepts_kafka_message_with_value_bytes(make_event):
    bundle = _fit_model(make_event)
    event = make_event(event_type="file.modified")
    consumer = FakeConsumer([FakeMessage(event.model_dump_json().encode("utf-8"))])
    producer = FakeProducer()
    engine = AnomalyEngine(
        consumer=consumer, producer=producer,
        output_topic="events.scored",
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        model_version=bundle["model_version"],
        threshold=0.5,
        now=_now_at(0),
    )
    await engine.run()
    assert len(producer.published) == 1
    rebuilt = ScoredEvent.model_validate_json(producer.published[0][1])
    assert rebuilt.source_event.event_id == event.event_id


async def test_engine_drops_malformed_json(make_event):
    bundle = _fit_model(make_event)
    consumer = FakeConsumer([
        FakeMessage(b'{"not":"a canonical event"}'),
        FakeMessage(None),
    ])
    producer = FakeProducer()
    engine = AnomalyEngine(
        consumer=consumer, producer=producer,
        output_topic="events.scored",
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        model_version=bundle["model_version"],
        threshold=0.5,
        now=_now_at(0),
    )
    await engine.run()
    assert producer.published == []


async def test_engine_continues_after_producer_failure(make_event):
    """A transient producer error must not crash the loop."""
    bundle = _fit_model(make_event)
    e1 = make_event(event_type="file.modified")
    e2 = make_event(event_type="file.created")
    consumer = FakeConsumer([e1, e2])

    class FlakyProducer:
        def __init__(self):
            self.calls = 0
            self.published: list[Any] = []

        async def send_and_wait(self, topic: str, value: bytes, key: bytes | None = None):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("simulated kafka outage")
            self.published.append((topic, value, key))

    producer = FlakyProducer()
    engine = AnomalyEngine(
        consumer=consumer, producer=producer,
        output_topic="events.scored",
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        model_version=bundle["model_version"],
        threshold=0.5,
        now=_now_at(0),
    )
    await engine.run()
    assert producer.calls == 2
    assert len(producer.published) == 1


async def test_engine_accepts_canonical_event_instance(make_event):
    """Test fast-path: consumer yields a CanonicalEvent directly (not wrapped)."""
    bundle = _fit_model(make_event)
    event = make_event()
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    engine = AnomalyEngine(
        consumer=consumer, producer=producer,
        output_topic="events.scored",
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        model_version=bundle["model_version"],
        threshold=0.5,
        now=_now_at(0),
    )
    await engine.run()
    assert len(producer.published) == 1


def test_engine_drift_guard_rejects_mismatched_feature_names(make_event):
    """If pickled feature_names != extractor output, init must raise."""
    bundle = _fit_model(make_event)
    bad_names = bundle["feature_names"] + ["bogus_extra_feature"]
    with pytest.raises(RuntimeError, match="feature schema drift"):
        AnomalyEngine(
            consumer=FakeConsumer([]),
            producer=FakeProducer(),
            output_topic="events.scored",
            model=bundle["model"],
            feature_names=bad_names,
            model_version=bundle["model_version"],
            threshold=0.5,
            now=_now_at(0),
        )
