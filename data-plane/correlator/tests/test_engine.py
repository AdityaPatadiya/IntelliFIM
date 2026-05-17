from datetime import datetime, timedelta, timezone
from typing import Any

from intellifim_schemas import CorrelatedEvent

from correlator.buffer import HostBuffer
from correlator.engine import CorrelationEngine


_T0 = datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc)


def _now_at(seconds_offset: int):
    def _now() -> datetime:
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
    """Mimics aiokafka.ConsumerRecord shape — only `.value` is used by _extract_event."""
    def __init__(self, value: bytes | None):
        self.value = value


async def test_file_event_after_network_emits_correlation(make_event):
    """Network event arrives first, then file event; the file event triggers a match."""
    network = make_event(
        event_type="network.flow", source="zeek.conn",
        timestamp=_T0, host_id="host-001",
    )
    file_event = make_event(
        event_type="file.modified", source="wazuh.fim",
        timestamp=_T0 + timedelta(seconds=10), host_id="host-001",
    )
    consumer = FakeConsumer([network, file_event])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(10))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(10),
    )
    await engine.run()

    assert len(producer.published) == 1
    topic, value, key = producer.published[0]
    assert topic == "events.correlated"
    assert key == b"host-001"
    rebuilt = CorrelatedEvent.model_validate_json(value)
    assert rebuilt.correlation_type == "file_with_network"
    assert rebuilt.host_id == "host-001"
    assert rebuilt.window_seconds == 60
    assert rebuilt.triggering_event.event_type == "file.modified"
    assert len(rebuilt.co_occurring_events) == 1
    assert rebuilt.co_occurring_events[0].event_type == "network.flow"


async def test_network_event_after_file_emits_correlation(make_event):
    """File first, then network; the network event triggers the match."""
    file_event = make_event(
        event_type="file.modified", source="wazuh.fim",
        timestamp=_T0, host_id="host-001",
    )
    network = make_event(
        event_type="network.flow", source="zeek.conn",
        timestamp=_T0 + timedelta(seconds=10), host_id="host-001",
    )
    consumer = FakeConsumer([file_event, network])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(10))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(10),
    )
    await engine.run()

    assert len(producer.published) == 1
    rebuilt = CorrelatedEvent.model_validate_json(producer.published[0][1])
    assert rebuilt.triggering_event.event_type == "network.flow"
    assert rebuilt.co_occurring_events[0].event_type == "file.modified"


async def test_no_match_when_hosts_differ(make_event):
    a = make_event(event_type="file.modified", host_id="host-A", timestamp=_T0)
    b = make_event(event_type="network.flow", source="zeek.conn",
                   host_id="host-B", timestamp=_T0)
    consumer = FakeConsumer([a, b])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(0))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(0),
    )
    await engine.run()
    assert producer.published == []


async def test_no_emission_when_no_counterparts(make_event):
    """Two file events from same host, no network events: nothing to correlate."""
    a = make_event(event_type="file.modified", timestamp=_T0)
    b = make_event(event_type="file.created", timestamp=_T0 + timedelta(seconds=5))
    consumer = FakeConsumer([a, b])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(5))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(5),
    )
    await engine.run()
    assert producer.published == []


async def test_expired_counterparts_are_not_matched(make_event):
    """Network event arrives, then 120 s later a file event arrives. Window
    is 60 s — the network event should have expired from the buffer."""
    network = make_event(event_type="network.flow", source="zeek.conn", timestamp=_T0)
    file_event = make_event(
        event_type="file.modified", source="wazuh.fim",
        timestamp=_T0 + timedelta(seconds=120),
    )
    consumer = FakeConsumer([network, file_event])
    producer = FakeProducer()
    # `now` advances to T0+120 by the time the file event is processed.
    buffer = HostBuffer(window_seconds=60, now=_now_at(120))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(120),
    )
    await engine.run()
    assert producer.published == []


async def test_loop_continues_after_producer_failure(make_event):
    """A transient producer error must not crash the loop."""
    a_net = make_event(event_type="network.flow", source="zeek.conn", timestamp=_T0)
    a_file = make_event(event_type="file.modified", timestamp=_T0 + timedelta(seconds=1))
    b_net = make_event(event_type="network.flow", source="zeek.conn",
                       host_id="host-B", timestamp=_T0)
    b_file = make_event(event_type="file.modified", host_id="host-B",
                        timestamp=_T0 + timedelta(seconds=2))
    consumer = FakeConsumer([a_net, a_file, b_net, b_file])

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
    buffer = HostBuffer(window_seconds=60, now=_now_at(2))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(2),
    )
    await engine.run()
    assert producer.calls == 2  # both correlations attempted
    assert len(producer.published) == 1  # only the second one succeeded


async def test_parses_real_kafka_message_value(make_event):
    """End-to-end JSON path: a message with `.value=<bytes>` round-trips through
    CanonicalEvent.model_validate_json and produces a correlation."""
    network = make_event(event_type="network.flow", source="zeek.conn", timestamp=_T0)
    file_event = make_event(
        event_type="file.modified", source="wazuh.fim",
        timestamp=_T0 + timedelta(seconds=10),
    )
    consumer = FakeConsumer([
        FakeMessage(network.model_dump_json().encode("utf-8")),
        FakeMessage(file_event.model_dump_json().encode("utf-8")),
    ])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(10))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(10),
    )
    await engine.run()
    assert len(producer.published) == 1
    rebuilt = CorrelatedEvent.model_validate_json(producer.published[0][1])
    assert rebuilt.triggering_event.event_type == "file.modified"
    assert rebuilt.co_occurring_events[0].event_type == "network.flow"


async def test_drops_message_with_no_value():
    """A message whose .value is None must not crash the loop or emit anything."""
    consumer = FakeConsumer([FakeMessage(None)])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(0))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(0),
    )
    await engine.run()
    assert producer.published == []


async def test_drops_invalid_canonical_event_json():
    """A message whose JSON does not match CanonicalEvent must be skipped, not crash."""
    consumer = FakeConsumer([FakeMessage(b'{"not":"a canonical event"}')])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(0))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(0),
    )
    await engine.run()
    assert producer.published == []


async def test_multiple_counterparts_emitted_in_one_correlation(make_event):
    """Two network events from the same host, then one file event: the file event
    triggers a single CorrelatedEvent containing BOTH network events."""
    n1 = make_event(event_type="network.flow", source="zeek.conn", timestamp=_T0)
    n2 = make_event(
        event_type="network.flow", source="zeek.conn",
        timestamp=_T0 + timedelta(seconds=5),
    )
    file_event = make_event(
        event_type="file.modified", source="wazuh.fim",
        timestamp=_T0 + timedelta(seconds=10),
    )
    consumer = FakeConsumer([n1, n2, file_event])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(10))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(10),
    )
    await engine.run()
    assert len(producer.published) == 1
    rebuilt = CorrelatedEvent.model_validate_json(producer.published[0][1])
    assert rebuilt.triggering_event.event_type == "file.modified"
    assert len(rebuilt.co_occurring_events) == 2
    assert {e.event_id for e in rebuilt.co_occurring_events} == {n1.event_id, n2.event_id}
