from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import pytest

from intellifim_schemas import CanonicalEvent
from normalizers.base import NormalizerLoop


class FakeConsumer:
    def __init__(self, messages: list[dict]):
        self._messages = list(messages)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._messages:
            raise StopAsyncIteration
        return self._messages.pop(0)


class FakeProducer:
    def __init__(self):
        self.published: list[tuple[str, bytes]] = []

    async def send_and_wait(self, topic: str, value: bytes, key: bytes | None = None):
        self.published.append((topic, value))


def _ok_transform(raw: dict) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="file.modified",
        source="wazuh.fim",
        timestamp=datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc),
        ingest_timestamp=datetime.now(tz=timezone.utc),
        host_id=raw["agent"]["id"],
        raw=raw,
    )


async def test_loop_transforms_and_publishes():
    consumer = FakeConsumer([{"agent": {"id": "agent-001"}, "syscheck": {"path": "/etc/shadow"}}])
    producer = FakeProducer()
    loop = NormalizerLoop(
        consumer=consumer,
        producer=producer,
        output_topic="events.normalized",
        transform=_ok_transform,
    )
    await loop.run()
    assert len(producer.published) == 1
    topic, value = producer.published[0]
    assert topic == "events.normalized"
    rebuilt = CanonicalEvent.model_validate_json(value)
    assert rebuilt.host_id == "agent-001"


async def test_loop_skips_transform_failure():
    consumer = FakeConsumer([
        {"agent": {"id": "agent-001"}},  # ok
        {"missing": "agent-key"},        # _broken_transform raises
        {"agent": {"id": "agent-002"}},  # ok
    ])
    producer = FakeProducer()

    def transform(raw: dict) -> CanonicalEvent:
        if "agent" not in raw:
            raise KeyError("agent")
        return _ok_transform(raw)

    loop = NormalizerLoop(
        consumer=consumer,
        producer=producer,
        output_topic="events.normalized",
        transform=transform,
    )
    await loop.run()
    assert len(producer.published) == 2  # broken one skipped, two survivors


async def test_loop_skips_validation_failure():
    consumer = FakeConsumer([{"agent": {"id": "agent-001"}}])
    producer = FakeProducer()

    def bad_transform(raw: dict) -> Any:
        # Returns a dict that can't be validated as CanonicalEvent — missing fields.
        return {"event_type": "file.modified"}

    loop = NormalizerLoop(
        consumer=consumer,
        producer=producer,
        output_topic="events.normalized",
        transform=bad_transform,
    )
    await loop.run()
    assert producer.published == []


async def test_loop_continues_after_producer_failure():
    """A transient producer error must NOT crash the loop.

    Real Kafka clients raise on broker disconnect / request timeout. The loop
    must log + skip and keep consuming so the partition does not stall.
    """
    consumer = FakeConsumer([
        {"agent": {"id": "agent-001"}},
        {"agent": {"id": "agent-002"}},
        {"agent": {"id": "agent-003"}},
    ])

    class FlakyProducer:
        def __init__(self) -> None:
            self.calls = 0
            self.published: list[tuple[str, bytes]] = []

        async def send_and_wait(self, topic: str, value: bytes, key: bytes | None = None) -> None:
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("simulated kafka outage")
            self.published.append((topic, value))

    producer = FlakyProducer()
    loop = NormalizerLoop(
        consumer=consumer,
        producer=producer,
        output_topic="events.normalized",
        transform=_ok_transform,
    )
    await loop.run()
    assert producer.calls == 3                 # all three attempted
    assert len(producer.published) == 2        # 1st + 3rd succeeded; 2nd was dropped
