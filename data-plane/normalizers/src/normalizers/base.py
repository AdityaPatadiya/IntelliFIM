from __future__ import annotations

import json
import logging
from typing import Any, Callable, Protocol

from pydantic import ValidationError

from intellifim_schemas import CanonicalEvent

log = logging.getLogger(__name__)

Transform = Callable[[dict], CanonicalEvent]


class _Consumer(Protocol):
    def __aiter__(self) -> "_Consumer": ...
    async def __anext__(self) -> Any: ...


class _Producer(Protocol):
    async def send_and_wait(
        self, topic: str, value: bytes, key: bytes | None = ...
    ) -> Any: ...


class NormalizerLoop:
    """Generic consume → transform → validate → produce loop.

    Per-source normalizers wire in a `transform` callable; the loop
    owns all the error handling and Kafka I/O so the source-specific
    code stays small and trivially testable.

    Offset-commit policy: this loop does NOT call `consumer.commit()`. The
    consumer is expected to be configured with `enable_auto_commit=True`
    (the aiokafka default). Together with the log-and-skip error policy,
    this means: a malformed or unpublishable message is skipped and its
    offset auto-committed; the partition does not stall.
    """

    def __init__(
        self,
        consumer: _Consumer,
        producer: _Producer,
        output_topic: str,
        transform: Transform,
    ) -> None:
        self._consumer = consumer
        self._producer = producer
        self._output_topic = output_topic
        self._transform = transform

    async def run(self) -> None:
        async for raw_message in self._consumer:
            payload = self._extract_payload(raw_message)
            if payload is None:
                continue
            event = self._safe_transform(payload)
            if event is None:
                continue
            await self._safe_publish(event)

    async def _safe_publish(self, event: CanonicalEvent) -> None:
        try:
            await self._producer.send_and_wait(
                self._output_topic,
                value=event.model_dump_json().encode("utf-8"),
                key=event.host_id.encode("utf-8"),
            )
        except Exception as exc:  # noqa: BLE001 - any Kafka error must not crash the loop
            log.warning("publish failed (%s); skipping event %s", exc, event.event_id)

    @staticmethod
    def _extract_payload(message: Any) -> dict | None:
        # Real aiokafka messages have a `.value` attribute (bytes); the
        # FakeConsumer in tests yields plain dicts. Accept both.
        if isinstance(message, dict):
            return message
        value = getattr(message, "value", None)
        if value is None:
            log.warning("dropping message with no value")
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            log.warning("dropping non-JSON message")
            return None

    def _safe_transform(self, raw: dict) -> CanonicalEvent | None:
        try:
            candidate = self._transform(raw)
        except Exception as exc:  # noqa: BLE001 - we want to skip ANY transform error
            log.warning("transform failed (%s); skipping event", exc)
            return None

        if not isinstance(candidate, CanonicalEvent):
            try:
                return CanonicalEvent.model_validate(candidate)
            except ValidationError as exc:
                log.warning("validation failed (%s); skipping event", exc)
                return None
        return candidate
