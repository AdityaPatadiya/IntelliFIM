from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from uuid import uuid4

from pydantic import ValidationError

from intellifim_schemas import CanonicalEvent, CorrelatedEvent

from correlator.buffer import HostBuffer
from correlator.metrics import (
    SERVICE_LABEL,
    errors_total,
    messages_processed_total,
    processing_seconds,
)

log = logging.getLogger(__name__)


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


class _Consumer(Protocol):
    def __aiter__(self) -> "_Consumer": ...
    async def __anext__(self) -> Any: ...


class _Producer(Protocol):
    async def send_and_wait(
        self, topic: str, value: bytes, key: bytes | None = ...
    ) -> Any: ...


class CorrelationEngine:
    """Consumes CanonicalEvents from `events.normalized`, maintains a per-host
    rolling buffer, and emits CorrelatedEvents whenever a file event matches
    a network event from the same host within the time window (or vice versa).

    Offset-commit policy: same as data-plane normalizers — no manual commit;
    expects the consumer to have `enable_auto_commit=True` (aiokafka default).
    Combined with the log-and-skip error policy, this guarantees the partition
    does not stall on a single bad message or transient publish failure.
    """

    def __init__(
        self,
        *,
        consumer: _Consumer,
        producer: _Producer,
        output_topic: str,
        buffer: HostBuffer,
        window_seconds: int,
        now: Callable[[], datetime] = _default_now,
    ) -> None:
        self._consumer = consumer
        self._producer = producer
        self._output_topic = output_topic
        self._buffer = buffer
        self._window_seconds = window_seconds
        self._now = now

    async def run(self) -> None:
        async for raw_message in self._consumer:
            try:
                await self.process_one(raw_message)
            except Exception:  # noqa: BLE001 - defensive: never let a single bad event kill the loop
                log.exception("error processing message; continuing")

    async def process_one(self, raw_message: Any) -> None:
        """Process a single Kafka record: extract → buffer → match → publish.

        Wrapped in RED-method Prometheus metrics so latency + throughput +
        per-exception-type error rates are observable. Exceptions are
        re-raised so the outer run-loop can log them (and so tests can assert
        on the raise) — the loop swallows them at its own boundary.
        """
        with processing_seconds.labels(SERVICE_LABEL).time():
            try:
                event = self._extract_event(raw_message)
                if event is None:
                    messages_processed_total.labels(SERVICE_LABEL).inc()
                    return
                self._buffer.add(event)
                counterparts = self._find_counterparts(event)
                if counterparts:
                    correlation = self._build_correlation(event, counterparts)
                    await self._safe_publish(correlation)
                messages_processed_total.labels(SERVICE_LABEL).inc()
            except Exception as e:
                errors_total.labels(service=SERVICE_LABEL, kind=type(e).__name__).inc()
                raise

    @staticmethod
    def _extract_event(message: Any) -> CanonicalEvent | None:
        # Real aiokafka messages have a `.value` attribute (bytes); fakes in
        # tests yield CanonicalEvent instances directly. Accept both.
        if isinstance(message, CanonicalEvent):
            return message
        value = getattr(message, "value", None)
        if value is None:
            log.warning("dropping message with no value")
            return None
        try:
            return CanonicalEvent.model_validate_json(value)
        except ValidationError as exc:
            log.warning("dropping invalid CanonicalEvent (%s)", exc)
            return None

    def _find_counterparts(self, event: CanonicalEvent) -> list[CanonicalEvent]:
        if event.event_type.startswith("file."):
            target_predicate = lambda e: e.event_type.startswith("network.")  # noqa: E731
        elif event.event_type.startswith("network."):
            target_predicate = lambda e: e.event_type.startswith("file.")  # noqa: E731
        else:
            return []
        # Exclude the just-added event itself by event_id (it could match its
        # own predicate if predicates ever overlap; not in v1, but defensive).
        return [
            e for e in self._buffer.recent(event.host_id, target_predicate)
            if e.event_id != event.event_id
        ]

    def _build_correlation(
        self,
        triggering: CanonicalEvent,
        co_occurring: list[CanonicalEvent],
    ) -> CorrelatedEvent:
        return CorrelatedEvent(
            correlation_id=uuid4(),
            correlation_type="file_with_network",
            correlated_at=self._now(),
            window_seconds=self._window_seconds,
            host_id=triggering.host_id,
            triggering_event=triggering,
            co_occurring_events=co_occurring,
        )

    async def _safe_publish(self, event: CorrelatedEvent) -> None:
        try:
            await self._producer.send_and_wait(
                self._output_topic,
                value=event.model_dump_json().encode("utf-8"),
                key=event.host_id.encode("utf-8"),
            )
        except Exception as exc:  # noqa: BLE001 - any Kafka error must not crash the loop
            log.warning(
                "publish failed (%s); skipping correlation %s", exc, event.correlation_id
            )
