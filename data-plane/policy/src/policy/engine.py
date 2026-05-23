"""PolicyEngine — consume ScoredEvents, query OPA, update Redis, publish ThreatScoreUpdates.

Offset-commit policy: same as data-plane normalizers + correlator + anomaly —
no manual commit; expects the consumer to have enable_auto_commit=True
(aiokafka default). Combined with the log-and-skip error policy in
_safe_publish + OPA/Redis client failures (each returns None / False),
no single bad message or transient external failure can stall a partition.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from uuid import uuid4

from pydantic import ValidationError

from intellifim_schemas import ScoredEvent, ThreatScoreUpdate

from policy.metrics import (
    SERVICE_LABEL,
    errors_total,
    messages_processed_total,
    processing_seconds,
)
from policy.opa_client import OpaClient
from policy.redis_store import RedisScoreStore

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


class PolicyEngine:
    def __init__(
        self,
        *,
        consumer: _Consumer,
        producer: _Producer,
        output_topic: str,
        opa: OpaClient,
        store: RedisScoreStore,
        window_seconds: int,
        now: Callable[[], datetime] = _default_now,
    ) -> None:
        self._consumer = consumer
        self._producer = producer
        self._output_topic = output_topic
        self._opa = opa
        self._store = store
        self._window_seconds = window_seconds
        self._now = now

    async def run(self) -> None:
        async for raw_message in self._consumer:
            try:
                await self.process_one(raw_message)
            except Exception:  # noqa: BLE001 - defensive: never let a single bad event kill the loop
                log.exception("error processing message; continuing")

    async def process_one(self, raw_message: Any) -> None:
        """Process a single Kafka record: extract → OPA query → Redis append → publish.

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
                update = await self._process(event)
                if update is None:
                    messages_processed_total.labels(SERVICE_LABEL).inc()
                    return
                await self._safe_publish(update)
                messages_processed_total.labels(SERVICE_LABEL).inc()
            except Exception as e:
                errors_total.labels(service=SERVICE_LABEL, kind=type(e).__name__).inc()
                raise

    @staticmethod
    def _extract_event(message: Any) -> ScoredEvent | None:
        if isinstance(message, ScoredEvent):
            return message
        value = getattr(message, "value", None)
        if value is None:
            log.warning("dropping message with no value")
            return None
        try:
            return ScoredEvent.model_validate_json(value)
        except ValidationError as exc:
            log.warning("dropping invalid ScoredEvent (%s)", exc)
            return None

    async def _process(self, event: ScoredEvent) -> ThreatScoreUpdate | None:
        decision = await self._opa.query(event)
        if decision is None:
            return None

        try:
            score_delta = int(decision["score_delta"])
            reason = str(decision["reason"])
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("dropping malformed OPA decision %s (%s)", decision, exc)
            return None
        # Clamp to ThreatScoreUpdate.last_score_delta's [0, 100] Field range so
        # an out-of-range Rego value can't raise ValidationError and stall the
        # partition. Mirrors the score=min(100.0, ...) clamp below.
        score_delta = max(0, min(100, score_delta))

        appended = await self._store.append_contribution(
            host_id=event.host_id,
            ts=self._now(),
            delta=score_delta,
            event_id=event.source_event.event_id,
        )
        if not appended:
            return None

        score, contributions = await self._store.current_score(
            host_id=event.host_id,
            window_seconds=self._window_seconds,
            now=self._now(),
        )

        return ThreatScoreUpdate(
            update_id=uuid4(),
            computed_at=self._now(),
            host_id=event.host_id,
            score=min(100.0, float(score)),
            window_seconds=self._window_seconds,
            contributions_in_window=contributions,
            last_event_id=event.source_event.event_id,
            last_score_delta=score_delta,
            last_reason=reason,
        )

    async def _safe_publish(self, update: ThreatScoreUpdate) -> None:
        try:
            await self._producer.send_and_wait(
                self._output_topic,
                value=update.model_dump_json().encode("utf-8"),
                key=update.host_id.encode("utf-8"),
            )
        except Exception as exc:  # noqa: BLE001 - Kafka error must not crash the loop
            log.warning(
                "publish failed (%s); skipping update %s", exc, update.update_id
            )
