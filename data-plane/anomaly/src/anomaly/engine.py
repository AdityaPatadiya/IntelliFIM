"""AnomalyEngine — consume CanonicalEvents, score with IsolationForest, publish ScoredEvents.

Offset-commit policy: same as data-plane normalizers + correlator — no
manual commit; expects the consumer to have enable_auto_commit=True
(aiokafka default). Combined with the log-and-skip error policy in
_safe_publish + _extract_event, no single bad message or transient
publish failure can stall a partition.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from uuid import UUID, uuid4

import numpy as np
from pydantic import ValidationError

from intellifim_schemas import CanonicalEvent, ScoredEvent

from anomaly.features import extract

log = logging.getLogger(__name__)


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


# Minimal valid CanonicalEvent used at engine init to verify the extractor's
# output keys match the pickled feature_names. This catches a class of bug
# where train.py and engine.py have drifted (someone edited features.py
# without rebuilding the model).
_SAMPLE_EVENT = CanonicalEvent(
    event_id=UUID("00000000-0000-0000-0000-000000000000"),
    event_type="file.modified",
    source="wazuh.fim",
    timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ingest_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    host_id="sample",
)


class _Consumer(Protocol):
    def __aiter__(self) -> "_Consumer": ...
    async def __anext__(self) -> Any: ...


class _Producer(Protocol):
    async def send_and_wait(
        self, topic: str, value: bytes, key: bytes | None = ...
    ) -> Any: ...


class AnomalyEngine:
    def __init__(
        self,
        *,
        consumer: _Consumer,
        producer: _Producer,
        output_topic: str,
        model: Any,
        feature_names: list[str],
        model_version: str,
        threshold: float,
        now: Callable[[], datetime] = _default_now,
    ) -> None:
        # Drift guard: extractor's output keys MUST match pickled feature_names.
        sample_keys = sorted(extract(_SAMPLE_EVENT).keys())
        if sample_keys != sorted(feature_names):
            raise RuntimeError(
                f"feature schema drift: pickle has {sorted(feature_names)}, "
                f"extractor produces {sample_keys}"
            )
        self._consumer = consumer
        self._producer = producer
        self._output_topic = output_topic
        self._model = model
        self._feature_names = list(feature_names)
        self._model_version = model_version
        self._threshold = threshold
        self._now = now

    async def run(self) -> None:
        async for raw_message in self._consumer:
            event = self._extract_event(raw_message)
            if event is None:
                continue
            scored = self._score(event)
            await self._safe_publish(scored)

    @staticmethod
    def _extract_event(message: Any) -> CanonicalEvent | None:
        # Real aiokafka messages have a `.value` attribute (bytes); test fakes
        # may yield CanonicalEvent instances directly. Accept both.
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

    def _score(self, event: CanonicalEvent) -> ScoredEvent:
        features = extract(event)
        X = np.array([[features[k] for k in self._feature_names]])
        decision = float(self._model.decision_function(X)[0])
        anomaly_score = max(0.0, min(1.0, 0.5 - decision))
        return ScoredEvent(
            score_id=uuid4(),
            scored_at=self._now(),
            model_version=self._model_version,
            anomaly_score=anomaly_score,
            is_anomaly=anomaly_score >= self._threshold,
            threshold=self._threshold,
            host_id=event.host_id,
            source_event=event,
            features=features,
        )

    async def _safe_publish(self, scored: ScoredEvent) -> None:
        try:
            await self._producer.send_and_wait(
                self._output_topic,
                value=scored.model_dump_json().encode("utf-8"),
                key=scored.host_id.encode("utf-8"),
            )
        except Exception as exc:  # noqa: BLE001 - Kafka error must not crash the loop
            log.warning(
                "publish failed (%s); skipping score %s", exc, scored.score_id
            )
