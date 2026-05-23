"""OrchestratorEngine - consume ThreatScoreUpdate, classify, dedupe, insert.

Offset-commit policy: same as data-plane normalizers + correlator + anomaly +
policy - no manual commit; expects the consumer to have enable_auto_commit=True
(aiokafka default). No external dispatch happens in the engine itself - the
API's /approve handler dispatches to Wazuh. The engine is purely a sink:
ThreatScoreUpdate -> SQLite.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from pydantic import ValidationError

from intellifim_schemas import ThreatScoreUpdate

from orchestrator.metrics import (
    SERVICE_LABEL,
    errors_total,
    messages_processed_total,
    processing_seconds,
)
from orchestrator.store import ApprovalStore
from orchestrator.tier import Tier, classify

log = logging.getLogger(__name__)


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


class _Consumer(Protocol):
    def __aiter__(self) -> "_Consumer": ...
    async def __anext__(self) -> Any: ...


_PRIORITY_BY_TIER: dict[Tier, str] = {
    Tier.LOW_URGENCY: "low",
    Tier.HIGH_URGENCY: "high",
}


class OrchestratorEngine:
    def __init__(
        self,
        *,
        consumer: _Consumer,
        store: ApprovalStore,
        tier_low: float,
        tier_high: float,
        now: Callable[[], datetime] = _default_now,
    ) -> None:
        self._consumer = consumer
        self._store = store
        self._tier_low = tier_low
        self._tier_high = tier_high
        self._now = now

    async def run(self) -> None:
        async for raw_message in self._consumer:
            update = self._extract_event(raw_message)
            if update is None:
                continue
            await self._process(update)

    @staticmethod
    def _extract_event(message: Any) -> ThreatScoreUpdate | None:
        if isinstance(message, ThreatScoreUpdate):
            return message
        value = getattr(message, "value", None)
        if value is None:
            log.warning("dropping message with no value")
            return None
        try:
            return ThreatScoreUpdate.model_validate_json(value)
        except ValidationError as exc:
            log.warning("dropping invalid ThreatScoreUpdate (%s)", exc)
            return None

    async def _process(self, update: ThreatScoreUpdate) -> None:
        with processing_seconds.labels(SERVICE_LABEL).time():
            try:
                tier = classify(update.score, low=self._tier_low, high=self._tier_high)
                if tier is Tier.IGNORE:
                    log.info(
                        "ignoring host=%s score=%.1f (below tier_low=%.1f)",
                        update.host_id, update.score, self._tier_low,
                    )
                    messages_processed_total.labels(SERVICE_LABEL).inc()
                    return
                inserted = await self._store.insert_if_no_pending(
                    id=update.update_id,
                    host_id=update.host_id,
                    priority=_PRIORITY_BY_TIER[tier],
                    score=update.score,
                    last_reason=update.last_reason,
                    now=self._now(),
                )
                if not inserted:
                    log.info(
                        "deduped host=%s update_id=%s (host already PENDING or duplicate id)",
                        update.host_id, update.update_id,
                    )
                messages_processed_total.labels(SERVICE_LABEL).inc()
            except Exception as e:
                errors_total.labels(service=SERVICE_LABEL, kind=type(e).__name__).inc()
                raise
