"""aiokafka consumer that tails `threat.scores` into the reporting store."""
from __future__ import annotations

import json
import logging

from aiokafka import AIOKafkaConsumer
from pydantic import ValidationError

from intellifim_schemas import ThreatScoreUpdate

from reporting.store import ReportingStore


logger = logging.getLogger(__name__)


def _extract_score(message) -> ThreatScoreUpdate | None:
    """Dual-mode: accept a typed ThreatScoreUpdate OR an object with .value bytes.

    Returns None for any decode/validation failure — the loop logs + skips so a
    single bad message can't stall the partition.
    """
    if isinstance(message, ThreatScoreUpdate):
        return message

    raw = getattr(message, "value", None)
    if not isinstance(raw, (bytes, bytearray)):
        return None
    try:
        payload = json.loads(raw)
        return ThreatScoreUpdate.model_validate(payload)
    except (json.JSONDecodeError, ValidationError, ValueError) as e:
        logger.warning("malformed threat.scores message: %s", e)
        return None


class KafkaScoreConsumer:
    def __init__(
        self,
        *,
        store: ReportingStore,
        bootstrap: str,
        topic: str,
        group_id: str,
    ) -> None:
        self._store = store
        self._bootstrap = bootstrap
        self._topic = topic
        self._group_id = group_id
        self._consumer: AIOKafkaConsumer | None = None

    async def start(self) -> None:
        self._consumer = AIOKafkaConsumer(
            self._topic,
            bootstrap_servers=self._bootstrap,
            group_id=self._group_id,
            auto_offset_reset="latest",
            enable_auto_commit=True,
        )
        await self._consumer.start()
        logger.info("kafka consumer started: topic=%s group=%s", self._topic, self._group_id)

    async def stop(self) -> None:
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None

    async def process_one(self, message) -> None:
        """Decode + persist a single message. Never raises on bad payload.

        Maps ThreatScoreUpdate to the flat threat_scores row shape:
        - last_reason -> reason
        - computed_at -> ts
        """
        upd = _extract_score(message)
        if upd is None:
            return
        await self._store.insert_score(
            host_id=upd.host_id,
            score=upd.score,
            reason=upd.last_reason,
            ts=upd.computed_at,
        )

    async def run(self) -> None:
        """Long-running consume loop. Caller is responsible for cancelation."""
        assert self._consumer is not None, "start() not called"
        async for msg in self._consumer:
            try:
                await self.process_one(msg)
            except Exception:   # defensive — never let a single bad event kill the loop
                logger.exception("error processing threat.scores message; continuing")
