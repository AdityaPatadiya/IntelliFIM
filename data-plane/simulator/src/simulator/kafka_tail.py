"""Tails `threat.scores` after a scenario fires, waits for a qualifying update.

`auto_offset_reset="latest"` + a unique per-invocation `group_id` ensures we
only see post-attack messages. Returns the first message matching the
`(host_id, threshold)` filter, or None on timeout.
"""
from __future__ import annotations

import asyncio
import json
import logging
from uuid import uuid4

from aiokafka import AIOKafkaConsumer
from pydantic import ValidationError

from intellifim_schemas import ThreatScoreUpdate


logger = logging.getLogger(__name__)


def _extract_update(message) -> ThreatScoreUpdate | None:
    """Dual-mode: typed ThreatScoreUpdate (test fast-path) OR an object with .value bytes."""
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


def _is_match(update: ThreatScoreUpdate, *, host_id: str, threshold: float) -> bool:
    return update.host_id == host_id and update.score >= threshold


async def wait_for_match(
    *,
    bootstrap: str,
    topic: str,
    host_id: str,
    threshold: float,
    timeout_seconds: float,
) -> ThreatScoreUpdate | None:
    """Open a consumer, poll for up to `timeout_seconds`, return first match or None."""
    consumer = AIOKafkaConsumer(
        topic,
        bootstrap_servers=bootstrap,
        group_id=f"intellifim-simulator-{uuid4()}",
        auto_offset_reset="latest",
        enable_auto_commit=False,
    )
    await consumer.start()
    try:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return None
            try:
                batch = await asyncio.wait_for(
                    consumer.getmany(timeout_ms=int(min(remaining, 1.0) * 1000), max_records=64),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                return None
            for _tp, messages in batch.items():
                for msg in messages:
                    upd = _extract_update(msg)
                    if upd is not None and _is_match(upd, host_id=host_id, threshold=threshold):
                        return upd
    finally:
        await consumer.stop()
