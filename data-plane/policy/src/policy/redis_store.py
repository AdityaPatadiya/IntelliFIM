"""Async Redis wrapper for the per-host sliding-window threat score.

Uses a Redis sorted set per host: key=`threat_score:host:<host_id>`,
score=unix timestamp (float), member=JSON `{"delta": N, "event_id": "..."}`.

On every read, expired entries (timestamp < now - window_seconds) are
removed via ZREMRANGEBYSCORE; the current score is the sum of surviving
`delta` fields.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from uuid import UUID

from redis.asyncio import Redis
from redis.exceptions import RedisError

log = logging.getLogger(__name__)


def _host_key(host_id: str) -> str:
    return f"threat_score:host:{host_id}"


class RedisScoreStore:
    def __init__(self, redis_url: str) -> None:
        self._client: Redis = Redis.from_url(redis_url, decode_responses=True)

    async def append_contribution(
        self, *, host_id: str, ts: datetime, delta: int, event_id: UUID,
    ) -> bool:
        key = _host_key(host_id)
        score = ts.timestamp()
        member = json.dumps({"delta": delta, "event_id": str(event_id)})
        try:
            await self._client.zadd(key, {member: score})
        except RedisError as exc:
            log.warning("Redis ZADD failed for %s (%s)", key, exc)
            return False
        return True

    async def current_score(
        self, *, host_id: str, window_seconds: int, now: datetime,
    ) -> tuple[float, int]:
        key = _host_key(host_id)
        cutoff = now.timestamp() - window_seconds
        try:
            await self._client.zremrangebyscore(key, "-inf", f"({cutoff}")
            members = await self._client.zrangebyscore(key, cutoff, "+inf")
        except RedisError as exc:
            log.warning("Redis read failed for %s (%s)", key, exc)
            return (0.0, 0)
        total = 0
        for m in members:
            try:
                total += int(json.loads(m)["delta"])
            except (ValueError, KeyError, TypeError) as exc:
                log.warning("malformed member in %s: %s (%s)", key, m, exc)
        return (float(total), len(members))

    async def aclose(self) -> None:
        await self._client.aclose()
