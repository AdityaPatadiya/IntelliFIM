from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Callable

from intellifim_schemas import CanonicalEvent


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


class HostBuffer:
    """Per-host rolling buffer of CanonicalEvents with lazy expiration.

    Events older than `window_seconds` (relative to the injected `now`) are
    discarded on add and on query. Pure data structure — no I/O. Not
    thread-safe; designed for single-task asyncio use within CorrelationEngine.
    """

    def __init__(
        self,
        *,
        window_seconds: int,
        now: Callable[[], datetime] = _default_now,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError(f"window_seconds must be positive, got {window_seconds}")
        self._window = timedelta(seconds=window_seconds)
        self._now = now
        self._buffers: dict[str, deque[CanonicalEvent]] = defaultdict(deque)

    def add(self, event: CanonicalEvent) -> None:
        host_buffer = self._buffers[event.host_id]
        self._expire(host_buffer)
        host_buffer.append(event)

    def recent(
        self,
        host_id: str,
        predicate: Callable[[CanonicalEvent], bool],
    ) -> list[CanonicalEvent]:
        # .get() (not [host_id]) so reads of unknown hosts don't bloat the
        # keyspace with empty deques. Side effect: expires stale entries (lazy GC).
        host_buffer = self._buffers.get(host_id)
        if host_buffer is None:
            return []
        self._expire(host_buffer)
        return [e for e in host_buffer if predicate(e)]

    def _expire(self, host_buffer: deque[CanonicalEvent]) -> None:
        cutoff = self._now() - self._window
        while host_buffer and host_buffer[0].timestamp < cutoff:
            host_buffer.popleft()
