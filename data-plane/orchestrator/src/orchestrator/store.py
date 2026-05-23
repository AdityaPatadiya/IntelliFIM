"""Postgres-backed approval-request store (v2).

asyncpg pool + native UUID / TIMESTAMPTZ types. External class shape +
method signatures match the v1 aiosqlite version exactly — callers
don't notice the swap.

The partial index `idx_approvals_host_pending WHERE state = 'PENDING'`
enforces the per-host PENDING-singleton guarantee (Postgres supports
partial indexes identically to SQLite). State transitions use
`UPDATE ... WHERE id = $1 AND state = $2` + rowcount check for race
detection — same pattern as v1, just with asyncpg's "UPDATE n" string
parsing instead of `cur.rowcount`.

Datetime contract preserved from v1: `created_at` / `decided_at` /
`executed_at` round-trip as ISO-8601 strings. `_row()` converts asyncpg's
native `datetime` back via `.isoformat()` so existing test assertions
like `row.created_at == _T0.isoformat()` keep passing.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import asyncpg


logger = logging.getLogger(__name__)


_CREATE_APPROVALS = """
CREATE TABLE IF NOT EXISTS approvals (
    id            UUID PRIMARY KEY,
    host_id       TEXT NOT NULL,
    priority      TEXT NOT NULL,
    score         DOUBLE PRECISION NOT NULL,
    last_reason   TEXT NOT NULL,
    state         TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    decided_at    TIMESTAMPTZ,
    executed_at   TIMESTAMPTZ,
    decided_by    TEXT,
    error_message TEXT
);
"""

_IDX_APPROVALS_HOST_PENDING = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_approvals_host_pending
    ON approvals(host_id) WHERE state = 'PENDING';
"""


@dataclass(frozen=True)
class ApprovalRow:
    id: UUID
    host_id: str
    priority: str
    score: float
    last_reason: str
    state: str
    created_at: str  # ISO-8601 (preserved from v1 aiosqlite contract)
    decided_at: str | None
    executed_at: str | None
    decided_by: str | None
    error_message: str | None


def _iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _row(record) -> ApprovalRow:
    return ApprovalRow(
        id=record["id"],
        host_id=record["host_id"],
        priority=record["priority"],
        score=float(record["score"]),
        last_reason=record["last_reason"],
        state=record["state"],
        created_at=_iso(record["created_at"]),
        decided_at=_iso(record["decided_at"]),
        executed_at=_iso(record["executed_at"]),
        decided_by=record["decided_by"],
        error_message=record["error_message"],
    )


class ApprovalStore:
    def __init__(
        self,
        database_url: str | None = None,
        *,
        pool: asyncpg.Pool | None = None,
    ) -> None:
        # Either `database_url` (production) or `pool` (tests using the
        # testcontainers fixture). The store only owns + closes the pool
        # if it created it.
        self._database_url = database_url
        self._pool: asyncpg.Pool | None = pool
        self._pool_owned = pool is None

    async def init_schema(self) -> None:
        if self._pool is None:
            if self._database_url is None:
                raise RuntimeError("database_url required when pool not provided")
            self._pool = await asyncpg.create_pool(
                self._database_url, min_size=1, max_size=8
            )
        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_APPROVALS)
            await conn.execute(_IDX_APPROVALS_HOST_PENDING)

    async def insert_if_no_pending(
        self,
        *,
        id: UUID,
        host_id: str,
        priority: str,
        score: float,
        last_reason: str,
        now: datetime,
    ) -> bool:
        """Insert a new PENDING row for `host_id` if (and only if):
          - the host has no current PENDING approval, AND
          - the `id` is not already in the table (duplicate-id dedupe).

        Returns True if the row was inserted, False otherwise. Matches v1
        contract exactly.
        """
        if self._pool is None:
            raise RuntimeError("call init_schema() first")
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                # Per-host PENDING singleton check
                existing_pending = await conn.fetchval(
                    "SELECT 1 FROM approvals WHERE host_id = $1 AND state = 'PENDING' LIMIT 1",
                    host_id,
                )
                if existing_pending is not None:
                    return False
                # Duplicate-id dedupe: ON CONFLICT DO NOTHING mirrors v1's
                # INSERT OR IGNORE — duplicate id yields no row.
                result = await conn.execute(
                    """
                    INSERT INTO approvals (
                        id, host_id, priority, score, last_reason, state, created_at
                    ) VALUES ($1, $2, $3, $4, $5, 'PENDING', $6)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    id, host_id, priority, score, last_reason, now,
                )
        # asyncpg's execute() returns a status string like "INSERT 0 1" or
        # "INSERT 0 0" — parse the trailing rowcount.
        try:
            rowcount = int(result.split()[-1])
        except (ValueError, IndexError):
            rowcount = 0
        return rowcount == 1

    async def list(self, state: str | None = "PENDING") -> list[ApprovalRow]:
        if self._pool is None:
            raise RuntimeError("call init_schema() first")
        async with self._pool.acquire() as conn:
            if state is None:
                rows = await conn.fetch(
                    "SELECT * FROM approvals ORDER BY created_at DESC"
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM approvals WHERE state = $1 ORDER BY created_at DESC",
                    state,
                )
        return [_row(r) for r in rows]

    async def get(self, id: UUID) -> ApprovalRow | None:
        if self._pool is None:
            raise RuntimeError("call init_schema() first")
        async with self._pool.acquire() as conn:
            record = await conn.fetchrow(
                "SELECT * FROM approvals WHERE id = $1", id
            )
        return _row(record) if record else None

    async def transition(
        self,
        *,
        id: UUID,
        from_state: str,
        to_state: str,
        now: datetime,
        decided_by: str | None = None,
        executed_at: datetime | None = None,
        error_message: str | None = None,
    ) -> ApprovalRow | None:
        """Atomic state transition. Returns the updated row on success,
        or None if the row was not in `from_state` (race / wrong state).
        Matches v1 contract exactly.
        """
        if self._pool is None:
            raise RuntimeError("call init_schema() first")
        sets: list[str] = ["state = $1"]
        params: list = [to_state]
        idx = 2
        if to_state in ("APPROVED", "REJECTED"):
            sets.append(f"decided_at = ${idx}")
            params.append(now)
            idx += 1
            sets.append(f"decided_by = ${idx}")
            params.append(decided_by)
            idx += 1
        if to_state == "EXECUTED":
            sets.append(f"executed_at = ${idx}")
            params.append(executed_at or now)
            idx += 1
        if to_state == "FAILED":
            sets.append(f"error_message = ${idx}")
            params.append(error_message)
            idx += 1
        # WHERE id = $idx AND state = $idx+1
        params.append(id)
        params.append(from_state)
        sql = (
            f"UPDATE approvals SET {', '.join(sets)} "
            f"WHERE id = ${idx} AND state = ${idx + 1}"
        )
        async with self._pool.acquire() as conn:
            result = await conn.execute(sql, *params)
        # asyncpg: "UPDATE n"
        try:
            rowcount = int(result.split()[-1])
        except (ValueError, IndexError):
            rowcount = 0
        if rowcount == 0:
            return None
        return await self.get(id)

    async def aclose(self) -> None:
        if self._pool is not None and self._pool_owned:
            await self._pool.close()
            self._pool = None
