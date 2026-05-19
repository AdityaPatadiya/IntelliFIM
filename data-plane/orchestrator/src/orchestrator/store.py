"""SQLite-backed approval-request store, async-friendly via aiosqlite.

Single table `approvals` with a partial index enforcing the per-host PENDING
singleton. All writes serialized via an asyncio.Lock; reads are concurrent.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import aiosqlite


_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS approvals (
    id            TEXT PRIMARY KEY,
    host_id       TEXT NOT NULL,
    priority      TEXT NOT NULL,
    score         REAL NOT NULL,
    last_reason   TEXT NOT NULL,
    state         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    decided_at    TEXT,
    executed_at   TEXT,
    decided_by    TEXT,
    error_message TEXT
);
"""

_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_approvals_host_pending
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
    created_at: str
    decided_at: str | None
    executed_at: str | None
    decided_by: str | None
    error_message: str | None


def _row(record) -> ApprovalRow:
    return ApprovalRow(
        id=UUID(record["id"]),
        host_id=record["host_id"],
        priority=record["priority"],
        score=record["score"],
        last_reason=record["last_reason"],
        state=record["state"],
        created_at=record["created_at"],
        decided_at=record["decided_at"],
        executed_at=record["executed_at"],
        decided_by=record["decided_by"],
        error_message=record["error_message"],
    )


class ApprovalStore:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def init_schema(self) -> None:
        if self._conn is not None:
            return  # idempotent — already initialized
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        async with self._lock:
            await self._conn.execute(_CREATE_TABLE)
            await self._conn.execute(_CREATE_INDEX)
            await self._conn.commit()

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
        assert self._conn is not None
        async with self._lock:
            # Check per-host PENDING singleton
            cur = await self._conn.execute(
                "SELECT 1 FROM approvals WHERE host_id = ? AND state = 'PENDING' LIMIT 1",
                (host_id,),
            )
            if await cur.fetchone() is not None:
                return False
            # INSERT OR IGNORE — duplicate id returns 0 rowcount, no exception
            cur = await self._conn.execute(
                """
                INSERT OR IGNORE INTO approvals (
                    id, host_id, priority, score, last_reason, state, created_at
                ) VALUES (?, ?, ?, ?, ?, 'PENDING', ?)
                """,
                (str(id), host_id, priority, score, last_reason, now.isoformat()),
            )
            await self._conn.commit()
            return cur.rowcount == 1

    async def list(self, state: str | None = "PENDING") -> list[ApprovalRow]:
        assert self._conn is not None
        if state is None:
            cur = await self._conn.execute(
                "SELECT * FROM approvals ORDER BY created_at DESC"
            )
        else:
            cur = await self._conn.execute(
                "SELECT * FROM approvals WHERE state = ? ORDER BY created_at DESC",
                (state,),
            )
        rows = await cur.fetchall()
        return [_row(r) for r in rows]

    async def get(self, id: UUID) -> ApprovalRow | None:
        assert self._conn is not None
        cur = await self._conn.execute(
            "SELECT * FROM approvals WHERE id = ?", (str(id),)
        )
        record = await cur.fetchone()
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
        assert self._conn is not None
        async with self._lock:
            params: list = [to_state]
            sets = ["state = ?"]
            if to_state in ("APPROVED", "REJECTED"):
                sets.append("decided_at = ?")
                sets.append("decided_by = ?")
                params.append(now.isoformat())
                params.append(decided_by)
            if to_state == "EXECUTED":
                sets.append("executed_at = ?")
                params.append((executed_at or now).isoformat())
            if to_state == "FAILED":
                sets.append("error_message = ?")
                params.append(error_message)
            params.extend([str(id), from_state])
            cur = await self._conn.execute(
                f"UPDATE approvals SET {', '.join(sets)} WHERE id = ? AND state = ?",
                params,
            )
            await self._conn.commit()
            if cur.rowcount == 0:
                return None
            return await self.get(id)

    async def aclose(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
