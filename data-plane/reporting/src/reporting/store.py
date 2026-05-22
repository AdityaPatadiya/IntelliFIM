"""SQLite-backed store for reporting service.

Two tables:
- `threat_scores` — append-log populated by the Kafka consumer.
- `reports` — generated-report metadata; PDF bytes live on filesystem.

Pattern: aiosqlite + asyncio.Lock single-writer. Reads are concurrent.
`init_schema()` is idempotent. `aclose()` discipline matches orchestrator's
WazuhClient + auth-backend's UsersStore.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

import aiosqlite


def _to_utc_iso(dt: datetime) -> str:
    """Convert a tz-aware datetime to canonical UTC ISO-8601.

    Naive datetimes are rejected — SQLite stores ts as TEXT and we need
    lex-comparable values for range queries.
    """
    if dt.tzinfo is None:
        raise ValueError("naive datetime not allowed; pass tz-aware UTC")
    return dt.astimezone(timezone.utc).isoformat()


_CREATE_THREAT_SCORES = """
CREATE TABLE IF NOT EXISTS threat_scores (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id TEXT NOT NULL,
    score   REAL NOT NULL,
    reason  TEXT NOT NULL,
    ts      TEXT NOT NULL
);
"""
_IDX_THREAT_SCORES_TS = "CREATE INDEX IF NOT EXISTS idx_threat_scores_ts ON threat_scores(ts);"
_IDX_THREAT_SCORES_HOST_TS = (
    "CREATE INDEX IF NOT EXISTS idx_threat_scores_host_ts "
    "ON threat_scores(host_id, ts);"
)

_CREATE_REPORTS = """
CREATE TABLE IF NOT EXISTS reports (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    range_start     TEXT NOT NULL,
    range_end       TEXT NOT NULL,
    generated_at    TEXT NOT NULL,
    generated_by    TEXT NOT NULL,
    pdf_path        TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    approvals_count INTEGER NOT NULL,
    scores_count    INTEGER NOT NULL
);
"""
_IDX_REPORTS_GEN_AT = (
    "CREATE INDEX IF NOT EXISTS idx_reports_generated_at "
    "ON reports(generated_at DESC);"
)


@dataclass(frozen=True)
class ScoreRow:
    host_id: str
    score: float
    reason: str
    ts: str  # ISO-8601 UTC


@dataclass(frozen=True)
class ReportRow:
    id: UUID
    name: str
    range_start: str
    range_end: str
    generated_at: str
    generated_by: str
    pdf_path: str
    size_bytes: int
    approvals_count: int
    scores_count: int


class ReportingStore:
    def __init__(self, db_path: str, reports_dir: str) -> None:
        self._db_path = db_path
        self._reports_dir = reports_dir
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def init_schema(self) -> None:
        if self._conn is not None:
            return
        os.makedirs(self._reports_dir, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        async with self._lock:
            await self._conn.execute(_CREATE_THREAT_SCORES)
            await self._conn.execute(_IDX_THREAT_SCORES_TS)
            await self._conn.execute(_IDX_THREAT_SCORES_HOST_TS)
            await self._conn.execute(_CREATE_REPORTS)
            await self._conn.execute(_IDX_REPORTS_GEN_AT)
            await self._conn.commit()

    async def aclose(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def reports_dir(self) -> str:
        return self._reports_dir

    # --- threat_scores --------------------------------------------------

    async def insert_score(
        self, *, host_id: str, score: float, reason: str, ts: datetime
    ) -> None:
        assert self._conn is not None, "init_schema() not called"
        ts_iso = _to_utc_iso(ts)
        async with self._lock:
            await self._conn.execute(
                "INSERT INTO threat_scores(host_id, score, reason, ts) "
                "VALUES(?, ?, ?, ?)",
                (host_id, score, reason, ts_iso),
            )
            await self._conn.commit()

    async def query_scores(
        self, *, start: datetime, end: datetime, host_id: str | None = None
    ) -> list[ScoreRow]:
        assert self._conn is not None
        sql = (
            "SELECT host_id, score, reason, ts FROM threat_scores "
            "WHERE ts >= ? AND ts < ?"
        )
        params: list = [_to_utc_iso(start), _to_utc_iso(end)]
        if host_id is not None:
            sql += " AND host_id = ?"
            params.append(host_id)
        sql += " ORDER BY ts ASC"
        async with self._conn.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
        return [
            ScoreRow(host_id=r["host_id"], score=r["score"], reason=r["reason"], ts=r["ts"])
            for r in rows
        ]

    async def top_hosts_by_max_score(
        self, *, start: datetime, end: datetime, limit: int = 10
    ) -> list[tuple[str, float]]:
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT host_id, MAX(score) AS max_score FROM threat_scores "
            "WHERE ts >= ? AND ts < ? "
            "GROUP BY host_id ORDER BY max_score DESC, host_id ASC LIMIT ?",
            (_to_utc_iso(start), _to_utc_iso(end), limit),
        ) as cursor:
            rows = await cursor.fetchall()
        return [(r["host_id"], r["max_score"]) for r in rows]

    # --- reports --------------------------------------------------------

    async def insert_report(
        self, *,
        id: UUID,
        name: str,
        range_start_iso: str,
        range_end_iso: str,
        generated_at_iso: str,
        generated_by: str,
        pdf_path: str,
        size_bytes: int,
        approvals_count: int,
        scores_count: int,
    ) -> None:
        assert self._conn is not None
        async with self._lock:
            await self._conn.execute(
                "INSERT INTO reports("
                "id, name, range_start, range_end, generated_at, "
                "generated_by, pdf_path, size_bytes, approvals_count, scores_count"
                ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(id), name, range_start_iso, range_end_iso, generated_at_iso,
                    generated_by, pdf_path, size_bytes, approvals_count, scores_count,
                ),
            )
            await self._conn.commit()

    async def list_reports(
        self, *, limit: int, offset: int
    ) -> tuple[list[ReportRow], int]:
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM reports ORDER BY generated_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()
        async with self._conn.execute("SELECT COUNT(*) AS n FROM reports") as cursor:
            total_row = await cursor.fetchone()
        total = int(total_row["n"]) if total_row else 0
        return [_row_to_report(r) for r in rows], total

    async def get_report(self, id: UUID) -> ReportRow | None:
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM reports WHERE id = ?", (str(id),)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_report(row)

    async def delete_report(self, id: UUID) -> bool:
        assert self._conn is not None
        async with self._lock:
            async with self._conn.execute(
                "SELECT pdf_path FROM reports WHERE id = ?", (str(id),)
            ) as cursor:
                row = await cursor.fetchone()
            if row is None:
                return False
            pdf_path = row["pdf_path"]
            await self._conn.execute("DELETE FROM reports WHERE id = ?", (str(id),))
            await self._conn.commit()
        try:
            os.unlink(pdf_path)
        except FileNotFoundError:
            pass   # idempotent — file already gone is fine
        return True


def _row_to_report(record) -> ReportRow:
    return ReportRow(
        id=UUID(record["id"]),
        name=record["name"],
        range_start=record["range_start"],
        range_end=record["range_end"],
        generated_at=record["generated_at"],
        generated_by=record["generated_by"],
        pdf_path=record["pdf_path"],
        size_bytes=int(record["size_bytes"]),
        approvals_count=int(record["approvals_count"]),
        scores_count=int(record["scores_count"]),
    )
