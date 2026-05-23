"""Postgres-backed reporting store (v2).

Two tables:
- `threat_scores` — append-log populated by the Kafka consumer.
- `reports` — generated-report metadata; PDF bytes live on filesystem (NOT here).

Pattern: asyncpg pool + native UUID/TIMESTAMPTZ types. The v1 `_to_utc_iso(dt)`
helper is REMOVED — asyncpg handles TIMESTAMPTZ natively. Naive datetimes still
rejected at the boundary as a footgun guard.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import asyncpg


logger = logging.getLogger(__name__)


_CREATE_THREAT_SCORES = """
CREATE TABLE IF NOT EXISTS threat_scores (
    id      BIGSERIAL PRIMARY KEY,
    host_id TEXT NOT NULL,
    score   DOUBLE PRECISION NOT NULL,
    reason  TEXT NOT NULL,
    ts      TIMESTAMPTZ NOT NULL
);
"""
_IDX_THREAT_SCORES_TS = "CREATE INDEX IF NOT EXISTS idx_threat_scores_ts ON threat_scores(ts);"
_IDX_THREAT_SCORES_HOST_TS = (
    "CREATE INDEX IF NOT EXISTS idx_threat_scores_host_ts "
    "ON threat_scores(host_id, ts);"
)

_CREATE_REPORTS = """
CREATE TABLE IF NOT EXISTS reports (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL,
    range_start     TIMESTAMPTZ NOT NULL,
    range_end       TIMESTAMPTZ NOT NULL,
    generated_at    TIMESTAMPTZ NOT NULL,
    generated_by    TEXT NOT NULL,
    pdf_path        TEXT NOT NULL,
    size_bytes      BIGINT NOT NULL,
    approvals_count INTEGER NOT NULL,
    scores_count    INTEGER NOT NULL
);
"""
_IDX_REPORTS_GEN_AT = (
    "CREATE INDEX IF NOT EXISTS idx_reports_generated_at "
    "ON reports(generated_at DESC);"
)


def _reject_naive(dt: datetime, name: str) -> None:
    if dt.tzinfo is None:
        raise ValueError(f"{name}: naive datetime not allowed; pass tz-aware UTC")


@dataclass(frozen=True)
class ScoreRow:
    host_id: str
    score: float
    reason: str
    ts: datetime


@dataclass(frozen=True)
class ReportRow:
    id: UUID
    name: str
    range_start: datetime
    range_end: datetime
    generated_at: datetime
    generated_by: str
    pdf_path: str
    size_bytes: int
    approvals_count: int
    scores_count: int


class ReportingStore:
    def __init__(
        self,
        database_url: str | None = None,
        reports_dir: str = "/data/reports",
        *,
        pool: asyncpg.Pool | None = None,
    ) -> None:
        self._database_url = database_url
        self._reports_dir = reports_dir
        self._pool: asyncpg.Pool | None = pool
        self._pool_owned = pool is None

    @property
    def reports_dir(self) -> str:
        return self._reports_dir

    async def init_schema(self) -> None:
        if self._pool is None:
            assert self._database_url is not None
            self._pool = await asyncpg.create_pool(self._database_url, min_size=1, max_size=8)
        os.makedirs(self._reports_dir, exist_ok=True)
        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_THREAT_SCORES)
            await conn.execute(_IDX_THREAT_SCORES_TS)
            await conn.execute(_IDX_THREAT_SCORES_HOST_TS)
            await conn.execute(_CREATE_REPORTS)
            await conn.execute(_IDX_REPORTS_GEN_AT)

    async def aclose(self) -> None:
        if self._pool is not None and self._pool_owned:
            await self._pool.close()
            self._pool = None

    # --- threat_scores --------------------------------------------------

    async def insert_score(self, *, host_id: str, score: float, reason: str, ts: datetime) -> None:
        assert self._pool is not None
        _reject_naive(ts, "ts")
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO threat_scores(host_id, score, reason, ts) VALUES($1, $2, $3, $4)",
                host_id, score, reason, ts,
            )

    async def query_scores(
        self, *, start: datetime, end: datetime, host_id: str | None = None
    ) -> list[ScoreRow]:
        assert self._pool is not None
        _reject_naive(start, "start")
        _reject_naive(end, "end")
        async with self._pool.acquire() as conn:
            if host_id is not None:
                rows = await conn.fetch(
                    "SELECT host_id, score, reason, ts FROM threat_scores "
                    "WHERE ts >= $1 AND ts < $2 AND host_id = $3 ORDER BY ts ASC",
                    start, end, host_id,
                )
            else:
                rows = await conn.fetch(
                    "SELECT host_id, score, reason, ts FROM threat_scores "
                    "WHERE ts >= $1 AND ts < $2 ORDER BY ts ASC",
                    start, end,
                )
        return [
            ScoreRow(host_id=r["host_id"], score=float(r["score"]), reason=r["reason"], ts=r["ts"])
            for r in rows
        ]

    async def top_hosts_by_max_score(
        self, *, start: datetime, end: datetime, limit: int = 10
    ) -> list[tuple[str, float]]:
        assert self._pool is not None
        _reject_naive(start, "start")
        _reject_naive(end, "end")
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT host_id, MAX(score) AS max_score FROM threat_scores "
                "WHERE ts >= $1 AND ts < $2 "
                "GROUP BY host_id ORDER BY max_score DESC, host_id ASC LIMIT $3",
                start, end, limit,
            )
        return [(r["host_id"], float(r["max_score"])) for r in rows]

    # --- reports --------------------------------------------------------

    async def insert_report(
        self,
        *,
        id: UUID,
        name: str,
        range_start: datetime,
        range_end: datetime,
        generated_at: datetime,
        generated_by: str,
        pdf_path: str,
        size_bytes: int,
        approvals_count: int,
        scores_count: int,
    ) -> None:
        assert self._pool is not None
        _reject_naive(range_start, "range_start")
        _reject_naive(range_end, "range_end")
        _reject_naive(generated_at, "generated_at")
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO reports(
                    id, name, range_start, range_end, generated_at,
                    generated_by, pdf_path, size_bytes, approvals_count, scores_count
                ) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                """,
                id, name, range_start, range_end, generated_at,
                generated_by, pdf_path, size_bytes, approvals_count, scores_count,
            )

    async def list_reports(self, *, limit: int, offset: int) -> tuple[list[ReportRow], int]:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM reports ORDER BY generated_at DESC LIMIT $1 OFFSET $2",
                limit, offset,
            )
            total = await conn.fetchval("SELECT COUNT(*) FROM reports")
        return [_row_to_report(r) for r in rows], int(total)

    async def get_report(self, id: UUID) -> ReportRow | None:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM reports WHERE id = $1", id)
        return _row_to_report(row) if row else None

    async def delete_report(self, id: UUID) -> bool:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT pdf_path FROM reports WHERE id = $1", id)
            if row is None:
                return False
            pdf_path = row["pdf_path"]
            await conn.execute("DELETE FROM reports WHERE id = $1", id)
        try:
            os.unlink(pdf_path)
        except FileNotFoundError:
            pass   # idempotent — file already gone is fine
        return True


def _row_to_report(record) -> ReportRow:
    return ReportRow(
        id=record["id"],
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
