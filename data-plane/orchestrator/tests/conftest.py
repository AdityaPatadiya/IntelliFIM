# data-plane/orchestrator/tests/conftest.py
"""Pytest fixtures for the response-orchestrator.

Uses testcontainers-python to spin up a Postgres 16 container once per
session, then hands out a fresh database per test via two fixtures:

  * `pg_url`  — bare asyncpg-compatible URL pointing at a fresh database.
                Use when a test needs to construct an ApprovalStore that
                creates its own pool on a specific event loop.
  * `pg_pool` — pre-made asyncpg pool against the same fresh database.
                Use for tests that drive the store directly from async
                test bodies (aiohttp's TestClient runs on the same loop
                as the test, so injecting a pre-made pool is fine).
"""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from uuid import uuid4

import asyncpg
import pytest
import pytest_asyncio
from testcontainers.postgres import PostgresContainer

from intellifim_schemas import ThreatScoreUpdate


@pytest.fixture(scope="session")
def pg_container():
    """Spin up a Postgres container once per test session."""
    with PostgresContainer("postgres:16-alpine") as pg:
        yield pg


def _root_url(pg_container) -> str:
    """Extract a bare asyncpg-compatible URL from the testcontainers container."""
    raw = pg_container.get_connection_url(driver=None)
    return (
        raw.replace("postgresql+psycopg2://", "postgresql://")
           .replace("postgresql+asyncpg://", "postgresql://")
    )


@pytest_asyncio.fixture
async def pg_url(pg_container):
    """Per-test asyncpg URL against a freshly-created database."""
    db_name = f"test_{_uuid.uuid4().hex[:12]}"
    root_url = _root_url(pg_container)

    root_conn = await asyncpg.connect(root_url)
    try:
        await root_conn.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        await root_conn.close()

    yield root_url.rsplit("/", 1)[0] + f"/{db_name}"


@pytest_asyncio.fixture
async def pg_pool(pg_url):
    """Per-test asyncpg pool against a freshly-created database."""
    pool = await asyncpg.create_pool(pg_url, min_size=1, max_size=4)
    try:
        yield pool
    finally:
        await pool.close()


@pytest.fixture
def make_threat_score_update():
    """Factory for ThreatScoreUpdate instances. Defaults to host-001, score=60,
    priority=low (per default thresholds 30/70)."""

    def _make(
        *,
        host_id: str = "001",
        score: float = 60.0,
        last_score_delta: int = 10,
        last_reason: str = "moderate anomaly",
        window_seconds: int = 300,
        contributions_in_window: int = 1,
    ) -> ThreatScoreUpdate:
        return ThreatScoreUpdate(
            update_id=uuid4(),
            computed_at=datetime.now(tz=timezone.utc),
            host_id=host_id,
            score=score,
            window_seconds=window_seconds,
            contributions_in_window=contributions_in_window,
            last_event_id=uuid4(),
            last_score_delta=last_score_delta,
            last_reason=last_reason,
        )

    return _make
