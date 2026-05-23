"""Shared pytest fixtures.

`_T0` is a fixed test clock far enough in the future that real wall-clock
never catches up to it during a test run — the lesson from sub-project #6's
Task 8 (JWT expiry checks were going stale overnight against a 2026-fixed clock).

Postgres fixtures follow the same two-fixture pattern auth-backend uses:

  * `pg_url`  — bare asyncpg-compatible URL pointing at a fresh database.
                Tests that drive FastAPI through `httpx.AsyncClient` should
                use this so `ReportingStore` creates its pool on the *same*
                event loop the AsyncClient ends up using (avoids the
                "another operation is in progress" race between loops).
  * `pg_pool` — pre-made asyncpg pool against the same fresh database.
                Convenient for tests that call ReportingStore methods
                directly from async test bodies.
"""
from __future__ import annotations

import os
import uuid as _uuid
from collections.abc import Callable
from datetime import datetime, timezone

import asyncpg
import pytest
import pytest_asyncio
from testcontainers.postgres import PostgresContainer

_T0 = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def fixed_now() -> Callable[[], datetime]:
    """Returns a `now` callable that always returns `_T0`."""
    return lambda: _T0


@pytest.fixture
def jwt_secret() -> str:
    return "test-jwt-secret-not-for-prod-use"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Each test starts with a clean reporting-relevant env."""
    _exact = {"DATABASE_URL", "REPORTS_DIR", "BIND_HOST", "PORT"}
    _prefixes = ("KAFKA_", "JWT_", "ORCHESTRATOR_", "CORS_")
    for k in list(os.environ):
        if k in _exact or k.startswith(_prefixes):
            monkeypatch.delenv(k, raising=False)


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
async def pg_url(pg_container) -> str:
    """Per-test asyncpg URL against a freshly-created database.

    Use this fixture for FastAPI-layer tests that need the store created
    on the test's event loop (avoids TestClient ↔ asyncpg incompatibility;
    use `httpx.AsyncClient(transport=ASGITransport(app=app))` in the test).
    """
    db_name = f"test_{_uuid.uuid4().hex[:12]}"
    root_url = _root_url(pg_container)

    root_conn = await asyncpg.connect(root_url)
    try:
        await root_conn.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        await root_conn.close()

    return root_url.rsplit("/", 1)[0] + f"/{db_name}"


@pytest_asyncio.fixture
async def pg_pool(pg_url):
    """Pre-made pool for direct-store unit tests."""
    pool = await asyncpg.create_pool(pg_url, min_size=1, max_size=4)
    try:
        yield pool
    finally:
        await pool.close()
