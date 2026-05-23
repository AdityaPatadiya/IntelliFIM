# data-plane/auth_backend/tests/conftest.py
"""Pytest fixtures for the auth-backend.

Uses testcontainers-python to spin up a Postgres 16 container once per
session, then hands out a fresh database per test via two fixtures:

  * `pg_url`  — bare asyncpg-compatible URL pointing at a fresh database.
                Tests that drive FastAPI through `TestClient` should use
                this so the UsersStore creates its pool on the *same*
                event loop the TestClient ends up using (avoids the
                "another operation is in progress" race between loops).
  * `pg_pool` — pre-made asyncpg pool against the same fresh database.
                Convenient for tests that call UsersStore methods
                directly from async test bodies.
"""
from __future__ import annotations

import uuid as _uuid

import asyncpg
import pytest
import pytest_asyncio
from testcontainers.postgres import PostgresContainer


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
