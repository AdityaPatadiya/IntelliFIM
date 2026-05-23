"""Prometheus metrics tests for auth-backend."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from auth_backend.api import build_app
from auth_backend.metrics import SERVICE_LABEL
from auth_backend.store import UsersStore


_T0 = datetime(2026, 5, 20, 12, 0, 0, tzinfo=timezone.utc)
_SECRET = "test-secret"


async def _store_for(path: str) -> UsersStore:
    store = UsersStore(path)
    await store.init_schema()
    return store


async def _client_for(tmp_db_path):
    store = await _store_for(tmp_db_path)
    app = build_app(
        store=store, jwt_secret=_SECRET, jwt_ttl_seconds=3600,
        cors_origins=["http://localhost:5173"], now=lambda: _T0,
    )
    return TestClient(app), store


def _counter_value() -> float:
    val = REGISTRY.get_sample_value(
        "intellifim_messages_processed_total",
        {"service": SERVICE_LABEL},
    )
    return val if val is not None else 0.0


async def test_metrics_endpoint_returns_prometheus_format(tmp_db_path):
    """GET /metrics returns 200 with the standard prometheus content type."""
    client, store = await _client_for(tmp_db_path)
    try:
        with client as c:
            r = c.get("/metrics")
            assert r.status_code == 200
            assert "text/plain" in r.headers["content-type"]
            assert "http_requests_total" in r.text
            assert "intellifim_messages_processed_total" in r.text
    finally:
        await store.aclose()


async def test_login_increments_messages_processed_counter(tmp_db_path):
    """After a successful login, the messages counter increments by 1."""
    client, store = await _client_for(tmp_db_path)
    try:
        # Seed a user via the store directly
        await store.create_user(
            username="alice", email="alice@x.io",
            password="s3cr3t!", role="admin", now=_T0,
        )
        before = _counter_value()
        with client as c:
            r = c.post("/auth/login", json={"email": "alice@x.io", "password": "s3cr3t!"})
            assert r.status_code == 200, r.text
        after = _counter_value()
        assert after - before == 1.0
    finally:
        await store.aclose()
