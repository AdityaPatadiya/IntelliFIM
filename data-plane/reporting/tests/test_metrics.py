"""Prometheus metrics tests for reporting."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import httpx
import pytest
import respx
from httpx import ASGITransport
from jose import jwt
from prometheus_client import REGISTRY

from reporting.api import build_app
from reporting.metrics import SERVICE_LABEL
from reporting.orchestrator_client import OrchestratorClient
from reporting.store import ReportingStore


_T0 = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_SECRET = "test-jwt-secret"


def _counter_value() -> float:
    val = REGISTRY.get_sample_value(
        "intellifim_messages_processed_total",
        {"service": SERVICE_LABEL},
    )
    return val if val is not None else 0.0


def _make_token(*, username: str, role: str) -> str:
    iat = int(_T0.timestamp())
    payload = {
        "sub": str(UUID("00000000-0000-0000-0000-000000000010")),
        "username": username, "email": f"{username}@x.io",
        "role": role, "iat": iat, "exp": iat + 3600,
    }
    return jwt.encode(payload, _SECRET, algorithm="HS256")


def _async_client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_prometheus_format(pg_url, tmp_path):
    store = ReportingStore(
        database_url=pg_url,
        reports_dir=str(tmp_path / "reports"),
    )
    await store.init_schema()
    orch = OrchestratorClient(base_url="http://orch:8200")
    try:
        app = build_app(
            store=store, orchestrator=orch,
            jwt_secret=_SECRET, jwt_ttl_seconds=3600,
            cors_origins=("http://localhost:5173",),
            now=lambda: _T0,
        )
        async with _async_client(app) as c:
            r = await c.get("/metrics")
            assert r.status_code == 200
            assert "text/plain" in r.headers["content-type"]
            assert "intellifim_messages_processed_total" in r.text
    finally:
        await orch.aclose()
        await store.aclose()


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_generate_increments_messages_processed_counter(respx_mock, pg_url, tmp_path):
    store = ReportingStore(
        database_url=pg_url,
        reports_dir=str(tmp_path / "reports"),
    )
    await store.init_schema()
    orch = OrchestratorClient(base_url="http://orch:8200")
    respx_mock.get("http://orch:8200/approvals").mock(
        return_value=httpx.Response(200, json={"approvals": []})
    )
    try:
        app = build_app(
            store=store, orchestrator=orch,
            jwt_secret=_SECRET, jwt_ttl_seconds=3600,
            cors_origins=("http://localhost:5173",),
            now=lambda: _T0,
        )
        before = _counter_value()
        token = _make_token(username="alice", role="admin")
        async with _async_client(app) as c:
            r = await c.post(
                "/reports/generate",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "name": "metrics-smoke",
                    "range_start": "2030-01-01T00:00:00+00:00",
                    "range_end": "2030-01-02T00:00:00+00:00",
                },
            )
            assert r.status_code == 201, r.text
        after = _counter_value()
        assert after - before == 1.0
    finally:
        await orch.aclose()
        await store.aclose()
