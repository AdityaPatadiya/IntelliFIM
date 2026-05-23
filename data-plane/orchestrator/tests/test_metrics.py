"""Prometheus metrics tests for response-orchestrator."""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from aiohttp.test_utils import TestClient, TestServer
from jose import jwt as _jose_jwt
from prometheus_client import REGISTRY

from orchestrator.api import build_api
from orchestrator.metrics import SERVICE_LABEL
from orchestrator.store import ApprovalStore


_T0 = datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc)
_JWT_SECRET = "test-secret"


def _make_token(role: str = "admin", *, secret: str = _JWT_SECRET) -> str:
    iat = _T0
    exp = _T0 + timedelta(hours=1)
    return _jose_jwt.encode(
        {
            "sub": str(uuid4()),
            "username": "alice",
            "email": "a@b",
            "role": role,
            "iat": int(iat.timestamp()),
            "exp": int(exp.timestamp()),
        },
        secret,
        algorithm="HS256",
    )


def _auth_headers(role: str = "admin") -> dict[str, str]:
    return {"Authorization": f"Bearer {_make_token(role)}"}


class FakeWazuh:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, list[str]]] = []

    async def run_active_response(
        self, *, agent_id: str, command: str, arguments: list[str]
    ) -> None:
        self.calls.append((agent_id, command, arguments))


async def _make_store():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    store = ApprovalStore(path)
    await store.init_schema()
    return store, path


async def _cleanup(store, path):
    await store.aclose()
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


async def _client(store, wazuh):
    app = build_api(store=store, wazuh=wazuh, jwt_secret=_JWT_SECRET, now=lambda: _T0)
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    return client


def _counter_value() -> float:
    val = REGISTRY.get_sample_value(
        "intellifim_messages_processed_total",
        {"service": SERVICE_LABEL},
    )
    return val if val is not None else 0.0


async def test_metrics_endpoint_returns_prometheus_format():
    store, path = await _make_store()
    client = await _client(store, FakeWazuh())
    try:
        r = await client.get("/metrics")
        assert r.status == 200
        body = await r.text()
        assert "intellifim_messages_processed_total" in body
    finally:
        await client.close()
        await _cleanup(store, path)


async def test_approve_increments_messages_processed_counter():
    store, path = await _make_store()
    uid = uuid4()
    await store.insert_if_no_pending(
        id=uid, host_id="001", priority="low",
        score=42.0, last_reason="weak", now=_T0,
    )
    client = await _client(store, FakeWazuh())
    try:
        before = _counter_value()
        r = await client.post(
            f"/approvals/{uid}/approve", headers=_auth_headers(),
        )
        assert r.status == 200, await r.text()
        after = _counter_value()
        assert after - before == 1.0
    finally:
        await client.close()
        await _cleanup(store, path)
