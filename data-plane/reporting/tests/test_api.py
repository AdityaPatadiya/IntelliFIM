"""FastAPI app factory tests using TestClient + respx for orchestrator mock."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from jose import jwt

from reporting.api import build_app
from reporting.orchestrator_client import OrchestratorClient
from reporting.store import ReportingStore


_T0 = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_SECRET = "test-jwt-secret"


def _make_token(*, username: str, role: str, exp_offset_s: int = 3600) -> str:
    iat = int(_T0.timestamp())
    exp = iat + exp_offset_s
    payload = {
        "sub": str(UUID("00000000-0000-0000-0000-000000000010")),
        "username": username, "email": f"{username}@x.io",
        "role": role, "iat": iat, "exp": exp,
    }
    return jwt.encode(payload, _SECRET, algorithm="HS256")


@pytest.fixture
async def deps(tmp_path):
    store = ReportingStore(
        db_path=str(tmp_path / "reporting.db"),
        reports_dir=str(tmp_path / "reports"),
    )
    await store.init_schema()
    orch = OrchestratorClient(base_url="http://orch:8200")
    yield store, orch
    await orch.aclose()
    await store.aclose()


def _client(store, orch) -> TestClient:
    app = build_app(
        store=store, orchestrator=orch,
        jwt_secret=_SECRET, jwt_ttl_seconds=3600,
        cors_origins=("http://localhost:5173",),
        now=lambda: _T0,
    )
    return TestClient(app)


@pytest.mark.asyncio
async def test_healthz_returns_ok(deps):
    store, orch = deps
    with _client(store, orch) as c:
        r = c.get("/healthz")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_missing_jwt_returns_401(deps):
    store, orch = deps
    with _client(store, orch) as c:
        r = c.get("/reports")
        assert r.status_code == 401
        assert "error" in r.json()


@pytest.mark.asyncio
async def test_viewer_cannot_generate(deps):
    store, orch = deps
    token = _make_token(username="vix", role="viewer")
    with _client(store, orch) as c:
        r = c.post(
            "/reports/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "summary",
                "range_start": "2030-01-01T00:00:00+00:00",
                "range_end": "2030-01-02T00:00:00+00:00",
            },
        )
        assert r.status_code == 403
        assert "error" in r.json()


@pytest.mark.asyncio
async def test_range_too_long_returns_400(deps):
    store, orch = deps
    token = _make_token(username="alice", role="admin")
    with _client(store, orch) as c:
        r = c.post(
            "/reports/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "summary",
                "range_start": "2030-01-01T00:00:00+00:00",
                "range_end": "2030-06-01T00:00:00+00:00",   # > 90 days
            },
        )
        assert r.status_code == 422 or r.status_code == 400
        assert "error" in r.json()


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_generate_happy_path(respx_mock, deps, tmp_path):
    store, orch = deps
    # Insert a couple of scores in range
    await store.insert_score(host_id="001", score=42.0, reason="r", ts=_T0)
    await store.insert_score(host_id="002", score=99.0, reason="r", ts=_T0)
    respx_mock.get("http://orch:8200/approvals").mock(
        return_value=httpx.Response(200, json=[
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "host_id": "001", "priority": "HIGH", "score": 80.0,
                "last_reason": "r", "state": "EXECUTED",
                "created_at": "2030-01-01T01:00:00+00:00",
                "decided_at": "2030-01-01T01:05:00+00:00",
                "executed_at": "2030-01-01T01:05:30+00:00",
                "decided_by": "alice", "error_message": None,
            },
        ])
    )
    token = _make_token(username="alice", role="admin")
    with _client(store, orch) as c:
        r = c.post(
            "/reports/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "daily",
                "range_start": "2030-01-01T00:00:00+00:00",
                "range_end": "2030-01-02T00:00:00+00:00",
            },
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["name"] == "daily"
        assert body["generated_by"] == "alice"
        assert body["size_bytes"] > 0
        assert body["approvals_count"] == 1
        assert body["scores_count"] == 2

        # Download endpoint returns PDF bytes
        rid = body["id"]
        r2 = c.get(
            f"/reports/{rid}/download",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r2.status_code == 200
        assert r2.headers["content-type"] == "application/pdf"
        assert r2.content.startswith(b"%PDF-")


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_orchestrator_unreachable_returns_502(respx_mock, deps):
    store, orch = deps
    respx_mock.get("http://orch:8200/approvals").mock(
        side_effect=httpx.ConnectError("nope")
    )
    token = _make_token(username="alice", role="admin")
    with _client(store, orch) as c:
        r = c.post(
            "/reports/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "x",
                "range_start": "2030-01-01T00:00:00+00:00",
                "range_end": "2030-01-02T00:00:00+00:00",
            },
        )
        assert r.status_code == 502
        assert "error" in r.json()


@pytest.mark.asyncio
async def test_delete_admin_only(deps, tmp_path):
    store, orch = deps
    rid = uuid4()
    pdf_path = f"{tmp_path / 'reports'}/2030-01-01-{rid}.pdf"
    import os
    os.makedirs(str(tmp_path / "reports"), exist_ok=True)
    with open(pdf_path, "wb") as f:
        f.write(b"%PDF-1.4\n")
    await store.insert_report(
        id=rid, name="x", range_start_iso="2030-01-01T00:00:00+00:00",
        range_end_iso="2030-01-02T00:00:00+00:00",
        generated_at_iso="2030-01-01T00:00:00+00:00", generated_by="alice",
        pdf_path=pdf_path, size_bytes=9, approvals_count=0, scores_count=0,
    )

    analyst_token = _make_token(username="ann", role="analyst")
    admin_token = _make_token(username="alice", role="admin")
    with _client(store, orch) as c:
        r = c.delete(f"/reports/{rid}",
                     headers={"Authorization": f"Bearer {analyst_token}"})
        assert r.status_code == 403

        r = c.delete(f"/reports/{rid}",
                     headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200

        r = c.delete(f"/reports/{rid}",
                     headers={"Authorization": f"Bearer {admin_token}"})
        # second delete returns 404 (idempotent: it's gone)
        assert r.status_code == 404
