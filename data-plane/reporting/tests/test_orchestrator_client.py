"""Orchestrator client tests — uses respx to mock /approvals responses."""
from __future__ import annotations

import httpx
import pytest
import respx

from reporting.orchestrator_client import (
    OrchestratorClient,
    OrchestratorError,
)


@pytest.fixture
async def client():
    c = OrchestratorClient(base_url="http://orch:8200")
    yield c
    await c.aclose()


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_list_approvals_happy_path(respx_mock, client):
    respx_mock.get("http://orch:8200/approvals").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "host_id": "001", "priority": "HIGH", "score": 42.0,
                    "last_reason": "r", "state": "PENDING",
                    "created_at": "2030-01-01T00:00:00+00:00",
                    "decided_at": None, "executed_at": None,
                    "decided_by": None, "error_message": None,
                },
            ],
        )
    )
    rows = await client.list_approvals(jwt="ey.fake.token")
    assert len(rows) == 1
    assert rows[0]["host_id"] == "001"


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_list_approvals_forwards_bearer_header(respx_mock, client):
    route = respx_mock.get("http://orch:8200/approvals").mock(
        return_value=httpx.Response(200, json=[])
    )
    await client.list_approvals(jwt="abc.def.ghi")
    sent = route.calls.last.request
    assert sent.headers["authorization"] == "Bearer abc.def.ghi"


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_list_approvals_raises_on_5xx(respx_mock, client):
    respx_mock.get("http://orch:8200/approvals").mock(
        return_value=httpx.Response(503, json={"error": "down"})
    )
    with pytest.raises(OrchestratorError) as exc:
        await client.list_approvals(jwt="t")
    assert exc.value.status == 503
