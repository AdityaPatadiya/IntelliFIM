import os
import tempfile
from datetime import datetime, timezone
from uuid import uuid4

from aiohttp.test_utils import TestClient, TestServer

from orchestrator.api import build_api
from orchestrator.store import ApprovalStore
from orchestrator.wazuh_client import WazuhDispatchError


_T0 = datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc)


class FakeWazuh:
    def __init__(self, raise_exc: Exception | None = None):
        self._raise = raise_exc
        self.calls: list[tuple[str, str, list[str]]] = []
    async def run_active_response(self, *, agent_id: str, command: str, arguments: list[str]) -> None:
        self.calls.append((agent_id, command, arguments))
        if self._raise is not None:
            raise self._raise


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
    app = build_api(store=store, wazuh=wazuh, now=lambda: _T0)
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    return client


async def test_healthz():
    store, path = await _make_store()
    client = await _client(store, FakeWazuh())
    try:
        resp = await client.get("/healthz")
        assert resp.status == 200
        assert (await resp.json()) == {"status": "ok"}
    finally:
        await client.close()
        await _cleanup(store, path)


async def test_list_approvals_defaults_to_pending():
    store, path = await _make_store()
    uid = uuid4()
    await store.insert_if_no_pending(
        id=uid, host_id="001", priority="low",
        score=42.0, last_reason="weak", now=_T0,
    )
    client = await _client(store, FakeWazuh())
    try:
        resp = await client.get("/approvals")
        assert resp.status == 200
        body = await resp.json()
        assert len(body["approvals"]) == 1
        assert body["approvals"][0]["id"] == str(uid)
        assert body["approvals"][0]["state"] == "PENDING"
    finally:
        await client.close()
        await _cleanup(store, path)


async def test_get_approval_missing_returns_404():
    store, path = await _make_store()
    client = await _client(store, FakeWazuh())
    try:
        resp = await client.get(f"/approvals/{uuid4()}")
        assert resp.status == 404
        assert (await resp.json()) == {"error": "not found"}
    finally:
        await client.close()
        await _cleanup(store, path)


async def test_approve_happy_path_returns_executed():
    store, path = await _make_store()
    uid = uuid4()
    await store.insert_if_no_pending(
        id=uid, host_id="001", priority="low",
        score=42.0, last_reason="weak", now=_T0,
    )
    wazuh = FakeWazuh()
    client = await _client(store, wazuh)
    try:
        resp = await client.post(f"/approvals/{uid}/approve")
        assert resp.status == 200
        body = await resp.json()
        assert body["state"] == "EXECUTED"
        assert body["id"] == str(uid)
        # Wazuh was called exactly once with the right args
        assert wazuh.calls == [("001", "!quarantine0", ["-", f'{{"update_id":"{uid}"}}'])]
    finally:
        await client.close()
        await _cleanup(store, path)


async def test_approve_already_decided_returns_409():
    store, path = await _make_store()
    uid = uuid4()
    await store.insert_if_no_pending(
        id=uid, host_id="001", priority="low",
        score=42.0, last_reason="weak", now=_T0,
    )
    # Pre-flip to REJECTED
    await store.transition(
        id=uid, from_state="PENDING", to_state="REJECTED",
        now=_T0, decided_by="curl",
    )
    client = await _client(store, FakeWazuh())
    try:
        resp = await client.post(f"/approvals/{uid}/approve")
        assert resp.status == 409
        body = await resp.json()
        assert body["current_state"] == "REJECTED"
    finally:
        await client.close()
        await _cleanup(store, path)


async def test_reject_flips_state():
    store, path = await _make_store()
    uid = uuid4()
    await store.insert_if_no_pending(
        id=uid, host_id="001", priority="low",
        score=42.0, last_reason="weak", now=_T0,
    )
    client = await _client(store, FakeWazuh())
    try:
        resp = await client.post(f"/approvals/{uid}/reject")
        assert resp.status == 200
        body = await resp.json()
        assert body["state"] == "REJECTED"
        assert body["decided_by"] == "curl"
    finally:
        await client.close()
        await _cleanup(store, path)


async def test_approve_dispatcher_fails_returns_failed_state():
    store, path = await _make_store()
    uid = uuid4()
    await store.insert_if_no_pending(
        id=uid, host_id="001", priority="low",
        score=42.0, last_reason="weak", now=_T0,
    )
    wazuh = FakeWazuh(raise_exc=WazuhDispatchError("simulated outage"))
    client = await _client(store, wazuh)
    try:
        resp = await client.post(f"/approvals/{uid}/approve")
        assert resp.status == 200
        body = await resp.json()
        assert body["state"] == "FAILED"
        assert "simulated outage" in body["error_message"]
    finally:
        await client.close()
        await _cleanup(store, path)
