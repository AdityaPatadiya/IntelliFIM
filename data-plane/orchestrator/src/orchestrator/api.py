"""aiohttp REST API for approval list / approve / reject.

Synchronous approve path: flip PENDING -> APPROVED, dispatch to Wazuh,
flip APPROVED -> EXECUTED (or FAILED). Caller sees the terminal state in
the response (no polling).
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Callable
from uuid import UUID

from aiohttp import web

from orchestrator.store import ApprovalRow, ApprovalStore
from orchestrator.wazuh_client import WazuhClient, WazuhDispatchError

log = logging.getLogger(__name__)


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _row_to_dict(row: ApprovalRow) -> dict:
    d = asdict(row)
    d["id"] = str(row.id)
    return d


def _json_error(message: str, *, status: int, **extra) -> web.Response:
    payload = {"error": message, **extra}
    return web.json_response(payload, status=status)


def build_api(
    *,
    store: ApprovalStore,
    wazuh: WazuhClient,
    now: Callable[[], datetime] = _default_now,
) -> web.Application:
    app = web.Application()

    async def healthz(_request: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def list_approvals(request: web.Request) -> web.Response:
        state = request.query.get("state", "PENDING")
        rows = await store.list(state=state if state else None)
        return web.json_response({"approvals": [_row_to_dict(r) for r in rows]})

    async def get_approval(request: web.Request) -> web.Response:
        try:
            uid = UUID(request.match_info["id"])
        except ValueError:
            return _json_error("not found", status=404)
        row = await store.get(uid)
        if row is None:
            return _json_error("not found", status=404)
        return web.json_response(_row_to_dict(row))

    async def approve(request: web.Request) -> web.Response:
        try:
            uid = UUID(request.match_info["id"])
        except ValueError:
            return _json_error("not found", status=404)
        row = await store.get(uid)
        if row is None:
            return _json_error("not found", status=404)
        if row.state != "PENDING":
            return _json_error(
                "not in PENDING state", status=409, current_state=row.state,
            )
        # Flip PENDING -> APPROVED
        approved_row = await store.transition(
            id=uid, from_state="PENDING", to_state="APPROVED",
            now=now(), decided_by="curl",
        )
        if approved_row is None:
            # Raced into a non-PENDING state between get() and transition()
            fresh = await store.get(uid)
            return _json_error(
                "not in PENDING state", status=409,
                current_state=fresh.state if fresh else "UNKNOWN",
            )
        # Dispatch to Wazuh (compact json to match Wazuh AR contract / tests).
        # `!` prefix is required for custom AR commands per Wazuh 4.x API.
        arguments = ["-", json.dumps({"update_id": str(uid)}, separators=(",", ":"))]
        try:
            await wazuh.run_active_response(
                agent_id=row.host_id, command="!quarantine0", arguments=arguments,
            )
        except WazuhDispatchError as exc:
            failed = await store.transition(
                id=uid, from_state="APPROVED", to_state="FAILED",
                now=now(), error_message=str(exc),
            )
            # Defensive: if the row was racing-mutated out of APPROVED, fall
            # back to a fresh read so we return SOMETHING shaped like a row
            # rather than crashing in _row_to_dict(None).
            if failed is None:
                failed = await store.get(uid)
            return web.json_response(_row_to_dict(failed))
        executed = await store.transition(
            id=uid, from_state="APPROVED", to_state="EXECUTED",
            now=now(), executed_at=now(),
        )
        if executed is None:
            executed = await store.get(uid)
        return web.json_response(_row_to_dict(executed))

    async def reject(request: web.Request) -> web.Response:
        try:
            uid = UUID(request.match_info["id"])
        except ValueError:
            return _json_error("not found", status=404)
        row = await store.get(uid)
        if row is None:
            return _json_error("not found", status=404)
        if row.state != "PENDING":
            return _json_error(
                "not in PENDING state", status=409, current_state=row.state,
            )
        rejected = await store.transition(
            id=uid, from_state="PENDING", to_state="REJECTED",
            now=now(), decided_by="curl",
        )
        if rejected is None:
            fresh = await store.get(uid)
            return _json_error(
                "not in PENDING state", status=409,
                current_state=fresh.state if fresh else "UNKNOWN",
            )
        return web.json_response(_row_to_dict(rejected))

    app.router.add_get("/healthz", healthz)
    app.router.add_get("/approvals", list_approvals)
    app.router.add_get("/approvals/{id}", get_approval)
    app.router.add_post("/approvals/{id}/approve", approve)
    app.router.add_post("/approvals/{id}/reject", reject)
    return app
