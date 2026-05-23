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
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from orchestrator.store import ApprovalRow, ApprovalStore
from orchestrator.wazuh_client import WazuhClient, WazuhDispatchError
from orchestrator.auth import make_auth_middleware
from orchestrator.metrics import (
    SERVICE_LABEL,
    errors_total,
    messages_processed_total,
    processing_seconds,
)

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


def _make_cors_middleware(allowed_origins: list[str]):
    """Tiny CORS middleware. Browsers calling cross-origin from the admin
    console send a preflight OPTIONS; we short-circuit it with the right
    Access-Control-* headers. For non-OPTIONS responses we tack the
    Access-Control-Allow-Origin header on.
    """
    allowed = set(allowed_origins)

    @web.middleware
    async def cors_middleware(request, handler):
        origin = request.headers.get("Origin", "")
        allow = origin if origin in allowed else ""
        if request.method == "OPTIONS":
            return web.Response(
                status=204,
                headers={
                    "Access-Control-Allow-Origin": allow,
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Authorization, Content-Type",
                    "Access-Control-Max-Age": "600",
                },
            )
        response = await handler(request)
        if allow:
            response.headers["Access-Control-Allow-Origin"] = allow
        return response

    return cors_middleware


def build_api(
    *,
    store: ApprovalStore,
    wazuh: WazuhClient,
    jwt_secret: str,
    cors_origins: list[str] | None = None,
    now: Callable[[], datetime] = _default_now,
) -> web.Application:
    # CORS runs BEFORE auth so OPTIONS preflights don't need a Bearer token.
    # Thread `now` into the auth middleware so tests with a mock clock see
    # consistent expiry checks across handlers AND the JWT validator.
    origins = cors_origins or ["http://localhost:5173", "http://127.0.0.1:5173"]
    app = web.Application(
        middlewares=[
            _make_cors_middleware(origins),
            make_auth_middleware(jwt_secret, now=now),
        ]
    )

    async def healthz(_request: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def metrics(_request: web.Request) -> web.Response:
        # CONTENT_TYPE_LATEST includes "; charset=utf-8" which aiohttp's
        # `content_type` arg refuses — pass it as a raw Content-Type header.
        return web.Response(
            body=generate_latest(),
            headers={"Content-Type": CONTENT_TYPE_LATEST},
        )

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
        with processing_seconds.labels(SERVICE_LABEL).time():
            try:
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
                # Flip PENDING -> APPROVED. decided_by = the authenticated user
                # (set on the request by auth_middleware after JWT validation).
                principal = request["principal"]
                approved_row = await store.transition(
                    id=uid, from_state="PENDING", to_state="APPROVED",
                    now=now(), decided_by=principal.username,
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
                    messages_processed_total.labels(SERVICE_LABEL).inc()
                    return web.json_response(_row_to_dict(failed))
                executed = await store.transition(
                    id=uid, from_state="APPROVED", to_state="EXECUTED",
                    now=now(), executed_at=now(),
                )
                if executed is None:
                    executed = await store.get(uid)
                messages_processed_total.labels(SERVICE_LABEL).inc()
                return web.json_response(_row_to_dict(executed))
            except web.HTTPException:
                raise  # 4xx — not an error we count separately
            except Exception as e:
                errors_total.labels(service=SERVICE_LABEL, kind=type(e).__name__).inc()
                raise

    async def reject(request: web.Request) -> web.Response:
        with processing_seconds.labels(SERVICE_LABEL).time():
            try:
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
                principal = request["principal"]
                rejected = await store.transition(
                    id=uid, from_state="PENDING", to_state="REJECTED",
                    now=now(), decided_by=principal.username,
                )
                if rejected is None:
                    fresh = await store.get(uid)
                    return _json_error(
                        "not in PENDING state", status=409,
                        current_state=fresh.state if fresh else "UNKNOWN",
                    )
                messages_processed_total.labels(SERVICE_LABEL).inc()
                return web.json_response(_row_to_dict(rejected))
            except web.HTTPException:
                raise  # 4xx — not an error we count separately
            except Exception as e:
                errors_total.labels(service=SERVICE_LABEL, kind=type(e).__name__).inc()
                raise

    app.router.add_get("/healthz", healthz)
    app.router.add_get("/metrics", metrics)
    app.router.add_get("/approvals", list_approvals)
    app.router.add_get("/approvals/{id}", get_approval)
    app.router.add_post("/approvals/{id}/approve", approve)
    app.router.add_post("/approvals/{id}/reject", reject)
    return app
