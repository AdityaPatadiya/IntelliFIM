"""JWT validation + RBAC middleware for the orchestrator API.

Shared HS256 secret with auth-backend. Mounted via build_api(jwt_secret=...).
Returns uniform {"error": "..."} JSON on 401 and 403.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable
from uuid import UUID

from aiohttp import web
from jose import JWTError, jwt

log = logging.getLogger(__name__)


_ALGO = "HS256"
_REQUIRED_CLAIMS = ("sub", "username", "role", "exp")
_ROLES_THAT_CAN_DECIDE = {"admin", "analyst"}


class AuthError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class Principal:
    user_id: UUID
    username: str
    role: str


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def decode_token(
    token: str,
    secret: str,
    *,
    now: datetime | None = None,
) -> Principal:
    try:
        claims = jwt.decode(
            token, secret, algorithms=[_ALGO],
            options={"verify_exp": False},  # we check exp below with injected `now`
        )
    except JWTError as exc:
        raise AuthError(401, f"invalid token: {exc}") from exc
    for required in _REQUIRED_CLAIMS:
        if required not in claims:
            raise AuthError(401, f"token missing claim: {required}")
    effective_now = now or _default_now()
    if int(effective_now.timestamp()) >= int(claims["exp"]):
        raise AuthError(401, "token has expired")
    try:
        user_id = UUID(claims["sub"])
    except (ValueError, TypeError) as exc:
        raise AuthError(401, f"sub claim not a UUID: {exc}") from exc
    return Principal(
        user_id=user_id,
        username=str(claims["username"]),
        role=str(claims["role"]),
    )


def _is_decide_route(request: web.Request) -> bool:
    """True for POST /approvals/{id}/{approve|reject}."""
    if request.method != "POST":
        return False
    parts = request.path.rstrip("/").split("/")
    return (
        len(parts) == 4
        and parts[1] == "approvals"
        and parts[3] in ("approve", "reject")
    )


def make_auth_middleware(
    secret: str,
    *,
    now: Callable[[], datetime] = _default_now,
):
    @web.middleware
    async def auth_middleware(
        request: web.Request,
        handler: Callable[[web.Request], Awaitable[web.Response]],
    ) -> web.Response:
        # /healthz, /metrics and CORS preflight (OPTIONS) are exempt — browsers
        # send OPTIONS without Authorization, so requiring Bearer here would
        # block every cross-origin call from the admin-console. /metrics is
        # scraped by Prometheus inside the bus network — no token (v1 spec §8).
        if request.path in ("/healthz", "/metrics") or request.method == "OPTIONS":
            return await handler(request)
        # Extract Bearer token
        authz = request.headers.get("Authorization", "")
        if not authz.startswith("Bearer "):
            return web.json_response({"error": "unauthorized"}, status=401)
        token = authz[len("Bearer "):]
        try:
            principal = decode_token(token, secret, now=now())
        except AuthError as exc:
            return web.json_response({"error": exc.message}, status=exc.status)
        # Role guard on decide routes
        if _is_decide_route(request) and principal.role not in _ROLES_THAT_CAN_DECIDE:
            return web.json_response(
                {
                    "error": "forbidden",
                    "required_role": "admin|analyst",
                    "actual_role": principal.role,
                },
                status=403,
            )
        request["principal"] = principal
        return await handler(request)

    return auth_middleware
