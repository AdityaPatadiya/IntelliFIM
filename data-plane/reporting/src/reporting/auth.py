"""JWT auth helpers for the reporting service.

Conceptually identical to orchestrator/auth.py but exposes a FastAPI
`Depends` style entry point (the orchestrator uses an aiohttp middleware).
The HS256 secret + claim shape match auth-backend so a single JWT works
across all three services.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import cast
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from reporting.models import Principal, Role


REQUIRED_CLAIMS = ("sub", "username", "role", "exp")


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def decode_token(
    token: str, secret: str, *, now: Callable[[], datetime] = _default_now
) -> Principal:
    """Decode + validate an HS256 JWT, returning a Principal.

    Raises HTTPException(401) on any failure: bad signature, missing claims,
    expired, malformed role.
    """
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"], options={"verify_exp": False})
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"invalid token: {e}") from e

    for claim in REQUIRED_CLAIMS:
        if claim not in payload:
            raise HTTPException(status_code=401, detail=f"missing claim: {claim}")

    exp = int(payload["exp"])
    if exp <= int(now().timestamp()):
        raise HTTPException(status_code=401, detail="token expired")

    role = payload["role"]
    if role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=401, detail=f"unknown role: {role}")

    try:
        user_id = UUID(payload["sub"])
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=401, detail=f"bad subject: {e}") from e

    return Principal(
        user_id=user_id,
        username=str(payload["username"]),
        role=cast(Role, role),
    )


bearer_scheme = HTTPBearer(auto_error=False)


def make_get_current_principal(
    jwt_secret: str, *, now: Callable[[], datetime] = _default_now
) -> Callable[..., Principal]:
    """Factory that returns a FastAPI dependency closing over the secret+clock."""

    async def _dep(
        creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> Principal:
        if creds is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing authorization header",
            )
        return decode_token(creds.credentials, jwt_secret, now=now)

    return _dep


def require_roles(*roles: Role) -> Callable[[Principal], Principal]:
    """Factory: returns a dep that 403s unless principal.role is in `roles`."""

    def _dep(principal: Principal) -> Principal:
        if principal.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role {principal.role!r} not permitted",
            )
        return principal

    return _dep
