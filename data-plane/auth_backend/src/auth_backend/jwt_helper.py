"""HS256 JWT encode/decode helpers for auth-backend.

Decode is also imported by response-orchestrator's auth middleware so the
two services agree byte-for-byte on the claim shape.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from jose import JWTError, jwt


class JwtError(Exception):
    """Raised on encode failure or any decode-time problem
    (invalid signature, expired, malformed, missing claim)."""


_ALGO = "HS256"


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def encode(
    *,
    user_id: UUID,
    username: str,
    email: str,
    role: str,
    secret: str,
    ttl_seconds: int,
    now: datetime | None = None,
) -> str:
    iat = (now or _utcnow())
    exp = iat + timedelta(seconds=ttl_seconds)
    claims = {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "role": role,
        "iat": int(iat.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(claims, secret, algorithm=_ALGO)


def decode(
    token: str,
    *,
    secret: str,
    now: datetime | None = None,
) -> dict:
    try:
        # We disable jose's built-in exp check so we can use the injected
        # `now` for testability; we re-check exp below ourselves.
        claims = jwt.decode(
            token, secret, algorithms=[_ALGO],
            options={"verify_exp": False},
        )
    except JWTError as exc:
        raise JwtError(f"invalid token: {exc}") from exc
    exp = claims.get("exp")
    if exp is None:
        raise JwtError("token missing required claim: exp")
    effective_now = now or _utcnow()
    if int(effective_now.timestamp()) >= int(exp):
        raise JwtError("token has expired")
    for required in ("sub", "username", "email", "role", "iat"):
        if required not in claims:
            raise JwtError(f"token missing required claim: {required}")
    return claims
