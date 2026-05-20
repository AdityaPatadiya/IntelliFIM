from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from jose import jwt

from orchestrator.auth import AuthError, Principal, decode_token


_T0 = datetime(2026, 5, 20, 12, 0, 0, tzinfo=timezone.utc)
_SECRET = "test-secret"


def _make_token(*, role: str = "admin", exp_offset_seconds: int = 3600,
                drop_claim: str | None = None, secret: str = _SECRET) -> str:
    claims = {
        "sub": str(uuid4()),
        "username": "alice",
        "email": "alice@example.com",
        "role": role,
        "iat": int(_T0.timestamp()),
        "exp": int((_T0 + timedelta(seconds=exp_offset_seconds)).timestamp()),
    }
    if drop_claim:
        claims.pop(drop_claim, None)
    return jwt.encode(claims, secret, algorithm="HS256")


def test_decode_token_happy_returns_principal():
    token = _make_token(role="analyst")
    principal = decode_token(token, _SECRET, now=_T0)
    assert isinstance(principal, Principal)
    assert principal.username == "alice"
    assert principal.role == "analyst"


def test_decode_token_invalid_signature_raises():
    token = _make_token(secret="wrong-secret")
    with pytest.raises(AuthError) as exc_info:
        decode_token(token, _SECRET, now=_T0)
    assert exc_info.value.status == 401


def test_decode_token_expired_raises():
    token = _make_token(exp_offset_seconds=60)
    with pytest.raises(AuthError) as exc_info:
        # 2 hours after issuance
        decode_token(token, _SECRET, now=_T0 + timedelta(hours=2))
    assert exc_info.value.status == 401
    assert "expired" in exc_info.value.message.lower()
