from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from auth_backend.jwt_helper import JwtError, decode, encode


_T0 = datetime(2026, 5, 20, 12, 0, 0, tzinfo=timezone.utc)


def test_encode_produces_three_segment_string():
    token = encode(
        user_id=uuid4(), username="alice", email="a@b", role="admin",
        secret="s", ttl_seconds=3600, now=_T0,
    )
    assert token.count(".") == 2


def test_decode_round_trips_claims():
    uid = uuid4()
    token = encode(
        user_id=uid, username="alice", email="a@b", role="admin",
        secret="s", ttl_seconds=3600, now=_T0,
    )
    claims = decode(token, secret="s", now=_T0)
    assert claims["sub"] == str(uid)
    assert claims["username"] == "alice"
    assert claims["email"] == "a@b"
    assert claims["role"] == "admin"


def test_decode_expired_token_raises():
    token = encode(
        user_id=uuid4(), username="x", email="y@z", role="viewer",
        secret="s", ttl_seconds=60, now=_T0,
    )
    # 2 hours later → expired
    with pytest.raises(JwtError, match="expired"):
        decode(token, secret="s", now=_T0 + timedelta(hours=2))
