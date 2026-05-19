from datetime import datetime, timedelta, timezone
from uuid import uuid4

import fakeredis.aioredis

from policy.redis_store import RedisScoreStore


_T0 = datetime(2026, 5, 18, 12, 0, 0, tzinfo=timezone.utc)


async def _make_store_with_fake_redis():
    """Construct a RedisScoreStore backed by an in-process fakeredis client."""
    store = RedisScoreStore("redis://localhost:6379/0")
    # Replace the real client with a fakeredis client BEFORE any use.
    await store.aclose()  # close the real client we'll never use
    store._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return store


async def test_append_contribution_persists_in_zset():
    store = await _make_store_with_fake_redis()
    try:
        ok = await store.append_contribution(
            host_id="host-001", ts=_T0, delta=10, event_id=uuid4()
        )
        assert ok is True
        # Verify via the fake client directly
        count = await store._client.zcard("threat_score:host:host-001")
        assert count == 1
    finally:
        await store.aclose()


async def test_current_score_sums_in_window_deltas():
    store = await _make_store_with_fake_redis()
    try:
        await store.append_contribution(host_id="host-001", ts=_T0, delta=10, event_id=uuid4())
        await store.append_contribution(host_id="host-001", ts=_T0 + timedelta(seconds=30), delta=5, event_id=uuid4())
        score, count = await store.current_score(
            host_id="host-001", window_seconds=300, now=_T0 + timedelta(seconds=60),
        )
        assert score == 15.0
        assert count == 2
    finally:
        await store.aclose()


async def test_current_score_excludes_expired_contributions():
    store = await _make_store_with_fake_redis()
    try:
        # Old contribution outside 60s window
        await store.append_contribution(host_id="host-001", ts=_T0, delta=10, event_id=uuid4())
        # Fresh contribution inside 60s window
        await store.append_contribution(
            host_id="host-001", ts=_T0 + timedelta(seconds=80), delta=5, event_id=uuid4(),
        )
        score, count = await store.current_score(
            host_id="host-001", window_seconds=60, now=_T0 + timedelta(seconds=100),
        )
        assert score == 5.0
        assert count == 1
    finally:
        await store.aclose()


async def test_multi_host_isolation():
    store = await _make_store_with_fake_redis()
    try:
        await store.append_contribution(host_id="host-A", ts=_T0, delta=10, event_id=uuid4())
        await store.append_contribution(host_id="host-B", ts=_T0, delta=25, event_id=uuid4())
        score_a, _ = await store.current_score(host_id="host-A", window_seconds=300, now=_T0)
        score_b, _ = await store.current_score(host_id="host-B", window_seconds=300, now=_T0)
        assert score_a == 10.0
        assert score_b == 25.0
    finally:
        await store.aclose()


async def test_current_score_returns_zero_for_unknown_host():
    store = await _make_store_with_fake_redis()
    try:
        score, count = await store.current_score(
            host_id="host-NOPE", window_seconds=300, now=_T0,
        )
        assert score == 0.0
        assert count == 0
    finally:
        await store.aclose()


async def test_append_failure_returns_false(monkeypatch):
    store = await _make_store_with_fake_redis()
    try:
        # Force ZADD to raise by replacing the method
        from redis.exceptions import RedisError

        async def broken_zadd(*args, **kwargs):
            raise RedisError("simulated")

        monkeypatch.setattr(store._client, "zadd", broken_zadd)
        ok = await store.append_contribution(
            host_id="host-X", ts=_T0, delta=10, event_id=uuid4(),
        )
        assert ok is False
    finally:
        await store.aclose()
