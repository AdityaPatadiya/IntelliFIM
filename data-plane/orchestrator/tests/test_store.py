from datetime import datetime, timezone
from uuid import uuid4

from orchestrator.store import ApprovalRow, ApprovalStore


_T0 = datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc)
_T1 = datetime(2026, 5, 19, 12, 0, 5, tzinfo=timezone.utc)
_T2 = datetime(2026, 5, 19, 12, 0, 10, tzinfo=timezone.utc)


async def _make_store(pg_pool):
    """ApprovalStore backed by the per-test Postgres pool."""
    store = ApprovalStore(pool=pg_pool)
    await store.init_schema()
    return store


async def _cleanup(store):
    await store.aclose()


async def test_insert_if_no_pending_creates_row(pg_pool):
    store = await _make_store(pg_pool)
    try:
        uid = uuid4()
        inserted = await store.insert_if_no_pending(
            id=uid, host_id="001", priority="low",
            score=42.0, last_reason="weak", now=_T0,
        )
        assert inserted is True
        row = await store.get(uid)
        assert row is not None
        assert row.id == uid
        assert row.host_id == "001"
        assert row.priority == "low"
        assert row.score == 42.0
        assert row.last_reason == "weak"
        assert row.state == "PENDING"
        assert row.created_at == _T0.isoformat()
    finally:
        await _cleanup(store)


async def test_insert_if_no_pending_dedupes_on_duplicate_id(pg_pool):
    store = await _make_store(pg_pool)
    try:
        uid = uuid4()
        first = await store.insert_if_no_pending(
            id=uid, host_id="001", priority="low",
            score=42.0, last_reason="weak", now=_T0,
        )
        assert first is True
        # Same id → False, no second row, no exception
        second = await store.insert_if_no_pending(
            id=uid, host_id="001", priority="high",
            score=99.0, last_reason="strong", now=_T1,
        )
        assert second is False
        row = await store.get(uid)
        assert row.priority == "low"  # original row unchanged
        assert row.score == 42.0
    finally:
        await _cleanup(store)


async def test_insert_if_no_pending_enforces_per_host_singleton(pg_pool):
    store = await _make_store(pg_pool)
    try:
        first = await store.insert_if_no_pending(
            id=uuid4(), host_id="001", priority="low",
            score=42.0, last_reason="weak", now=_T0,
        )
        assert first is True
        # Different id, same host, host is still PENDING → False
        second = await store.insert_if_no_pending(
            id=uuid4(), host_id="001", priority="high",
            score=99.0, last_reason="strong", now=_T1,
        )
        assert second is False
        rows = await store.list(state="PENDING")
        assert len(rows) == 1
    finally:
        await _cleanup(store)


async def test_insert_after_terminal_state_creates_new_row(pg_pool):
    store = await _make_store(pg_pool)
    try:
        uid_a = uuid4()
        await store.insert_if_no_pending(
            id=uid_a, host_id="001", priority="low",
            score=42.0, last_reason="weak", now=_T0,
        )
        # Reject → terminal
        await store.transition(
            id=uid_a, from_state="PENDING", to_state="REJECTED",
            now=_T1, decided_by="curl",
        )
        # New update for same host now creates a new row
        uid_b = uuid4()
        inserted = await store.insert_if_no_pending(
            id=uid_b, host_id="001", priority="high",
            score=80.0, last_reason="strong", now=_T2,
        )
        assert inserted is True
        rows = await store.list(state="PENDING")
        assert len(rows) == 1
        assert rows[0].id == uid_b
    finally:
        await _cleanup(store)


async def test_transition_with_correct_from_state(pg_pool):
    store = await _make_store(pg_pool)
    try:
        uid = uuid4()
        await store.insert_if_no_pending(
            id=uid, host_id="001", priority="low",
            score=42.0, last_reason="weak", now=_T0,
        )
        row = await store.transition(
            id=uid, from_state="PENDING", to_state="APPROVED",
            now=_T1, decided_by="curl",
        )
        assert row is not None
        assert row.state == "APPROVED"
        assert row.decided_at == _T1.isoformat()
        assert row.decided_by == "curl"
    finally:
        await _cleanup(store)


async def test_transition_with_wrong_from_state_returns_none(pg_pool):
    store = await _make_store(pg_pool)
    try:
        uid = uuid4()
        await store.insert_if_no_pending(
            id=uid, host_id="001", priority="low",
            score=42.0, last_reason="weak", now=_T0,
        )
        # Try transition from APPROVED while still PENDING → no-op
        result = await store.transition(
            id=uid, from_state="APPROVED", to_state="EXECUTED",
            now=_T1, decided_by="curl",
        )
        assert result is None
        # Row state unchanged
        row = await store.get(uid)
        assert row.state == "PENDING"
    finally:
        await _cleanup(store)


async def test_list_filter_and_get_missing(pg_pool):
    store = await _make_store(pg_pool)
    try:
        # Default state=PENDING
        assert await store.list() == []
        assert await store.get(uuid4()) is None
        # Insert one, list both filters
        uid = uuid4()
        await store.insert_if_no_pending(
            id=uid, host_id="001", priority="low",
            score=42.0, last_reason="weak", now=_T0,
        )
        pending = await store.list(state="PENDING")
        assert len(pending) == 1
        # No-filter list returns everything
        all_rows = await store.list(state=None)
        assert len(all_rows) == 1
    finally:
        await _cleanup(store)
