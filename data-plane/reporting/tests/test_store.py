"""ReportingStore tests — Part 1: schema + threat_scores."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio

from reporting.store import ReportingStore


_T = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def store(pg_pool, tmp_path):
    s = ReportingStore(reports_dir=str(tmp_path / "reports"), pool=pg_pool)
    await s.init_schema()
    yield s
    await s.aclose()


async def test_init_schema_is_idempotent(pg_pool, tmp_path):
    s = ReportingStore(reports_dir=str(tmp_path / "reports"), pool=pg_pool)
    await s.init_schema()
    await s.init_schema()   # second call must not raise
    await s.aclose()


async def test_insert_and_query_threat_scores(store):
    await store.insert_score(host_id="001", score=42.5, reason="r1", ts=_T)
    await store.insert_score(host_id="001", score=55.0, reason="r2", ts=_T + timedelta(minutes=5))
    await store.insert_score(host_id="002", score=10.0, reason="r3", ts=_T + timedelta(minutes=10))

    rows = await store.query_scores(start=_T, end=_T + timedelta(hours=1))
    assert len(rows) == 3
    assert {r.host_id for r in rows} == {"001", "002"}

    rows_001 = await store.query_scores(
        start=_T, end=_T + timedelta(hours=1), host_id="001"
    )
    assert len(rows_001) == 2
    assert all(r.host_id == "001" for r in rows_001)


async def test_query_scores_filters_by_range(store):
    inside = _T + timedelta(minutes=30)
    before = _T - timedelta(hours=1)
    after = _T + timedelta(hours=2)
    await store.insert_score(host_id="001", score=1.0, reason="before", ts=before)
    await store.insert_score(host_id="001", score=2.0, reason="inside", ts=inside)
    await store.insert_score(host_id="001", score=3.0, reason="after", ts=after)

    rows = await store.query_scores(start=_T, end=_T + timedelta(hours=1))
    assert len(rows) == 1
    assert rows[0].reason == "inside"


async def test_top_hosts_by_max_score(store):
    await store.insert_score(host_id="A", score=10.0, reason="x", ts=_T)
    await store.insert_score(host_id="A", score=50.0, reason="x", ts=_T + timedelta(minutes=1))
    await store.insert_score(host_id="B", score=80.0, reason="x", ts=_T)
    await store.insert_score(host_id="C", score=30.0, reason="x", ts=_T)

    top = await store.top_hosts_by_max_score(
        start=_T, end=_T + timedelta(hours=1), limit=2
    )
    assert top == [("B", 80.0), ("A", 50.0)]


async def test_query_scores_boundary_semantics(store):
    """Pin the half-open [start, end) range semantics."""
    await store.insert_score(host_id="X", score=0.0, reason="at_start", ts=_T)
    await store.insert_score(host_id="X", score=0.0, reason="mid", ts=_T + timedelta(minutes=30))
    await store.insert_score(host_id="X", score=0.0, reason="at_end", ts=_T + timedelta(hours=1))
    rows = await store.query_scores(start=_T, end=_T + timedelta(hours=1))
    assert {r.reason for r in rows} == {"at_start", "mid"}, (
        "start must be inclusive; end must be exclusive"
    )


async def test_insert_score_rejects_naive_datetime(store):
    naive = datetime(2030, 1, 1, 0, 0, 0)   # no tzinfo
    with pytest.raises(ValueError, match="naive"):
        await store.insert_score(host_id="X", score=1.0, reason="r", ts=naive)


async def test_insert_list_get_delete_report(store):
    rid1 = uuid4()
    rid2 = uuid4()
    pdf_path1 = f"{store.reports_dir}/2030-01-01-{rid1}.pdf"
    pdf_path2 = f"{store.reports_dir}/2030-01-02-{rid2}.pdf"

    # Make the actual files so delete_report's os.unlink works
    import os
    os.makedirs(store.reports_dir, exist_ok=True)
    with open(pdf_path1, "wb") as f:
        f.write(b"%PDF-1.4\n")
    with open(pdf_path2, "wb") as f:
        f.write(b"%PDF-1.4\n")

    await store.insert_report(
        id=rid1, name="r1",
        range_start=datetime(2030, 1, 1, tzinfo=timezone.utc),
        range_end=datetime(2030, 1, 2, tzinfo=timezone.utc),
        generated_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        generated_by="alice",
        pdf_path=pdf_path1, size_bytes=9, approvals_count=2, scores_count=10,
    )
    await store.insert_report(
        id=rid2, name="r2",
        range_start=datetime(2030, 1, 2, tzinfo=timezone.utc),
        range_end=datetime(2030, 1, 3, tzinfo=timezone.utc),
        generated_at=datetime(2030, 1, 2, tzinfo=timezone.utc),
        generated_by="bob",
        pdf_path=pdf_path2, size_bytes=9, approvals_count=5, scores_count=20,
    )

    rows, total = await store.list_reports(limit=10, offset=0)
    assert total == 2
    assert [r.id for r in rows] == [rid2, rid1]   # newest first

    fetched = await store.get_report(rid1)
    assert fetched is not None
    assert fetched.name == "r1"
    assert fetched.generated_by == "alice"
    assert fetched.range_start == datetime(2030, 1, 1, tzinfo=timezone.utc)

    assert await store.delete_report(rid1) is True
    assert await store.get_report(rid1) is None
    assert os.path.exists(pdf_path1) is False  # file removed too


async def test_delete_report_idempotent_on_missing_file(store):
    rid = uuid4()
    ghost_path = f"{store.reports_dir}/ghost-{rid}.pdf"
    # Do NOT create the file
    await store.insert_report(
        id=rid, name="ghost",
        range_start=datetime(2030, 1, 1, tzinfo=timezone.utc),
        range_end=datetime(2030, 1, 2, tzinfo=timezone.utc),
        generated_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        generated_by="alice",
        pdf_path=ghost_path, size_bytes=0, approvals_count=0, scores_count=0,
    )
    assert await store.delete_report(rid) is True   # row removed even though file absent

    # Second delete returns False (no row)
    assert await store.delete_report(rid) is False
