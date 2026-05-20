from datetime import datetime, timezone

import pytest

from auth_backend.store import DuplicateUserError, UserRow, UsersStore


_T0 = datetime(2026, 5, 20, 12, 0, 0, tzinfo=timezone.utc)


async def _make_store(tmp_db_path):
    store = UsersStore(tmp_db_path)
    await store.init_schema()
    return store


async def test_create_user_persists_row(tmp_db_path):
    store = await _make_store(tmp_db_path)
    try:
        row = await store.create_user(
            username="alice", email="alice@example.com",
            password="secret", role="admin", now=_T0,
        )
        assert isinstance(row, UserRow)
        assert row.username == "alice"
        assert row.email == "alice@example.com"
        assert row.role == "admin"
        assert row.created_at == _T0.isoformat()
        fetched = await store.get_by_email("alice@example.com")
        assert fetched is not None
        assert fetched.id == row.id
    finally:
        await store.aclose()


async def test_create_user_duplicate_username_raises(tmp_db_path):
    store = await _make_store(tmp_db_path)
    try:
        await store.create_user(
            username="alice", email="a@b", password="x", role="admin", now=_T0,
        )
        with pytest.raises(DuplicateUserError, match="username"):
            await store.create_user(
                username="alice", email="other@b", password="x", role="admin", now=_T0,
            )
    finally:
        await store.aclose()


async def test_create_user_duplicate_email_raises(tmp_db_path):
    store = await _make_store(tmp_db_path)
    try:
        await store.create_user(
            username="alice", email="a@b", password="x", role="admin", now=_T0,
        )
        with pytest.raises(DuplicateUserError, match="email"):
            await store.create_user(
                username="bob", email="a@b", password="x", role="admin", now=_T0,
            )
    finally:
        await store.aclose()


async def test_get_by_email_missing_returns_none(tmp_db_path):
    store = await _make_store(tmp_db_path)
    try:
        assert await store.get_by_email("nope@example.com") is None
    finally:
        await store.aclose()


async def test_password_hash_is_bcrypt_not_plaintext(tmp_db_path):
    store = await _make_store(tmp_db_path)
    try:
        await store.create_user(
            username="alice", email="a@b", password="my-plaintext",
            role="admin", now=_T0,
        )
        row = await store.get_by_email("a@b")
        assert row is not None
        # bcrypt hashes start with '$2'
        assert row.password_hash.startswith("$2"), f"got: {row.password_hash}"
        assert "my-plaintext" not in row.password_hash
        # Verify works
        assert store.verify_password("my-plaintext", row.password_hash) is True
        assert store.verify_password("wrong", row.password_hash) is False
    finally:
        await store.aclose()
