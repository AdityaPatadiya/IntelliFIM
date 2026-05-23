"""Postgres-backed users store (v2).

asyncpg connection pool + native UUID / TIMESTAMPTZ types. The class shape
and method signatures match the v1 aiosqlite version exactly — callers
don't notice the swap.

Pattern: asyncpg.create_pool(min_size=1, max_size=8). Postgres handles
concurrent writes natively; no application-level asyncio.Lock needed.
`init_schema()` is idempotent (CREATE TABLE IF NOT EXISTS). `aclose()`
closes the pool (only if the store owns it).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

import asyncpg
from passlib.hash import bcrypt


logger = logging.getLogger(__name__)


_CREATE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL
);
"""
_IDX_USERS_EMAIL = "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);"


class DuplicateUserError(Exception):
    """Raised when create_user hits a UNIQUE constraint on username or email."""


@dataclass(frozen=True)
class UserRow:
    id: UUID
    username: str
    email: str
    password_hash: str
    role: str
    created_at: str  # ISO-8601 string (preserved from v1 contract)


def _row(record) -> UserRow:
    created_at = record["created_at"]
    return UserRow(
        id=record["id"],
        username=record["username"],
        email=record["email"],
        password_hash=record["password_hash"],
        role=record["role"],
        created_at=created_at.isoformat() if isinstance(created_at, datetime) else created_at,
    )


class UsersStore:
    def __init__(
        self,
        database_url: str | None = None,
        *,
        pool: asyncpg.Pool | None = None,
    ) -> None:
        # Either `database_url` (production) or `pool` (tests using the testcontainers fixture).
        self._database_url = database_url
        self._pool: asyncpg.Pool | None = pool
        self._pool_owned = pool is None  # only close pool if we created it

    async def init_schema(self) -> None:
        if self._pool is None:
            if self._database_url is None:
                raise RuntimeError("database_url required when pool not provided")
            self._pool = await asyncpg.create_pool(
                self._database_url, min_size=1, max_size=8
            )
        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_USERS)
            await conn.execute(_IDX_USERS_EMAIL)

    async def create_user(
        self,
        *,
        username: str,
        email: str,
        password: str,
        role: str,
        now: datetime,
    ) -> UserRow:
        if self._pool is None:
            raise RuntimeError("call init_schema() first")
        password_hash = bcrypt.hash(password)
        new_id = uuid4()
        async with self._pool.acquire() as conn:
            # Pre-check for clearer error than UniqueViolationError
            existing_uname = await conn.fetchrow(
                "SELECT 1 FROM users WHERE username = $1 LIMIT 1", username
            )
            if existing_uname is not None:
                raise DuplicateUserError(f"username '{username}' already exists")
            existing_email = await conn.fetchrow(
                "SELECT 1 FROM users WHERE email = $1 LIMIT 1", email
            )
            if existing_email is not None:
                raise DuplicateUserError(f"email '{email}' already exists")
            row = await conn.fetchrow(
                """
                INSERT INTO users (id, username, email, password_hash, role, created_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *
                """,
                new_id,
                username,
                email,
                password_hash,
                role,
                now,
            )
        return _row(row)

    async def get_by_email(self, email: str) -> UserRow | None:
        if self._pool is None:
            raise RuntimeError("call init_schema() first")
        async with self._pool.acquire() as conn:
            record = await conn.fetchrow(
                "SELECT * FROM users WHERE email = $1", email
            )
        return _row(record) if record else None

    async def get_by_id(self, user_id: UUID) -> UserRow | None:
        if self._pool is None:
            raise RuntimeError("call init_schema() first")
        async with self._pool.acquire() as conn:
            record = await conn.fetchrow(
                "SELECT * FROM users WHERE id = $1", user_id
            )
        return _row(record) if record else None

    async def admin_exists(self) -> bool:
        if self._pool is None:
            raise RuntimeError("call init_schema() first")
        async with self._pool.acquire() as conn:
            record = await conn.fetchrow(
                "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1"
            )
        return record is not None

    @staticmethod
    def verify_password(plaintext: str, password_hash: str) -> bool:
        try:
            return bcrypt.verify(plaintext, password_hash)
        except ValueError:
            return False

    async def aclose(self) -> None:
        if self._pool is not None and self._pool_owned:
            await self._pool.close()
            self._pool = None
