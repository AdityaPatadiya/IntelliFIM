"""SQLite-backed user store with bcrypt password hashing."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

import aiosqlite
from passlib.hash import bcrypt


_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
"""


class DuplicateUserError(Exception):
    """Raised when create_user hits a UNIQUE constraint on username or email."""


@dataclass(frozen=True)
class UserRow:
    id: UUID
    username: str
    email: str
    password_hash: str
    role: str
    created_at: str


def _row(record) -> UserRow:
    return UserRow(
        id=UUID(record["id"]),
        username=record["username"],
        email=record["email"],
        password_hash=record["password_hash"],
        role=record["role"],
        created_at=record["created_at"],
    )


class UsersStore:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def init_schema(self) -> None:
        if self._conn is not None:
            return
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        async with self._lock:
            await self._conn.execute(_CREATE_TABLE)
            await self._conn.commit()

    async def create_user(
        self,
        *,
        username: str,
        email: str,
        password: str,
        role: str,
        now: datetime,
    ) -> UserRow:
        if self._conn is None:
            raise RuntimeError("call init_schema() first")
        password_hash = bcrypt.hash(password)
        new_id = uuid4()
        async with self._lock:
            # Pre-check for clearer error than IntegrityError
            cur = await self._conn.execute(
                "SELECT 1 FROM users WHERE username = ? LIMIT 1", (username,)
            )
            if await cur.fetchone() is not None:
                raise DuplicateUserError(f"username '{username}' already exists")
            cur = await self._conn.execute(
                "SELECT 1 FROM users WHERE email = ? LIMIT 1", (email,)
            )
            if await cur.fetchone() is not None:
                raise DuplicateUserError(f"email '{email}' already exists")
            await self._conn.execute(
                """
                INSERT INTO users (id, username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (str(new_id), username, email, password_hash, role, now.isoformat()),
            )
            await self._conn.commit()
        return UserRow(
            id=new_id, username=username, email=email,
            password_hash=password_hash, role=role, created_at=now.isoformat(),
        )

    async def get_by_email(self, email: str) -> UserRow | None:
        if self._conn is None:
            raise RuntimeError("call init_schema() first")
        cur = await self._conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        )
        record = await cur.fetchone()
        return _row(record) if record else None

    async def get_by_id(self, user_id: UUID) -> UserRow | None:
        if self._conn is None:
            raise RuntimeError("call init_schema() first")
        cur = await self._conn.execute(
            "SELECT * FROM users WHERE id = ?", (str(user_id),)
        )
        record = await cur.fetchone()
        return _row(record) if record else None

    async def admin_exists(self) -> bool:
        if self._conn is None:
            raise RuntimeError("call init_schema() first")
        cur = await self._conn.execute(
            "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1"
        )
        return await cur.fetchone() is not None

    @staticmethod
    def verify_password(plaintext: str, password_hash: str) -> bool:
        try:
            return bcrypt.verify(plaintext, password_hash)
        except ValueError:
            return False

    async def aclose(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
