# Admin Console v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing `chronos-ai-guard/` React frontend into the data-plane stack as a live admin console for response-orchestrator approvals, backed by a new FastAPI `auth-backend` service that issues HS256 JWTs and a JWT-validating middleware added to the orchestrator.

**Architecture:** Two new services (`auth-backend` on :8000 with FastAPI + SQLite + python-jose + passlib; `admin-console` on :5173 using the existing chronos-ai-guard Vite dev image). One modified service (`response-orchestrator` gains aiohttp middleware for JWT validation + per-route role guards). One frontend page (`IncidentManagement.tsx`) is rewritten to poll `/approvals` and call approve/reject via a new `apiClient.ts`. Other 8 pages keep their mocks with a "Mock data — v2" badge.

**Tech Stack:** Python 3.12, FastAPI ~0.115, uvicorn, aiosqlite, passlib[bcrypt], python-jose[cryptography], pytest, httpx (FastAPI TestClient). aiohttp middleware on orchestrator. React 18 + TypeScript + Vite + shadcn/ui (all pre-existing). @tanstack/react-query (pre-existing). Docker Compose.

**Reference spec:** [`docs/superpowers/specs/2026-05-20-admin-console-v1-design.md`](../specs/2026-05-20-admin-console-v1-design.md)

**Reference for patterns:** Auth-backend mirrors the orchestrator's shape (pyproject + Dockerfile + nested try/finally `__main__.py` + per-component pytest with fakes) but uses FastAPI instead of aiohttp. Orchestrator middleware mirrors the per-request injection pattern from any aiohttp web app. Frontend pattern: react-query for polling, single `apiClient.ts` for fetch + auth header injection.

**Branch:** Create `feat/admin-console-v1` off `main` before Task 1.

---

## File Map

```
data-plane/
├── auth_backend/                                ← NEW package
│   ├── pyproject.toml
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── README.md
│   ├── src/auth_backend/
│   │   ├── __init__.py                          (empty)
│   │   ├── __main__.py                          (entry point — uvicorn launcher)
│   │   ├── config.py                            (AuthBackendConfig)
│   │   ├── store.py                             (UsersStore + UserRow, aiosqlite + bcrypt)
│   │   ├── jwt_helper.py                        (encode/decode + JwtError)
│   │   └── api.py                               (FastAPI app factory)
│   └── tests/
│       ├── __init__.py                          (empty)
│       ├── conftest.py                          (shared fixtures)
│       ├── test_config.py                       (4 tests)
│       ├── test_users_store.py                  (5 tests)
│       ├── test_jwt.py                          (3 tests)
│       └── test_api.py                          (7 tests)
│
├── orchestrator/src/orchestrator/
│   ├── auth.py                                  ← NEW (Principal + decode_token + middleware)
│   ├── config.py                                ← MODIFY (add jwt_secret)
│   ├── api.py                                   ← MODIFY (mount middleware; accept jwt_secret)
│   └── __main__.py                              ← MODIFY (pass jwt_secret)
├── orchestrator/tests/
│   ├── test_auth.py                             ← NEW (3 tests)
│   ├── test_api.py                              ← MODIFY (Authorization headers + 2 new tests)
│   └── test_config.py                           ← MODIFY (JWT_SECRET in monkeypatch)
│
├── docker-compose.yml                           ← MODIFY (add 2 services + healthcheck on orchestrator)
├── .env.dataplane.example                       ← MODIFY (JWT_SECRET= placeholder, ADMIN_* defaults)
├── scripts/
│   ├── init-secrets.sh                          ← NEW (idempotent JWT_SECRET generator)
│   └── approve-pending.py                       ← MODIFY (login first, forward token)
└── README.md                                    ← MODIFY (service count 21→23, new section, DoD #10)

chronos-ai-guard/                                ← repo root (NOT inside data-plane/)
├── src/lib/apiClient.ts                         ← NEW (~40 lines, fetch + auth header injection)
├── src/contexts/AuthContext.tsx                 ← MODIFY (live wiring to auth-backend)
├── src/pages/IncidentManagement.tsx             ← MODIFY (rewrite with useQuery + approve/reject)
├── src/pages/{Dashboard,FileIntegrity,NetworkMonitoring,AIAnomaly,
│              EmployeeManagement,SystemConfig,Reports,AuditLogs}.tsx
│                                                ← MODIFY (one-line "Mock data — v2" badge)
└── (existing Dockerfile, vite.config.ts unchanged — env vars passed via Compose)
```

**13 tasks total. ~24 new Python tests (4 config + 5 store + 3 jwt + 7 api in auth-backend, + 3 auth + 2 api additions in orchestrator). No new JS tests in v1. 1 manual UX smoke (DoD #10).**

---

## Task 1: Bootstrap `intellifim-auth-backend` package

**Files:**
- Create: `data-plane/auth_backend/pyproject.toml`
- Create: `data-plane/auth_backend/README.md`
- Create: `data-plane/auth_backend/src/auth_backend/__init__.py` (empty)
- Create: `data-plane/auth_backend/tests/__init__.py` (empty)
- Create: `data-plane/auth_backend/tests/conftest.py`

### Step 1: Create `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "intellifim-auth-backend"
version = "0.1.0"
description = "Auth backend (FastAPI + SQLite + JWT) for IntelliFIM"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115,<0.116",
    "uvicorn[standard]>=0.30,<0.35",
    "pydantic[email]>=2.7,<3",  # [email] pulls email-validator for Pydantic's EmailStr (mid-execution amendment, Task 5)
    "aiosqlite>=0.20,<0.22",
    "passlib[bcrypt]>=1.7,<2",
    # bcrypt 4.1+ removed `__about__.__version__` which passlib 1.7.4 reads;
    # any hash call then raises `ValueError("password cannot be longer than
    # 72 bytes")` during passlib's wrap-bug detection probe. Pin <4.1 until
    # passlib 1.8 ships an upstream fix. (Mid-execution amendment from Task 1.)
    "bcrypt>=4.0,<4.1",
    "python-jose[cryptography]>=3.3,<4",
]

[project.optional-dependencies]
dev = [
    "pytest>=8,<9",
    "pytest-asyncio>=0.23,<0.25",
    "httpx>=0.27,<0.29",
]

[project.scripts]
intellifim-auth-backend = "auth_backend.__main__:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
```

### Step 2: Empty `__init__.py` files

`data-plane/auth_backend/src/auth_backend/__init__.py` — completely empty (0 bytes).
`data-plane/auth_backend/tests/__init__.py` — completely empty (0 bytes).

### Step 3: Create `tests/conftest.py`

```python
# data-plane/auth_backend/tests/conftest.py
import os
import tempfile

import pytest


@pytest.fixture
def tmp_db_path():
    """Temp-file SQLite path for tests; cleaned up after."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
```

### Step 4: Create `README.md`

```markdown
# intellifim-auth-backend

FastAPI service that issues HS256 JWTs for the IntelliFIM admin console
and validates them via shared secret with response-orchestrator. SQLite-
backed user store; bcrypt password hashing; seeds one admin user from
env on first start.

Install for development:

    pip install -e data-plane/auth_backend[dev]

Run Python tests:

    pytest --import-mode=importlib data-plane/auth_backend/tests

Endpoints:
- POST /auth/register
- POST /auth/login
- GET  /auth/me
- GET  /healthz
- GET  /docs  (Swagger UI; FastAPI built-in)
```

### Step 5: Install and verify

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
pip install -e data-plane/auth_backend[dev]
python -c "import auth_backend; print(auth_backend.__file__)"
```

Expected: prints `/home/aditya/Documents/IntelliFIM/data-plane/auth_backend/src/auth_backend/__init__.py`.

### Step 6: STAGE ONLY — DO NOT COMMIT

```bash
git add data-plane/auth_backend/pyproject.toml \
        data-plane/auth_backend/README.md \
        data-plane/auth_backend/src/auth_backend/__init__.py \
        data-plane/auth_backend/tests/__init__.py \
        data-plane/auth_backend/tests/conftest.py
```

> Suggested commit: `feat(auth-backend): bootstrap intellifim-auth-backend package`

---

## Task 2: `AuthBackendConfig` (TDD)

**Files:**
- Create: `data-plane/auth_backend/src/auth_backend/config.py`
- Create: `data-plane/auth_backend/tests/test_config.py`

### Step 1: Write the failing tests

```python
# data-plane/auth_backend/tests/test_config.py
import pytest

from auth_backend.config import AuthBackendConfig


def test_from_env_with_defaults(monkeypatch):
    monkeypatch.delenv("DB_PATH", raising=False)
    monkeypatch.delenv("API_HOST", raising=False)
    monkeypatch.delenv("API_PORT", raising=False)
    monkeypatch.delenv("JWT_TTL_SECONDS", raising=False)
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    # Required vars
    monkeypatch.setenv("JWT_SECRET", "test-secret")
    monkeypatch.setenv("ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("ADMIN_PASSWORD", "secret")
    cfg = AuthBackendConfig.from_env()
    assert cfg.db_path == "/data/users.db"
    assert cfg.api_host == "0.0.0.0"
    assert cfg.api_port == 8000
    assert cfg.jwt_secret == "test-secret"
    assert cfg.jwt_ttl_seconds == 28800
    assert cfg.cors_origins == ["http://localhost:5173", "http://127.0.0.1:5173"]
    assert cfg.admin_username == "admin"
    assert cfg.admin_email == "admin@example.com"
    assert cfg.admin_password == "secret"


def test_from_env_overrides(monkeypatch):
    monkeypatch.setenv("DB_PATH", "/tmp/staging.db")
    monkeypatch.setenv("API_HOST", "127.0.0.1")
    monkeypatch.setenv("API_PORT", "9999")
    monkeypatch.setenv("JWT_SECRET", "prod-secret")
    monkeypatch.setenv("JWT_TTL_SECONDS", "3600")
    monkeypatch.setenv("CORS_ORIGINS", "https://a.example.com,https://b.example.com")
    monkeypatch.setenv("ADMIN_USERNAME", "root")
    monkeypatch.setenv("ADMIN_EMAIL", "root@example.com")
    monkeypatch.setenv("ADMIN_PASSWORD", "rootpw")
    cfg = AuthBackendConfig.from_env()
    assert cfg.db_path == "/tmp/staging.db"
    assert cfg.api_host == "127.0.0.1"
    assert cfg.api_port == 9999
    assert cfg.jwt_secret == "prod-secret"
    assert cfg.jwt_ttl_seconds == 3600
    assert cfg.cors_origins == ["https://a.example.com", "https://b.example.com"]
    assert cfg.admin_username == "root"
    assert cfg.admin_email == "root@example.com"
    assert cfg.admin_password == "rootpw"


def test_from_env_missing_jwt_secret_raises(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.setenv("ADMIN_EMAIL", "x@y")
    monkeypatch.setenv("ADMIN_PASSWORD", "z")
    with pytest.raises(ValueError, match="JWT_SECRET"):
        AuthBackendConfig.from_env()


def test_from_env_missing_admin_fields_raises(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x")
    monkeypatch.delenv("ADMIN_EMAIL", raising=False)
    monkeypatch.setenv("ADMIN_PASSWORD", "z")
    with pytest.raises(ValueError, match="ADMIN_EMAIL"):
        AuthBackendConfig.from_env()
    monkeypatch.setenv("ADMIN_EMAIL", "x@y")
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    with pytest.raises(ValueError, match="ADMIN_PASSWORD"):
        AuthBackendConfig.from_env()
```

### Step 2: Run tests, confirm they fail

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
pytest --import-mode=importlib data-plane/auth_backend/tests/test_config.py -v
```

Expected: ImportError on `auth_backend.config`.

### Step 3: Implement `config.py`

```python
# data-plane/auth_backend/src/auth_backend/config.py
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthBackendConfig:
    db_path: str
    api_host: str
    api_port: int
    jwt_secret: str
    jwt_ttl_seconds: int
    cors_origins: list[str]
    admin_username: str
    admin_email: str
    admin_password: str

    @classmethod
    def from_env(cls) -> "AuthBackendConfig":
        jwt_secret = os.environ.get("JWT_SECRET")
        if not jwt_secret:
            raise ValueError("JWT_SECRET env var is required (no default)")
        admin_email = os.environ.get("ADMIN_EMAIL")
        if not admin_email:
            raise ValueError("ADMIN_EMAIL env var is required (no default)")
        admin_password = os.environ.get("ADMIN_PASSWORD")
        if not admin_password:
            raise ValueError("ADMIN_PASSWORD env var is required (no default)")
        cors_raw = os.environ.get(
            "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        )
        return cls(
            db_path=os.environ.get("DB_PATH", "/data/users.db"),
            api_host=os.environ.get("API_HOST", "0.0.0.0"),
            api_port=int(os.environ.get("API_PORT", "8000")),
            jwt_secret=jwt_secret,
            jwt_ttl_seconds=int(os.environ.get("JWT_TTL_SECONDS", "28800")),
            cors_origins=[s.strip() for s in cors_raw.split(",") if s.strip()],
            admin_username=os.environ.get("ADMIN_USERNAME", "admin"),
            admin_email=admin_email,
            admin_password=admin_password,
        )
```

### Step 4: Run tests, confirm 4 pass

```bash
pytest --import-mode=importlib data-plane/auth_backend/tests/test_config.py -v
```

Expected: **4 passed**.

### Step 5: STAGE — DO NOT COMMIT

```bash
git add data-plane/auth_backend/src/auth_backend/config.py \
        data-plane/auth_backend/tests/test_config.py
```

> Suggested commit: `feat(auth-backend): add AuthBackendConfig with env-var parsing`

---

## Task 3: `UsersStore` (TDD with aiosqlite + bcrypt)

**Files:**
- Create: `data-plane/auth_backend/src/auth_backend/store.py`
- Create: `data-plane/auth_backend/tests/test_users_store.py`

### Step 1: Write the failing tests

```python
# data-plane/auth_backend/tests/test_users_store.py
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
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/auth_backend/tests/test_users_store.py -v
```

Expected: ImportError on `auth_backend.store`.

### Step 3: Implement `store.py`

```python
# data-plane/auth_backend/src/auth_backend/store.py
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
```

### Step 4: Run tests, confirm 5 pass

```bash
pytest --import-mode=importlib data-plane/auth_backend/tests/test_users_store.py -v
```

Expected: **5 passed**.

### Step 5: STAGE — DO NOT COMMIT

```bash
git add data-plane/auth_backend/src/auth_backend/store.py \
        data-plane/auth_backend/tests/test_users_store.py
```

> Suggested commit: `feat(auth-backend): add UsersStore (aiosqlite + bcrypt)`

---

## Task 4: JWT helpers (TDD)

**Files:**
- Create: `data-plane/auth_backend/src/auth_backend/jwt_helper.py`
- Create: `data-plane/auth_backend/tests/test_jwt.py`

### Step 1: Write the failing tests

```python
# data-plane/auth_backend/tests/test_jwt.py
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
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/auth_backend/tests/test_jwt.py -v
```

Expected: ImportError on `auth_backend.jwt_helper`.

### Step 3: Implement `jwt_helper.py`

```python
# data-plane/auth_backend/src/auth_backend/jwt_helper.py
"""HS256 JWT encode/decode helpers for auth-backend.

Decode is also imported by response-orchestrator's auth middleware so the
two services agree byte-for-byte on the claim shape.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from jose import ExpiredSignatureError, JWTError, jwt


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
    options = {"verify_exp": True}
    try:
        # python-jose checks exp against the server clock; for testability
        # we'd want to inject `now`, but jose doesn't expose that. As a
        # workaround when `now` is provided, do the exp check ourselves
        # AFTER signature verification.
        claims = jwt.decode(
            token, secret, algorithms=[_ALGO],
            options={**options, "verify_exp": False},  # we check below with injected `now`
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
```

### Step 4: Run tests, confirm 3 pass

```bash
pytest --import-mode=importlib data-plane/auth_backend/tests/test_jwt.py -v
```

Expected: **3 passed**.

### Step 5: STAGE — DO NOT COMMIT

```bash
git add data-plane/auth_backend/src/auth_backend/jwt_helper.py \
        data-plane/auth_backend/tests/test_jwt.py
```

> Suggested commit: `feat(auth-backend): add HS256 JWT encode/decode helpers`

---

## Task 5: FastAPI app + endpoints (TDD)

**Files:**
- Create: `data-plane/auth_backend/src/auth_backend/api.py`
- Create: `data-plane/auth_backend/tests/test_api.py`

### Step 1: Write the failing tests

```python
# data-plane/auth_backend/tests/test_api.py
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from auth_backend.api import build_app
from auth_backend.jwt_helper import decode
from auth_backend.store import UsersStore


_T0 = datetime(2026, 5, 20, 12, 0, 0, tzinfo=timezone.utc)
_SECRET = "test-secret"


async def _store_for(path):
    store = UsersStore(path)
    await store.init_schema()
    return store


async def _client_for(tmp_db_path):
    store = await _store_for(tmp_db_path)
    app = build_app(store=store, jwt_secret=_SECRET, jwt_ttl_seconds=3600,
                    cors_origins=["http://localhost:5173"], now=lambda: _T0)
    return TestClient(app), store


async def test_healthz(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
    finally:
        await store.aclose()


async def test_register_happy_path(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        resp = client.post("/auth/register", json={
            "username": "alice", "email": "alice@example.com",
            "password": "secret", "role": "admin",
        })
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["username"] == "alice"
        assert body["email"] == "alice@example.com"
        assert body["role"] == "admin"
        assert "id" in body
        # No password field in response
        assert "password" not in body
        assert "password_hash" not in body
    finally:
        await store.aclose()


async def test_register_duplicate_returns_409(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        # email needs a valid TLD because Pydantic EmailStr (via email-validator) rejects "a@b"
        payload = {"username": "alice", "email": "a@b.io", "password": "x", "role": "admin"}
        first = client.post("/auth/register", json=payload)
        assert first.status_code == 201
        second = client.post("/auth/register", json=payload)
        assert second.status_code == 409
        assert "already exists" in second.json()["error"]
    finally:
        await store.aclose()


async def test_login_happy_returns_token(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        client.post("/auth/register", json={
            "username": "alice", "email": "alice@example.com",
            "password": "secret", "role": "admin",
        })
        resp = client.post("/auth/login", json={
            "email": "alice@example.com", "password": "secret",
        })
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert body["user"]["email"] == "alice@example.com"
        # Token decodes with the shared secret
        claims = decode(body["access_token"], secret=_SECRET, now=_T0)
        assert claims["email"] == "alice@example.com"
        assert claims["role"] == "admin"
    finally:
        await store.aclose()


async def test_login_wrong_password_returns_401(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        # email needs valid TLD for Pydantic EmailStr
        client.post("/auth/register", json={
            "username": "alice", "email": "a@b.io", "password": "secret", "role": "admin",
        })
        resp = client.post("/auth/login", json={
            "email": "a@b.io", "password": "wrong",
        })
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid credentials"
    finally:
        await store.aclose()


async def test_me_with_token_returns_user(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        # email needs valid TLD for Pydantic EmailStr
        client.post("/auth/register", json={
            "username": "alice", "email": "a@b.io", "password": "x", "role": "analyst",
        })
        login = client.post("/auth/login", json={"email": "a@b.io", "password": "x"})
        token = login.json()["access_token"]
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["email"] == "a@b.io"
        assert resp.json()["role"] == "analyst"
    finally:
        await store.aclose()


async def test_me_without_token_returns_401(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        resp = client.get("/auth/me")
        assert resp.status_code == 401
        assert resp.json()["error"] == "unauthorized"
    finally:
        await store.aclose()
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/auth_backend/tests/test_api.py -v
```

Expected: ImportError on `auth_backend.api`.

### Step 3: Implement `api.py`

```python
# data-plane/auth_backend/src/auth_backend/api.py
"""FastAPI app for the auth-backend.

Built via build_app(store, jwt_secret, jwt_ttl_seconds, cors_origins, now)
so tests can inject fakes / fixed clock. Returns uniform JSON errors
{"error":"..."} via custom exception handlers.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from auth_backend.jwt_helper import JwtError, decode as jwt_decode, encode as jwt_encode
from auth_backend.store import DuplicateUserError, UsersStore


Role = Literal["admin", "analyst", "viewer"]


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1)
    email: EmailStr
    password: str = Field(min_length=1)
    role: Role


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str = Field(min_length=1)


class UserPublic(BaseModel):
    id: str
    username: str
    email: str
    role: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic


def build_app(
    *,
    store: UsersStore,
    jwt_secret: str,
    jwt_ttl_seconds: int,
    cors_origins: list[str],
    now: Callable[[], datetime] = _default_now,
) -> FastAPI:
    app = FastAPI(title="intellifim-auth-backend", docs_url="/docs", redoc_url=None)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.exception_handler(DuplicateUserError)
    async def _dup_handler(_req: Request, exc: DuplicateUserError) -> JSONResponse:
        return JSONResponse(
            {"error": f"username or email already exists: {exc}"},
            status_code=status.HTTP_409_CONFLICT,
        )

    @app.exception_handler(HTTPException)
    async def _http_handler(_req: Request, exc: HTTPException) -> JSONResponse:
        # Normalize FastAPI's default {"detail": "..."} to {"error": "..."}
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    async def _current_user(
        authorization: str | None = Header(default=None),
    ) -> UserPublic:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="unauthorized")
        token = authorization[len("Bearer "):]
        try:
            claims = jwt_decode(token, secret=jwt_secret, now=now())
        except JwtError:
            raise HTTPException(status_code=401, detail="unauthorized")
        # Fetch fresh from DB so we don't trust stale role claims
        from uuid import UUID
        row = await store.get_by_id(UUID(claims["sub"]))
        if row is None:
            raise HTTPException(status_code=401, detail="unauthorized")
        return UserPublic(
            id=str(row.id), username=row.username, email=row.email, role=row.role,
        )

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/auth/register", status_code=201, response_model=UserPublic)
    async def register(body: RegisterRequest) -> UserPublic:
        row = await store.create_user(
            username=body.username, email=body.email,
            password=body.password, role=body.role, now=now(),
        )
        return UserPublic(
            id=str(row.id), username=row.username, email=row.email, role=row.role,
        )

    @app.post("/auth/login", response_model=LoginResponse)
    async def login(body: LoginRequest) -> LoginResponse:
        row = await store.get_by_email(body.email)
        if row is None or not store.verify_password(body.password, row.password_hash):
            raise HTTPException(status_code=401, detail="invalid credentials")
        token = jwt_encode(
            user_id=row.id, username=row.username, email=row.email, role=row.role,
            secret=jwt_secret, ttl_seconds=jwt_ttl_seconds, now=now(),
        )
        return LoginResponse(
            access_token=token,
            user=UserPublic(
                id=str(row.id), username=row.username, email=row.email, role=row.role,
            ),
        )

    @app.get("/auth/me", response_model=UserPublic)
    async def me(user: UserPublic = Depends(_current_user)) -> UserPublic:
        return user

    return app


async def seed_admin_if_missing(
    *,
    store: UsersStore,
    username: str,
    email: str,
    password: str,
    now: Callable[[], datetime] = _default_now,
) -> None:
    """Called once at startup. Inserts the admin user if no admin exists yet."""
    import logging
    log = logging.getLogger("auth_backend")
    if await store.admin_exists():
        log.info("admin user already exists, skipping seed")
        return
    try:
        await store.create_user(
            username=username, email=email, password=password,
            role="admin", now=now(),
        )
        log.info("seeded admin user %s", username)
    except DuplicateUserError as exc:
        log.info("admin seed skipped (race): %s", exc)
```

### Step 4: Run tests, confirm 7 pass

```bash
pytest --import-mode=importlib data-plane/auth_backend/tests/test_api.py -v
```

Expected: **7 passed**.

### Step 5: Run full auth-backend suite

```bash
pytest --import-mode=importlib data-plane/auth_backend/tests -v
```

Expected: 4 config + 5 store + 3 jwt + 7 api = **19 passed**.

### Step 6: STAGE — DO NOT COMMIT

```bash
git add data-plane/auth_backend/src/auth_backend/api.py \
        data-plane/auth_backend/tests/test_api.py
```

> Suggested commit: `feat(auth-backend): add FastAPI endpoints (login/register/me/healthz)`

---

## Task 6: Entry point + Dockerfile for auth-backend

**Files:**
- Create: `data-plane/auth_backend/src/auth_backend/__main__.py`
- Create: `data-plane/auth_backend/Dockerfile`
- Create: `data-plane/auth_backend/.dockerignore`

### Step 1: Implement `__main__.py`

```python
# data-plane/auth_backend/src/auth_backend/__main__.py
from __future__ import annotations

import asyncio
import logging

import uvicorn

from auth_backend.api import build_app, seed_admin_if_missing
from auth_backend.config import AuthBackendConfig
from auth_backend.store import UsersStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("auth_backend")


async def _bootstrap(cfg: AuthBackendConfig) -> tuple[UsersStore, "uvicorn.Server"]:
    store = UsersStore(cfg.db_path)
    await store.init_schema()
    await seed_admin_if_missing(
        store=store, username=cfg.admin_username,
        email=cfg.admin_email, password=cfg.admin_password,
    )
    app = build_app(
        store=store,
        jwt_secret=cfg.jwt_secret,
        jwt_ttl_seconds=cfg.jwt_ttl_seconds,
        cors_origins=cfg.cors_origins,
    )
    config = uvicorn.Config(
        app=app, host=cfg.api_host, port=cfg.api_port,
        log_level="info", access_log=False,
    )
    server = uvicorn.Server(config)
    return store, server


async def _run() -> None:
    cfg = AuthBackendConfig.from_env()
    log.info(
        "starting auth-backend db=%s api=%s:%d jwt_ttl=%ds cors=%s",
        cfg.db_path, cfg.api_host, cfg.api_port,
        cfg.jwt_ttl_seconds, cfg.cors_origins,
    )
    store, server = await _bootstrap(cfg)
    try:
        await server.serve()
    finally:
        await store.aclose()


def main() -> None:
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        log.info("shutdown requested")


if __name__ == "__main__":
    main()
```

### Step 2: Create `.dockerignore`

```
__pycache__
.pytest_cache
.venv
*.egg-info
tests
```

### Step 3: Create `Dockerfile`

```dockerfile
# data-plane/auth_backend/Dockerfile
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY auth_backend /app/auth_backend
RUN pip install /app/auth_backend

RUN mkdir -p /data

CMD ["intellifim-auth-backend"]
```

(Build context is `data-plane/` — same convention as orchestrator. Schemas package NOT installed because auth-backend doesn't import it.)

### Step 4: Sanity-check entry point imports

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
python -c "from auth_backend.__main__ import main; print(main)"
```

Expected: `<function main at 0x...>`.

### Step 5: Build the image

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker build -f auth_backend/Dockerfile -t intellifim-auth-backend:dev .
```

Expected: build succeeds. Image ~180-220 MB (FastAPI + bcrypt + python-jose).

### Step 6: Sanity-check image runs (exits fast — no env vars set)

```bash
docker run --rm intellifim-auth-backend:dev 2>&1 | head -5 || true
```

Expected: container fails fast with `JWT_SECRET env var is required (no default)`.

Now with env vars:

```bash
docker run --rm \
    -e JWT_SECRET=test \
    -e ADMIN_EMAIL=admin@local \
    -e ADMIN_PASSWORD=changeme \
    -e DB_PATH=/tmp/test.db \
    intellifim-auth-backend:dev 2>&1 | head -8 &
SLEEP_PID=$!
sleep 5
kill $SLEEP_PID 2>/dev/null || true
```

Expected: logs `starting auth-backend db=/tmp/test.db api=0.0.0.0:8000 jwt_ttl=28800s cors=['http://localhost:5173', 'http://127.0.0.1:5173']` and `seeded admin user admin` then begins serving (no exit before kill).

### Step 7: STAGE — DO NOT COMMIT

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/auth_backend/src/auth_backend/__main__.py \
        data-plane/auth_backend/Dockerfile \
        data-plane/auth_backend/.dockerignore
```

> Suggested commit: `feat(auth-backend): add Docker entry point and image`

---

## Task 7: Orchestrator `auth.py` — Principal + decode_token + middleware (TDD)

**Files:**
- Create: `data-plane/orchestrator/src/orchestrator/auth.py`
- Create: `data-plane/orchestrator/tests/test_auth.py`

### Step 1: Write the failing tests

```python
# data-plane/orchestrator/tests/test_auth.py
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
```

### Step 2: Run tests, confirm they fail

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
pytest --import-mode=importlib data-plane/orchestrator/tests/test_auth.py -v
```

Expected: ImportError on `orchestrator.auth`.

### Step 3: Implement `auth.py`

```python
# data-plane/orchestrator/src/orchestrator/auth.py
"""JWT validation + RBAC middleware for the orchestrator API.

Shared HS256 secret with auth-backend. Mounted via build_api(jwt_secret=...).
Returns uniform {"error": "..."} JSON on 401 and 403.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable
from uuid import UUID

from aiohttp import web
from jose import JWTError, jwt

log = logging.getLogger(__name__)


_ALGO = "HS256"
_REQUIRED_CLAIMS = ("sub", "username", "role", "exp")
_ROLES_THAT_CAN_DECIDE = {"admin", "analyst"}


class AuthError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class Principal:
    user_id: UUID
    username: str
    role: str


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def decode_token(
    token: str,
    secret: str,
    *,
    now: datetime | None = None,
) -> Principal:
    try:
        claims = jwt.decode(
            token, secret, algorithms=[_ALGO],
            options={"verify_exp": False},  # we check exp below with injected `now`
        )
    except JWTError as exc:
        raise AuthError(401, f"invalid token: {exc}") from exc
    for required in _REQUIRED_CLAIMS:
        if required not in claims:
            raise AuthError(401, f"token missing claim: {required}")
    effective_now = now or _default_now()
    if int(effective_now.timestamp()) >= int(claims["exp"]):
        raise AuthError(401, "token has expired")
    try:
        user_id = UUID(claims["sub"])
    except (ValueError, TypeError) as exc:
        raise AuthError(401, f"sub claim not a UUID: {exc}") from exc
    return Principal(
        user_id=user_id,
        username=str(claims["username"]),
        role=str(claims["role"]),
    )


def _is_decide_route(request: web.Request) -> bool:
    """True for POST /approvals/{id}/{approve|reject}."""
    if request.method != "POST":
        return False
    parts = request.path.rstrip("/").split("/")
    return (
        len(parts) == 4
        and parts[1] == "approvals"
        and parts[3] in ("approve", "reject")
    )


def make_auth_middleware(
    secret: str,
    *,
    now: Callable[[], datetime] = _default_now,
):
    @web.middleware
    async def auth_middleware(
        request: web.Request,
        handler: Callable[[web.Request], Awaitable[web.Response]],
    ) -> web.Response:
        # /healthz is exempt
        if request.path == "/healthz":
            return await handler(request)
        # Extract Bearer token
        authz = request.headers.get("Authorization", "")
        if not authz.startswith("Bearer "):
            return web.json_response({"error": "unauthorized"}, status=401)
        token = authz[len("Bearer "):]
        try:
            principal = decode_token(token, secret, now=now())
        except AuthError as exc:
            return web.json_response({"error": exc.message}, status=exc.status)
        # Role guard on decide routes
        if _is_decide_route(request) and principal.role not in _ROLES_THAT_CAN_DECIDE:
            return web.json_response(
                {
                    "error": "forbidden",
                    "required_role": "admin|analyst",
                    "actual_role": principal.role,
                },
                status=403,
            )
        request["principal"] = principal
        return await handler(request)

    return auth_middleware
```

### Step 4: Run tests, confirm 3 pass

```bash
pytest --import-mode=importlib data-plane/orchestrator/tests/test_auth.py -v
```

Expected: **3 passed**.

### Step 5: STAGE — DO NOT COMMIT

```bash
git add data-plane/orchestrator/src/orchestrator/auth.py \
        data-plane/orchestrator/tests/test_auth.py
```

> Suggested commit: `feat(orchestrator): add JWT auth middleware + Principal + decode_token`

---

## Task 8: Wire orchestrator (config + api + main + existing tests)

**Files:**
- Modify: `data-plane/orchestrator/src/orchestrator/config.py`
- Modify: `data-plane/orchestrator/src/orchestrator/api.py`
- Modify: `data-plane/orchestrator/src/orchestrator/__main__.py`
- Modify: `data-plane/orchestrator/tests/test_config.py`
- Modify: `data-plane/orchestrator/tests/test_api.py`
- Modify: `data-plane/orchestrator/src/orchestrator/pyproject.toml` (add python-jose dep)

### Step 1: Add python-jose to orchestrator pyproject

In `data-plane/orchestrator/pyproject.toml`, add to the `dependencies` list:

```toml
    "python-jose[cryptography]>=3.3,<4",
```

Re-install:

```bash
pip install -e data-plane/orchestrator[dev]
```

### Step 2: Add `jwt_secret` to `OrchestratorConfig`

Edit `data-plane/orchestrator/src/orchestrator/config.py`. Add the field + env parsing. Final shape:

```python
# data-plane/orchestrator/src/orchestrator/config.py
from __future__ import annotations

import os
from dataclasses import dataclass

INPUT_TOPIC = "threat.scores"


@dataclass(frozen=True)
class OrchestratorConfig:
    bootstrap_servers: str
    consumer_group: str
    db_path: str
    api_host: str
    api_port: int
    wazuh_manager_url: str
    wazuh_api_user: str
    wazuh_api_password: str
    tier_low_threshold: float
    tier_high_threshold: float
    jwt_secret: str
    input_topic: str = INPUT_TOPIC

    @classmethod
    def from_env(cls) -> "OrchestratorConfig":
        api_port = _parse_port(os.environ.get("API_PORT", "8200"))
        low = _parse_threshold(os.environ.get("TIER_LOW_THRESHOLD", "30"), "TIER_LOW_THRESHOLD")
        high = _parse_threshold(os.environ.get("TIER_HIGH_THRESHOLD", "70"), "TIER_HIGH_THRESHOLD")
        if low <= 0:
            raise ValueError(f"TIER_LOW_THRESHOLD must be > 0, got {low}")
        if high > 100:
            raise ValueError(f"TIER_HIGH_THRESHOLD must be <= 100, got {high}")
        if low >= high:
            raise ValueError(
                f"TIER_LOW_THRESHOLD ({low}) must be < TIER_HIGH_THRESHOLD ({high})"
            )
        jwt_secret = os.environ.get("JWT_SECRET")
        if not jwt_secret:
            raise ValueError("JWT_SECRET env var is required (no default)")
        return cls(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092"),
            consumer_group=os.environ.get("CONSUMER_GROUP", "response-orchestrator"),
            db_path=os.environ.get("DB_PATH", "/data/approvals.db"),
            api_host=os.environ.get("API_HOST", "0.0.0.0"),
            api_port=api_port,
            wazuh_manager_url=os.environ.get("WAZUH_MANAGER_URL", "https://wazuh-manager:55000"),
            wazuh_api_user=os.environ.get("WAZUH_API_USER", "wazuh"),
            wazuh_api_password=os.environ.get("WAZUH_API_PASSWORD", "wazuh"),
            tier_low_threshold=low,
            tier_high_threshold=high,
            jwt_secret=jwt_secret,
        )


def _parse_port(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"API_PORT must be a positive integer 1-65535, got {raw!r}") from exc
    if port < 1 or port > 65535:
        raise ValueError(f"API_PORT must be 1-65535, got {port}")
    return port


def _parse_threshold(raw: str, name: str) -> float:
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc
```

### Step 3: Add 2 new tests + update existing test_config

In `data-plane/orchestrator/tests/test_config.py`:

- Update `test_from_env_with_defaults` to `monkeypatch.setenv("JWT_SECRET", "test")` BEFORE calling `from_env()` and add `assert cfg.jwt_secret == "test"`.
- Update `test_from_env_overrides` to set `JWT_SECRET` and assert.
- The 4 rejection tests (`test_from_env_rejects_invalid_port`, etc.) ALSO need `JWT_SECRET` set in their monkeypatch (otherwise they'll raise the wrong error). Add a one-liner at the top of each: `monkeypatch.setenv("JWT_SECRET", "x")`.

Append two new tests:

```python
def test_from_env_missing_jwt_secret_raises(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(ValueError, match="JWT_SECRET"):
        OrchestratorConfig.from_env()


def test_from_env_jwt_secret_round_trips(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "round-trip-value")
    cfg = OrchestratorConfig.from_env()
    assert cfg.jwt_secret == "round-trip-value"
```

Total: 7 prior + 2 new = **9 config tests**.

### Step 4: Update `api.py` to accept jwt_secret + mount middleware

Edit `data-plane/orchestrator/src/orchestrator/api.py`. Add the import and middleware mount; signature change to `build_api()`:

```python
# Top of file: add import
from orchestrator.auth import make_auth_middleware
```

Replace the `build_api` signature line:

```python
def build_api(
    *,
    store: ApprovalStore,
    wazuh: WazuhClient,
    jwt_secret: str,
    now: Callable[[], datetime] = _default_now,
) -> web.Application:
    # Thread `now` into the middleware too so tests with a mock clock see
    # consistent expiry checks across handlers AND the JWT validator.
    app = web.Application(middlewares=[make_auth_middleware(jwt_secret, now=now)])
    # ... rest unchanged
```

NO other changes to api.py — the middleware does the gating in front of every handler.

### Step 5: Update `test_api.py` to set JWT_SECRET + add 2 new tests

Edit `data-plane/orchestrator/tests/test_api.py`. At the top, add:

```python
from datetime import timedelta
from uuid import uuid4

from jose import jwt as _jose_jwt


_JWT_SECRET = "test-secret"


def _make_token(role: str = "admin", *, secret: str = _JWT_SECRET) -> str:
    iat = _T0
    exp = _T0 + timedelta(hours=1)
    return _jose_jwt.encode(
        {
            "sub": str(uuid4()),
            "username": "alice",
            "email": "a@b",
            "role": role,
            "iat": int(iat.timestamp()),
            "exp": int(exp.timestamp()),
        },
        secret,
        algorithm="HS256",
    )


def _auth_headers(role: str = "admin") -> dict[str, str]:
    return {"Authorization": f"Bearer {_make_token(role)}"}
```

Then in `_client()` helper, update the `build_api(...)` call to pass `jwt_secret=_JWT_SECRET`:

```python
async def _client(store, wazuh):
    app = build_api(store=store, wazuh=wazuh, jwt_secret=_JWT_SECRET, now=lambda: _T0)
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    return client
```

For every existing test that makes an HTTP call against the orchestrator, add `headers=_auth_headers()` to the `.get`/`.post` invocation. Example for `test_healthz`:

```python
async def test_healthz():
    store, path = await _make_store()
    client = await _client(store, FakeWazuh())
    try:
        resp = await client.get("/healthz")  # healthz is unauthenticated, no header needed
        assert resp.status == 200
        assert (await resp.json()) == {"status": "ok"}
    finally:
        await client.close()
        await _cleanup(store, path)
```

For approve/reject tests, use `headers=_auth_headers("admin")`. For list/get, `headers=_auth_headers("viewer")` is fine (any valid role works for GET).

Append 2 new tests:

```python
async def test_unauthenticated_returns_401():
    store, path = await _make_store()
    client = await _client(store, FakeWazuh())
    try:
        resp = await client.get("/approvals")
        assert resp.status == 401
        assert (await resp.json()) == {"error": "unauthorized"}
    finally:
        await client.close()
        await _cleanup(store, path)


async def test_viewer_cannot_approve_returns_403():
    store, path = await _make_store()
    uid = uuid4()
    await store.insert_if_no_pending(
        id=uid, host_id="001", priority="low",
        score=42.0, last_reason="weak", now=_T0,
    )
    client = await _client(store, FakeWazuh())
    try:
        resp = await client.post(
            f"/approvals/{uid}/approve",
            headers=_auth_headers("viewer"),
        )
        assert resp.status == 403
        body = await resp.json()
        assert body["error"] == "forbidden"
        assert body["actual_role"] == "viewer"
        assert body["required_role"] == "admin|analyst"
    finally:
        await client.close()
        await _cleanup(store, path)
```

Total: 7 prior + 2 new = **9 api tests**.

### Step 6: Update `__main__.py` to pass jwt_secret

Edit `data-plane/orchestrator/src/orchestrator/__main__.py`. In the call to `build_api`, add `jwt_secret=cfg.jwt_secret`:

```python
            try:
                api_app = build_api(store=store, wazuh=wazuh, jwt_secret=cfg.jwt_secret)
                runner = web.AppRunner(api_app)
                # ... rest unchanged
```

Also update the startup log line to acknowledge JWT is on:

```python
    log.info(
        "starting response-orchestrator in=%s db=%s api=%s:%d wazuh=%s tiers=%.1f/%.1f jwt=enabled",
        cfg.input_topic, cfg.db_path, cfg.api_host, cfg.api_port,
        cfg.wazuh_manager_url, cfg.tier_low_threshold, cfg.tier_high_threshold,
    )
```

### Step 7: Run the full orchestrator suite + sanity check

```bash
pytest --import-mode=importlib data-plane/orchestrator/tests -v
```

Expected: 9 config + 7 store + 6 wazuh_client + 9 engine + 9 api + 3 auth + 2 quarantine_sh = **45 passed**.

### Step 8: STAGE — DO NOT COMMIT

```bash
git add data-plane/orchestrator/src/orchestrator/config.py \
        data-plane/orchestrator/src/orchestrator/api.py \
        data-plane/orchestrator/src/orchestrator/__main__.py \
        data-plane/orchestrator/pyproject.toml \
        data-plane/orchestrator/tests/test_config.py \
        data-plane/orchestrator/tests/test_api.py
```

> Suggested commit: `feat(orchestrator): wire JWT middleware + RBAC into api/config/main`

---

## Task 9: `init-secrets.sh` + `.env.dataplane.example` + orchestrator healthcheck

**Files:**
- Create: `data-plane/scripts/init-secrets.sh`
- Modify: `data-plane/.env.dataplane.example`
- Modify: `data-plane/docker-compose.yml` (add healthcheck to existing `response-orchestrator` service block)

### Step 1: Create `init-secrets.sh`

```bash
#!/usr/bin/env bash
# data-plane/scripts/init-secrets.sh
# Generates JWT_SECRET in .env.dataplane on first stack-up (idempotent).
# Safe to re-run: skips if JWT_SECRET is already set to a non-empty value.
set -euo pipefail

ENV_FILE="$(dirname "$0")/../.env.dataplane"

if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: $ENV_FILE not found. Copy .env.dataplane.example first." >&2
    exit 1
fi

if grep -q '^JWT_SECRET=.\+' "$ENV_FILE"; then
    echo "JWT_SECRET already set in ${ENV_FILE}; skipping."
    exit 0
fi

SECRET=$(openssl rand -base64 48 | tr -d '\n')

# If a blank JWT_SECRET= line exists, replace it; else append.
if grep -q '^JWT_SECRET=$' "$ENV_FILE"; then
    sed -i "s|^JWT_SECRET=$|JWT_SECRET=${SECRET}|" "$ENV_FILE"
else
    echo "JWT_SECRET=${SECRET}" >> "$ENV_FILE"
fi

echo "JWT_SECRET written to ${ENV_FILE}"
```

Make executable:

```bash
chmod +x data-plane/scripts/init-secrets.sh
```

### Step 2: Verify the script is idempotent

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
./scripts/init-secrets.sh
grep '^JWT_SECRET=' .env.dataplane
./scripts/init-secrets.sh  # second run — should say "already set"
```

Expected: first run writes a 64-char base64 secret; second run prints `JWT_SECRET already set ... skipping.`

### Step 3: Update `.env.dataplane.example`

Append to `data-plane/.env.dataplane.example`:

```
# Auth & secrets (sub-project #6 / admin console)
JWT_SECRET=
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@intellifim.local
ADMIN_PASSWORD=changeme
```

(Empty `JWT_SECRET=` is the convention; `init-secrets.sh` fills it on first run.)

### Step 4: Add healthcheck to orchestrator service

In `data-plane/docker-compose.yml`, find the `response-orchestrator:` service block. Add a `healthcheck:` directive (preserve every other line):

```yaml
    healthcheck:
      test: ["CMD-SHELL", "python -c \"import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8200/healthz', timeout=2).getcode()==200 else 1)\""]
      interval: 5s
      timeout: 3s
      retries: 6
```

(Uses Python because `python:3.12-slim` has no `wget` or `curl`.)

### Step 5: Validate the compose file

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane config -q
```

Expected: no output (success).

### Step 6: STAGE — DO NOT COMMIT

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/scripts/init-secrets.sh \
        data-plane/.env.dataplane.example \
        data-plane/docker-compose.yml
```

> Suggested commit: `feat(compose): add init-secrets.sh + orchestrator healthcheck + .env.dataplane.example admin defaults`

---

## Task 10: Wire `auth-backend` + `admin-console` into Compose; update `approve-pending.py`

**Files:**
- Modify: `data-plane/docker-compose.yml` (append auth-backend + admin-console services + volume)
- Modify: `data-plane/scripts/approve-pending.py` (login first, forward token)
- Modify: `data-plane/.env.dataplane` (the user's local env file gets JWT_SECRET written by init-secrets.sh; also append ADMIN_EMAIL/ADMIN_PASSWORD for compose)

### Step 1: Append auth-backend service block

In `data-plane/docker-compose.yml`, after the last existing service block (`response-orchestrator`) and BEFORE the top-level `volumes:` key, append:

```yaml
  auth-backend:
    image: intellifim-auth-backend:dev
    build:
      context: .
      dockerfile: auth_backend/Dockerfile
    container_name: auth-backend
    networks: [bus]
    ports:
      - "127.0.0.1:8000:8000"
    volumes:
      - auth_backend_data:/data
    environment:
      DB_PATH: "/data/users.db"
      API_HOST: "0.0.0.0"
      API_PORT: "8000"
      JWT_SECRET: "${JWT_SECRET}"
      JWT_TTL_SECONDS: "28800"
      CORS_ORIGINS: "http://localhost:5173,http://127.0.0.1:5173"
      ADMIN_USERNAME: "${ADMIN_USERNAME:-admin}"
      ADMIN_EMAIL: "${ADMIN_EMAIL}"
      ADMIN_PASSWORD: "${ADMIN_PASSWORD}"
    healthcheck:
      test: ["CMD-SHELL", "python -c \"import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/healthz', timeout=2).getcode()==200 else 1)\""]
      interval: 5s
      timeout: 3s
      retries: 6
```

### Step 2: Add `JWT_SECRET` to orchestrator service env

In the SAME compose file, find the existing `response-orchestrator:` service block and ADD `JWT_SECRET: "${JWT_SECRET}"` to its `environment:` block (preserve every other line).

### Step 3: Append admin-console service block

Right after auth-backend (still before the top-level `volumes:`), append:

```yaml
  admin-console:
    image: chronos-ai-guard:dev
    build:
      context: ../chronos-ai-guard
      dockerfile: Dockerfile
      target: dev
    container_name: admin-console
    networks: [bus]
    depends_on:
      auth-backend:
        condition: service_healthy
      response-orchestrator:
        condition: service_healthy
    ports:
      - "127.0.0.1:5173:8080"
    volumes:
      - ../chronos-ai-guard/src:/app/src:ro
      - ../chronos-ai-guard/public:/app/public:ro
      - ../chronos-ai-guard/index.html:/app/index.html:ro
      # Vite needs these at /app root or path aliases (@/), Tailwind classes,
      # and shadcn imports all break inside the container.
      # (Mid-execution amendment from Task 10.)
      - ../chronos-ai-guard/vite.config.ts:/app/vite.config.ts:ro
      - ../chronos-ai-guard/tsconfig.json:/app/tsconfig.json:ro
      - ../chronos-ai-guard/tsconfig.app.json:/app/tsconfig.app.json:ro
      - ../chronos-ai-guard/tsconfig.node.json:/app/tsconfig.node.json:ro
      - ../chronos-ai-guard/tailwind.config.ts:/app/tailwind.config.ts:ro
      - ../chronos-ai-guard/postcss.config.js:/app/postcss.config.js:ro
      - ../chronos-ai-guard/components.json:/app/components.json:ro
    environment:
      VITE_AUTH_API_URL: "http://localhost:8000"
      VITE_ORCHESTRATOR_API_URL: "http://localhost:8200"
```

### Step 4: Add `auth_backend_data` to top-level volumes

In the top-level `volumes:` block (alongside `orchestrator_data`, `kafka_data`, etc.), add:

```yaml
  auth_backend_data:
```

### Step 5: Update `approve-pending.py` to login first

Replace the contents of `data-plane/scripts/approve-pending.py` with:

```python
#!/usr/bin/env python3
# data-plane/scripts/approve-pending.py
"""Poll GET /approvals until a PENDING row appears (timeout 60s), then POST
/approve on it and print the final row JSON.

Reads ADMIN_EMAIL and ADMIN_PASSWORD from env (matches the compose env vars),
logs in to the auth-backend at AUTH_BACKEND_URL, and forwards the JWT on
every orchestrator call.

Usage:
    ADMIN_EMAIL=admin@intellifim.local ADMIN_PASSWORD=changeme \\
        python data-plane/scripts/approve-pending.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


def _http_get(url: str, token: str | None = None) -> dict:
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_post(url: str, body: dict | None = None, token: str | None = None) -> dict:
    data = json.dumps(body or {}).encode("utf-8")
    req = urllib.request.Request(url, method="POST", data=data)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body_str = exc.read().decode("utf-8")
        return {"_http_status": exc.code, "_body": body_str}


def _login(auth_url: str, email: str, password: str) -> str:
    try:
        body = _http_post(f"{auth_url}/auth/login", {"email": email, "password": password})
    except urllib.error.URLError as exc:
        print(f"auth-backend unreachable at {auth_url}: {exc}", file=sys.stderr)
        sys.exit(3)
    if "_http_status" in body:
        print(f"login failed: {body['_http_status']} {body['_body']}", file=sys.stderr)
        sys.exit(4)
    return body["access_token"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8200",
                        help="orchestrator REST API base URL")
    parser.add_argument("--auth-url", default=os.environ.get("AUTH_BACKEND_URL", "http://127.0.0.1:8000"),
                        help="auth-backend base URL")
    parser.add_argument("--timeout-seconds", type=int, default=60)
    args = parser.parse_args()

    email = os.environ.get("ADMIN_EMAIL")
    password = os.environ.get("ADMIN_PASSWORD")
    if not email or not password:
        print("ADMIN_EMAIL and ADMIN_PASSWORD env vars are required", file=sys.stderr)
        return 5

    print(f"logging in as {email} at {args.auth_url}", file=sys.stderr)
    token = _login(args.auth_url, email, password)

    deadline = time.monotonic() + args.timeout_seconds
    pending_id: str | None = None
    while time.monotonic() < deadline:
        body = _http_get(f"{args.base_url}/approvals?state=PENDING", token=token)
        approvals = body.get("approvals", [])
        if approvals:
            pending_id = approvals[0]["id"]
            print(f"found PENDING approval id={pending_id}", file=sys.stderr)
            break
        time.sleep(2)

    if pending_id is None:
        print(f"timeout: no PENDING approvals appeared in {args.timeout_seconds}s",
              file=sys.stderr)
        return 1

    print(f"POST {args.base_url}/approvals/{pending_id}/approve", file=sys.stderr)
    result = _http_post(f"{args.base_url}/approvals/{pending_id}/approve", token=token)
    print(json.dumps(result, indent=2))
    if result.get("state") == "EXECUTED":
        return 0
    print(f"unexpected state: {result.get('state')!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
```

### Step 6: Build the two new images

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker build -f auth_backend/Dockerfile -t intellifim-auth-backend:dev .
docker build -f ../chronos-ai-guard/Dockerfile --target dev \
    -t chronos-ai-guard:dev ../chronos-ai-guard
```

Expected: both builds succeed. Image sizes: auth-backend ~200MB, chronos-ai-guard dev ~500MB (node_modules).

### Step 7: Prepare env + secrets

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
test -f .env.dataplane || cp .env.dataplane.example .env.dataplane
# Append the new auth vars if not present
grep -q '^ADMIN_EMAIL=' .env.dataplane || echo "ADMIN_EMAIL=admin@intellifim.local" >> .env.dataplane
grep -q '^ADMIN_PASSWORD=' .env.dataplane || echo "ADMIN_PASSWORD=changeme" >> .env.dataplane
./scripts/init-secrets.sh
```

### Step 8: Bring up the stack (synchronous waits)

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane down -v 2>/dev/null || true
docker compose --env-file .env.dataplane up -d
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 120
```

### Step 9: Verify all 23 services Up + auth-backend works + orchestrator requires auth

```bash
docker compose --env-file .env.dataplane ps --format '{{.Name}} {{.Status}}'
echo "---healthz---"
curl -s http://127.0.0.1:8000/healthz
echo ""
echo "---login---"
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
    -H 'Content-Type: application/json' \
    -d "$(printf '{"email":"%s","password":"%s"}' "$(grep ^ADMIN_EMAIL= .env.dataplane | cut -d= -f2)" "$(grep ^ADMIN_PASSWORD= .env.dataplane | cut -d= -f2)")" \
    | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
echo "got token len=${#TOKEN}"
echo "---approvals WITHOUT auth (expect 401)---"
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8200/approvals
echo "---approvals WITH auth (expect 200)---"
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8200/approvals
echo "---approve-pending.py---"
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
# Seed first
./scripts/seed-test-traffic.sh
sleep 45
ADMIN_EMAIL="$(grep ^ADMIN_EMAIL= .env.dataplane | cut -d= -f2)" \
    ADMIN_PASSWORD="$(grep ^ADMIN_PASSWORD= .env.dataplane | cut -d= -f2)" \
    python ./scripts/approve-pending.py 2>&1 | tail -10
```

Expected:
- 23 services Up
- `/healthz` returns `{"status":"ok"}`
- TOKEN length > 200
- Unauthenticated `/approvals` → `401`
- Authenticated `/approvals` → `200`
- `approve-pending.py` exits 0 with `"state": "EXECUTED"`

### Step 10: Bring DOWN (KEEP volumes)

```bash
docker compose --env-file .env.dataplane down
```

### Step 11: STAGE — DO NOT COMMIT

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/docker-compose.yml \
        data-plane/scripts/approve-pending.py
```

(NOT staging `.env.dataplane` — it's per-user and may contain a real secret. The `.example` file is what's tracked.)

> Suggested commit: `feat(compose): wire auth-backend + admin-console; approve-pending.py logs in first`

---

## Task 11: Frontend `apiClient.ts` + `AuthContext.tsx`

**Files:**
- Create: `chronos-ai-guard/src/lib/apiClient.ts`
- Modify: `chronos-ai-guard/src/contexts/AuthContext.tsx`

### Step 1: Create `apiClient.ts`

Create `chronos-ai-guard/src/lib/apiClient.ts` with EXACTLY this content:

```ts
// chronos-ai-guard/src/lib/apiClient.ts
// Small fetch wrapper that injects the JWT Bearer token from localStorage
// and handles 401 by clearing the session + redirecting to /auth.

export const AUTH_API_URL =
  (import.meta.env.VITE_AUTH_API_URL as string | undefined) ?? "http://localhost:8000";
export const ORCH_API_URL =
  (import.meta.env.VITE_ORCHESTRATOR_API_URL as string | undefined) ?? "http://localhost:8200";

export function getToken(): string | null {
  return localStorage.getItem("access_token");
}

export function clearSession(): void {
  localStorage.removeItem("access_token");
  localStorage.removeItem("aifim_user");
}

export async function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(url, { ...init, headers });
  if (response.status === 401) {
    clearSession();
    // Avoid redirect loop if we're already on /auth
    if (typeof window !== "undefined" && window.location.pathname !== "/auth") {
      window.location.href = "/auth";
    }
  }
  return response;
}
```

### Step 2: Replace `AuthContext.tsx`

Replace `chronos-ai-guard/src/contexts/AuthContext.tsx` with:

```tsx
// chronos-ai-guard/src/contexts/AuthContext.tsx
import React, { createContext, useContext, useState, useEffect } from "react";
import { AUTH_API_URL, apiFetch, clearSession } from "@/lib/apiClient";

export type UserRole = "admin" | "analyst" | "viewer";

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
}

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string, role: UserRole) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const initializeAuth = async () => {
      const token = localStorage.getItem("access_token");
      const storedUser = localStorage.getItem("aifim_user");
      if (token && storedUser) {
        try {
          const resp = await apiFetch(`${AUTH_API_URL}/auth/me`);
          if (resp.ok) {
            const fresh = (await resp.json()) as User;
            setUser(fresh);
            localStorage.setItem("aifim_user", JSON.stringify(fresh));
          } else {
            clearSession();
            setUser(null);
          }
        } catch {
          clearSession();
          setUser(null);
        }
      }
      setIsLoading(false);
    };
    initializeAuth();
  }, []);

  const login = async (email: string, password: string): Promise<void> => {
    const resp = await fetch(`${AUTH_API_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.error ?? `login failed: ${resp.status}`);
    }
    const data = await resp.json();
    localStorage.setItem("access_token", data.access_token);
    localStorage.setItem("aifim_user", JSON.stringify(data.user));
    setUser(data.user as User);
  };

  const register = async (
    username: string, email: string, password: string, role: UserRole,
  ): Promise<void> => {
    const resp = await fetch(`${AUTH_API_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email, password, role }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.error ?? `register failed: ${resp.status}`);
    }
    // v1: register does NOT auto-login. Caller redirects to /auth.
  };

  const logout = (): void => {
    clearSession();
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{ user, login, register, logout, isAuthenticated: !!user, isLoading }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const ctx = useContext(AuthContext);
  if (ctx === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
};
```

### Step 3: Type-check + lint

```bash
cd /home/aditya/Documents/IntelliFIM/chronos-ai-guard
npm run lint 2>&1 | tail -10
```

Expected: no new errors from the two changed files. (Existing repo lint baseline may have warnings; what matters is no NEW errors from `apiClient.ts` or `AuthContext.tsx`.)

If `npm run lint` is too strict against the existing baseline, just verify TypeScript itself accepts the files:

```bash
npx tsc --noEmit src/lib/apiClient.ts src/contexts/AuthContext.tsx 2>&1 | head -10
```

Expected: no errors (or only errors about types in other files we're not changing).

### Step 4: STAGE — DO NOT COMMIT

```bash
cd /home/aditya/Documents/IntelliFIM
git add chronos-ai-guard/src/lib/apiClient.ts \
        chronos-ai-guard/src/contexts/AuthContext.tsx
```

> Suggested commit: `feat(admin-console): add apiClient.ts + wire AuthContext to auth-backend`

---

## Task 12: Rewrite `IncidentManagement.tsx` + add "Mock data — v2" badge to 8 pages

**Files:**
- Modify: `chronos-ai-guard/src/pages/IncidentManagement.tsx` (full rewrite)
- Modify: `chronos-ai-guard/src/pages/Dashboard.tsx` (badge only)
- Modify: `chronos-ai-guard/src/pages/FileIntegrity.tsx` (badge only)
- Modify: `chronos-ai-guard/src/pages/NetworkMonitoring.tsx` (badge only)
- Modify: `chronos-ai-guard/src/pages/AIAnomaly.tsx` (badge only)
- Modify: `chronos-ai-guard/src/pages/EmployeeManagement.tsx` (badge only)
- Modify: `chronos-ai-guard/src/pages/SystemConfig.tsx` (badge only)
- Modify: `chronos-ai-guard/src/pages/Reports.tsx` (badge only)
- Modify: `chronos-ai-guard/src/pages/AuditLogs.tsx` (badge only)

### Step 1: Rewrite `IncidentManagement.tsx`

Replace `chronos-ai-guard/src/pages/IncidentManagement.tsx` with:

```tsx
// chronos-ai-guard/src/pages/IncidentManagement.tsx
import { DashboardLayout } from "@/components/DashboardLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { CheckCircle, XCircle, Clock, ShieldAlert } from "lucide-react";
import { apiFetch, ORCH_API_URL } from "@/lib/apiClient";
import { useAuth } from "@/contexts/AuthContext";

interface ApprovalRow {
  id: string;
  host_id: string;
  priority: "low" | "high";
  score: number;
  last_reason: string;
  state: "PENDING" | "APPROVED" | "REJECTED" | "EXECUTED" | "FAILED";
  created_at: string;
  decided_at: string | null;
  executed_at: string | null;
  decided_by: string | null;
  error_message: string | null;
}

const priorityVariant: Record<ApprovalRow["priority"], "destructive" | "default"> = {
  high: "destructive",
  low: "default",
};

const stateVariant: Record<ApprovalRow["state"], "secondary" | "default" | "destructive" | "outline"> = {
  PENDING: "secondary",
  APPROVED: "default",
  EXECUTED: "default",
  FAILED: "destructive",
  REJECTED: "outline",
};

const ResponseApprovals = () => {
  const { user } = useAuth();
  const canDecide = user?.role === "admin" || user?.role === "analyst";
  const qc = useQueryClient();

  const approvalsQuery = useQuery({
    queryKey: ["approvals", "PENDING"],
    queryFn: async (): Promise<ApprovalRow[]> => {
      const resp = await apiFetch(`${ORCH_API_URL}/approvals?state=PENDING`);
      if (!resp.ok) throw new Error(`status ${resp.status}`);
      const body = (await resp.json()) as { approvals: ApprovalRow[] };
      return body.approvals;
    },
    refetchInterval: 3000,
  });

  const decide = useMutation({
    mutationFn: async ({ id, action }: { id: string; action: "approve" | "reject" }) => {
      const resp = await apiFetch(`${ORCH_API_URL}/approvals/${id}/${action}`, { method: "POST" });
      if (!resp.ok) throw new Error(await resp.text());
      return resp.json();
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["approvals"] }),
  });

  const rows = approvalsQuery.data ?? [];

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Response Approvals</h1>
            <p className="text-muted-foreground">
              Review threat-score updates and approve enforcement actions.
            </p>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              Pending Approvals
              <Badge variant="outline" className="ml-2">
                Polling every 3s
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {approvalsQuery.isLoading && <p className="text-muted-foreground">Loading…</p>}
            {approvalsQuery.isError && (
              <p className="text-destructive">
                Failed to load approvals: {(approvalsQuery.error as Error).message}
              </p>
            )}
            {!approvalsQuery.isLoading && !approvalsQuery.isError && rows.length === 0 && (
              <p className="text-muted-foreground flex items-center gap-2">
                <Clock className="h-4 w-4" />
                No pending approvals.
              </p>
            )}
            {rows.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Created</TableHead>
                    <TableHead>Host</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Reason</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((row) => (
                    <TableRow key={row.id}>
                      <TableCell className="text-xs text-muted-foreground">
                        {new Date(row.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{row.host_id}</TableCell>
                      <TableCell>
                        <Badge variant={priorityVariant[row.priority]}>{row.priority}</Badge>
                      </TableCell>
                      <TableCell>{row.score.toFixed(1)}</TableCell>
                      <TableCell className="max-w-xs truncate" title={row.last_reason}>
                        {row.last_reason}
                      </TableCell>
                      <TableCell>
                        <Badge variant={stateVariant[row.state]}>{row.state}</Badge>
                      </TableCell>
                      <TableCell className="text-right space-x-2">
                        {canDecide ? (
                          <>
                            <Button
                              size="sm"
                              onClick={() => decide.mutate({ id: row.id, action: "approve" })}
                              disabled={decide.isPending}
                            >
                              <CheckCircle className="h-4 w-4 mr-1" />
                              Approve
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => decide.mutate({ id: row.id, action: "reject" })}
                              disabled={decide.isPending}
                            >
                              <XCircle className="h-4 w-4 mr-1" />
                              Reject
                            </Button>
                          </>
                        ) : (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span>
                                <Button size="sm" disabled>
                                  <CheckCircle className="h-4 w-4 mr-1" />
                                  Approve
                                </Button>
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>
                              Requires analyst or admin role
                            </TooltipContent>
                          </Tooltip>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default ResponseApprovals;
```

(File still exports default, but the component name changes. The route in `App.tsx` continues to render this file's default export — no router change needed.)

### Step 2: Add "Mock data — v2" badge to the 8 other pages

For EACH of these 8 files, find the H1 element and add a `<Badge>` sibling. Example for `Dashboard.tsx`:

Original:
```tsx
<h1 className="text-3xl font-bold">Dashboard</h1>
```

New (assuming `import { Badge } from "@/components/ui/badge"` already present — if not, add it):
```tsx
<div className="flex items-center gap-3">
  <h1 className="text-3xl font-bold">Dashboard</h1>
  <Badge variant="outline">Mock data — v2</Badge>
</div>
```

Apply to: `Dashboard.tsx`, `FileIntegrity.tsx`, `NetworkMonitoring.tsx`, `AIAnomaly.tsx`, `EmployeeManagement.tsx`, `SystemConfig.tsx`, `Reports.tsx`, `AuditLogs.tsx`.

(The Badge import is already in the codebase from shadcn; if a particular page hasn't imported it yet, add `import { Badge } from "@/components/ui/badge";` near the other imports.)

### Step 3: Bring up the stack + manually verify (DoD #10)

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane up -d
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 120
./scripts/seed-test-traffic.sh
sleep 45
```

Open `http://localhost:5173/auth` in a browser. Log in with `admin@intellifim.local` / `changeme`. You should land on the Dashboard.

Click "Incident Management" in the left nav (now showing "Response Approvals" in the header). You should see at least one PENDING row from the seed traffic. Click **Approve** → row state should flip to `EXECUTED` within 3 seconds (the polling interval).

If any of those steps fail, check:
- Browser console for CORS errors → verify `CORS_ORIGINS` env on auth-backend includes `http://localhost:5173`
- Browser network tab — does the request to `:8200/approvals` carry an `Authorization: Bearer ...` header?
- `docker logs admin-console` and `docker logs auth-backend` and `docker logs response-orchestrator` for backend errors

### Step 4: Bring DOWN (KEEP volumes)

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane down
```

### Step 5: STAGE — DO NOT COMMIT

```bash
cd /home/aditya/Documents/IntelliFIM
git add chronos-ai-guard/src/pages/IncidentManagement.tsx \
        chronos-ai-guard/src/pages/Dashboard.tsx \
        chronos-ai-guard/src/pages/FileIntegrity.tsx \
        chronos-ai-guard/src/pages/NetworkMonitoring.tsx \
        chronos-ai-guard/src/pages/AIAnomaly.tsx \
        chronos-ai-guard/src/pages/EmployeeManagement.tsx \
        chronos-ai-guard/src/pages/SystemConfig.tsx \
        chronos-ai-guard/src/pages/Reports.tsx \
        chronos-ai-guard/src/pages/AuditLogs.tsx
```

> Suggested commit: `feat(admin-console): rewrite IncidentManagement as live Response Approvals; tag other pages as mock`

---

## Task 13: README + final fresh-checkout smoke test (DoD #1–#10)

**Files:**
- Modify: `data-plane/README.md`

### Step 1: Update `data-plane/README.md`

**Change A:** Service count `21 services on Docker Compose:` → `23 services on Docker Compose:`.

**Change B:** Add two new bullets in the "What's in the box" list, after `**Response orchestration:**` and before `**Normalizers:**`:

```markdown
- **Auth backend:** `auth-backend` (FastAPI + SQLite + HS256 JWT, seeds admin from env, see [auth_backend/](auth_backend/))
- **Admin console:** `admin-console` (React + Vite + shadcn live wiring of the Response Approvals page, see [../chronos-ai-guard/](../chronos-ai-guard/))
```

**Change C:** Update the "Bring up the stack" section. Replace step 2 + 3 + 4 with:

```bash
# 2. Build the six service images.
docker build -f normalizers/Dockerfile -t intellifim-normalizer:dev .
docker build -f correlator/Dockerfile  -t intellifim-correlator:dev .
docker build -f anomaly/Dockerfile     -t intellifim-anomaly-detector:dev .
docker build -f policy/Dockerfile      -t intellifim-policy:dev .
docker build -f orchestrator/Dockerfile -t intellifim-orchestrator:dev .
docker build -f auth_backend/Dockerfile -t intellifim-auth-backend:dev .
docker build -f ../chronos-ai-guard/Dockerfile --target dev \
    -t chronos-ai-guard:dev ../chronos-ai-guard

# 3. Generate JWT_SECRET (idempotent — safe to re-run).
./scripts/init-secrets.sh

# 4. Start everything.
docker compose --env-file .env.dataplane up -d

# 5. Create Kafka topics (idempotent — safe to re-run).
./scripts/create-topics.sh
```

**Change D:** Add a new section AFTER "Approve a response action" and BEFORE "Consume canonical events from a downstream service":

```markdown
## Use the admin console

Open `http://localhost:5173/auth` in a browser. Log in with the
credentials from `.env.dataplane` (defaults: `admin@intellifim.local` /
`changeme`). Navigate to **Incident Management** (header reads "Response
Approvals" — same route): PENDING approval requests are polled every
3 seconds from the orchestrator's `/approvals` endpoint. Click
**Approve** to dispatch a `!quarantine0` AR command (synchronous; state
flips to `EXECUTED` within ~3 seconds on success). Click **Reject** to
close the request without dispatch. Viewers see disabled buttons with a
tooltip.

The other 8 pages (Dashboard, FileIntegrity, NetworkMonitoring,
AIAnomaly, EmployeeManagement, SystemConfig, Reports, AuditLogs) still
render mock data and are tagged with a "Mock data — v2" badge until
later sub-projects wire them up.

The orchestrator's REST API at `:8200` now requires `Authorization:
Bearer <jwt>` on every request except `/healthz`. POST `/approve` and
POST `/reject` additionally require role=admin or role=analyst; viewer
gets 403. To call the API directly from curl, log in first:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \\
    -H 'Content-Type: application/json' \\
    -d '{"email":"admin@intellifim.local","password":"changeme"}' \\
    | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8200/approvals
```
```

**Change E:** Update "Running the unit tests" — add `auth_backend[dev]` install + a 6th pytest pass:

Replace:

```bash
pip install -e schemas[dev]
pip install -e normalizers[dev]
pip install -e correlator[dev]
pip install -e anomaly[dev]
pip install -e policy[dev]
pip install -e orchestrator[dev]

# Each package declares its own `tests/` package, which means a single
# combined `pytest` call collides on conftest registration. Run them
# in five passes (each with `--import-mode=importlib`):
pytest --import-mode=importlib schemas/tests normalizers/tests -v
pytest --import-mode=importlib correlator/tests -v
pytest --import-mode=importlib anomaly/tests -v
pytest --import-mode=importlib policy/tests -v
pytest --import-mode=importlib orchestrator/tests -v
```

With:

```bash
pip install -e schemas[dev]
pip install -e normalizers[dev]
pip install -e correlator[dev]
pip install -e anomaly[dev]
pip install -e policy[dev]
pip install -e orchestrator[dev]
pip install -e auth_backend[dev]

# Each package declares its own `tests/` package, which means a single
# combined `pytest` call collides on conftest registration. Run them
# in six passes (each with `--import-mode=importlib`):
pytest --import-mode=importlib schemas/tests normalizers/tests -v
pytest --import-mode=importlib correlator/tests -v
pytest --import-mode=importlib anomaly/tests -v
pytest --import-mode=importlib policy/tests -v
pytest --import-mode=importlib orchestrator/tests -v
pytest --import-mode=importlib auth_backend/tests -v
```

**Change F:** Append a new DoD item:

```markdown
10. After bringing the stack up fresh and seeding traffic:
    a. `POST http://localhost:8000/auth/login` with the admin
       credentials returns a JWT `access_token`.
    b. Opening `http://localhost:5173/auth` in a browser and logging in
       redirects to the IncidentManagement (now "Response Approvals") page.
    c. The page lists at least one PENDING approval row (sourced from
       `GET /approvals` via the JWT).
    d. Clicking **Approve** on a PENDING row causes the row state to
       transition to EXECUTED within 3 seconds (the polling interval).
    e. The Wazuh manager's `api.log` shows the corresponding
       `PUT /active-response` call returning HTTP 200 (the orchestrator's
       dispatch contract honored — same v1 limitation as DoD #9 re:
       marker file landing on the agent).
```

### Step 2: Final fresh-checkout smoke test

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane down -v 2>/dev/null || true
docker rmi intellifim-normalizer:dev intellifim-correlator:dev \
           intellifim-anomaly-detector:dev intellifim-policy:dev \
           intellifim-orchestrator:dev intellifim-auth-backend:dev \
           chronos-ai-guard:dev 2>/dev/null || true

docker build -f normalizers/Dockerfile -t intellifim-normalizer:dev .
docker build -f correlator/Dockerfile  -t intellifim-correlator:dev .
docker build -f anomaly/Dockerfile     -t intellifim-anomaly-detector:dev .
docker build -f policy/Dockerfile      -t intellifim-policy:dev .
docker build -f orchestrator/Dockerfile -t intellifim-orchestrator:dev .
docker build -f auth_backend/Dockerfile -t intellifim-auth-backend:dev .
docker build -f ../chronos-ai-guard/Dockerfile --target dev \
    -t chronos-ai-guard:dev ../chronos-ai-guard

./scripts/init-secrets.sh

docker compose --env-file .env.dataplane up -d
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 120
```

Verify all 10 DoD items (each numbered; the last one is the new admin-console smoke):

```bash
# DoD #1: 23 services Up
docker compose --env-file .env.dataplane ps

# DoD #2-#3: FIM + zeek on events.normalized
echo "smoke-final-$(date +%s)" > monitored/smoke.txt
sleep 30
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic events.normalized \
    --from-beginning --max-messages 200 --timeout-ms 30000 > /tmp/normalized.txt 2>/dev/null || true
echo "normalized: $(wc -l < /tmp/normalized.txt) lines  wazuh.fim: $(grep -c '\"source\":\"wazuh.fim\"' /tmp/normalized.txt)  zeek: $(grep -c '\"source\":\"zeek' /tmp/normalized.txt)"

# DoD #4: pcap replay
./scripts/replay-pcap.sh pcaps/http_get_basic.pcap
sleep 10

# DoD #5: unit tests (6 pytest passes + Rego)
cd /home/aditya/Documents/IntelliFIM
source .venv/bin/activate
pytest --import-mode=importlib data-plane/schemas/tests data-plane/normalizers/tests 2>&1 | tail -1
pytest --import-mode=importlib data-plane/correlator/tests 2>&1 | tail -1
pytest --import-mode=importlib data-plane/anomaly/tests 2>&1 | tail -1
pytest --import-mode=importlib data-plane/policy/tests 2>&1 | tail -1
pytest --import-mode=importlib data-plane/orchestrator/tests 2>&1 | tail -1
pytest --import-mode=importlib data-plane/auth_backend/tests 2>&1 | tail -1
docker run --rm -v /home/aditya/Documents/IntelliFIM/data-plane/policy/policies:/p \
    openpolicyagent/opa:latest test /p 2>&1 | tail -1
# Expected: 70 + 20 + 24 + 26 + 45 + 19 + 5 Rego = 209 total

# DoD #6-#9: correlations, scored, threat.scores + approve-pending.py
cd /home/aditya/Documents/IntelliFIM/data-plane
./scripts/seed-test-traffic.sh
sleep 60
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic events.correlated \
    --from-beginning --max-messages 5 --timeout-ms 30000 > /tmp/correlated.txt 2>/dev/null || true
echo "correlated: $(wc -l < /tmp/correlated.txt) lines"
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic events.scored \
    --from-beginning --max-messages 10 --timeout-ms 30000 > /tmp/scored.txt 2>/dev/null || true
echo "scored: $(wc -l < /tmp/scored.txt) lines"
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic threat.scores \
    --from-beginning --max-messages 10 --timeout-ms 30000 > /tmp/threat.txt 2>/dev/null || true
echo "threat: $(wc -l < /tmp/threat.txt) lines  Redis ZCARD: $(docker exec redis redis-cli ZCARD threat_score:host:001)"
ADMIN_EMAIL="$(grep ^ADMIN_EMAIL= .env.dataplane | cut -d= -f2)" \
    ADMIN_PASSWORD="$(grep ^ADMIN_PASSWORD= .env.dataplane | cut -d= -f2)" \
    python /home/aditya/Documents/IntelliFIM/data-plane/scripts/approve-pending.py 2>&1 | tail -15

# DoD #10: admin-console UX (MANUAL — described in README)
echo "--- DoD #10: open http://localhost:5173/auth in browser, log in with admin creds, ---"
echo "--- navigate to Incident Management, click Approve on a PENDING row, verify EXECUTED ---"
```

### Step 3: Cleanup smoke artifacts

```bash
rm -f /home/aditya/Documents/IntelliFIM/data-plane/monitored/smoke.txt
rm -f /tmp/normalized.txt /tmp/correlated.txt /tmp/scored.txt /tmp/threat.txt
find /home/aditya/Documents/IntelliFIM/data-plane/monitored -maxdepth 1 -name 'seed-*' -type d -exec rm -rf {} + 2>/dev/null
docker compose --env-file .env.dataplane down
```

### Step 4: STAGE — DO NOT COMMIT

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/README.md
```

> Suggested commit: `docs(data-plane): document admin-console + auth-backend; add DoD #10`

### Step 5: User opens PR

```bash
git push -u origin feat/admin-console-v1
gh pr create --title "feat: admin console v1 (auth-backend + JWT-gated orchestrator + React wiring)" --body "$(cat <<'EOF'
## Summary
Implements admin console v1 per [docs/superpowers/specs/2026-05-20-admin-console-v1-design.md](docs/superpowers/specs/2026-05-20-admin-console-v1-design.md).

- New `intellifim-auth-backend` Python package (FastAPI + SQLite + bcrypt + HS256 JWT). Endpoints: `POST /auth/login`, `POST /auth/register`, `GET /auth/me`, `GET /healthz`. Seeds admin from env on first start.
- New `auth-backend` Compose service on port 8000.
- New `admin-console` Compose service running the existing `chronos-ai-guard/` Vite dev server (container port 8080 → host 5173).
- `response-orchestrator` extended with aiohttp middleware that validates HS256 JWT on every request except `/healthz`. POST `/approve` and POST `/reject` require role=admin or analyst; viewer gets 403.
- `chronos-ai-guard/src/pages/IncidentManagement.tsx` rewritten as live "Response Approvals" page (polls `/approvals` every 3s, approve/reject via `useMutation`).
- New `chronos-ai-guard/src/lib/apiClient.ts` for fetch + auth-header injection + 401-handling.
- `chronos-ai-guard/src/contexts/AuthContext.tsx` wired to real auth-backend (was a non-functional stub).
- Other 8 frontend pages tagged with a "Mock data — v2" badge.
- New `data-plane/scripts/init-secrets.sh` (idempotent JWT_SECRET generator).
- `data-plane/scripts/approve-pending.py` updated to log in first and forward the token.
- Stack grows 21 → 23 services.

## Test plan
- [x] All six pytest invocations green: schemas + normalizers (~70) + correlator (20) + anomaly (24) + policy (26) + orchestrator (45) + auth-backend (19) = **~204 Python tests**.
- [x] Rego tests via `opa test data-plane/policy/policies/` = **5 tests pass** (total ~209).
- [x] `approve-pending.py` against a seeded stack (now login-first) returns `state="EXECUTED"`.
- [x] DoD #10 (manual UX smoke): browser login → see PENDING row → click Approve → row flips to EXECUTED within 3s.
- [x] All 10 DoD items in `data-plane/README.md` pass on a fresh checkout.

## v2 backlog (deferred)
- Postgres-backed user store (replaces SQLite)
- Refresh tokens, password reset, email verification, rate limiting on /login, account lockout
- RS256 + key rotation (replaces HS256 shared secret)
- httpOnly cookie storage + CSRF protection (replaces localStorage)
- OIDC / Keycloak (replaces in-house auth-backend)
- Admin-only `/auth/register`
- Per-page wiring for the other 8 mock pages
- vitest + react-testing-library + a few component / integration tests
- CORS hardening
- Frontend prod build wired into Compose (uses dev target in v1)
- WebSocket / SSE push from orchestrator → admin-console
- Live tail of Kafka topics in the console (needs Kafka→SSE bridge)
- Audit log of login / approve / reject events (couples with response.events from #5 v2)
- Per-user theme + i18n persistence
- Role enforcement on SYSTEM-LEVEL settings UI
- Healthcheck + resource limits on auth-backend and admin-console

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review (run by plan author)

**1. Spec coverage**

| Spec section | Implementing task(s) |
|---|---|
| §1 Purpose | Tasks 1-13 collectively |
| §2 Scope (walking skeleton + real auth) | Reflected in plan opening; each piece is covered by a task |
| §3 Out of scope | Verified: no task implements Postgres / refresh tokens / Keycloak / etc. |
| §4 Architecture overview | Tasks 6 (auth-backend Dockerfile), 10 (compose wiring), 13 (final smoke) |
| §5 auth-backend | Tasks 1-6 (bootstrap, config, store, jwt, api, entry-point/Dockerfile) |
| §6 orchestrator modifications | Tasks 7-8 (auth.py + wire) |
| §7 chronos-ai-guard modifications | Tasks 11-12 (apiClient + AuthContext, then IncidentManagement + badges) |
| §8 JWT_SECRET management | Task 9 (init-secrets.sh + .env.dataplane.example) |
| §9 approve-pending.py modification | Task 10 (combined with compose wiring) |
| §10 DoD (10 items, item #10 new) | Task 13 verifies all 10 |
| §11 Test budget | Task 13's pytest invocations exercise the full ~209-test budget |
| §12 Patterns reused | Consistent throughout (dataclass config, asyncio.Lock store, range pins, AwareDatetime, nested try/finally) |
| §13 New patterns introduced | FastAPI (Task 5), shared JWT_SECRET (Tasks 6-9), aiohttp middleware (Task 7), browser-facing port (Task 10), React wiring (Tasks 11-12), env-file secret bootstrap (Task 9) |
| §14 v2 deferrals | Listed in PR body (Task 13 Step 5) |

**2. No placeholders**

No "TBD", "implement later", "add error handling", or skeleton-only steps. Every code block is complete and copy-pasteable.

**3. Type / method consistency**

- `AuthBackendConfig` fields `db_path, api_host, api_port, jwt_secret, jwt_ttl_seconds, cors_origins, admin_username, admin_email, admin_password` — Tasks 2, 6, 10.
- `UsersStore` methods `create_user, get_by_email, get_by_id, admin_exists, verify_password, aclose` — Tasks 3, 5, 6.
- `DuplicateUserError` — Tasks 3, 5.
- `UserRow` fields `id (UUID), username, email, password_hash, role, created_at` — Tasks 3, 5.
- `jwt_helper.encode(user_id, username, email, role, secret, ttl_seconds, now)` and `decode(token, secret, now)` — Tasks 4, 5.
- `JwtError` — Tasks 4, 5.
- FastAPI `build_app(store, jwt_secret, jwt_ttl_seconds, cors_origins, now)` — Tasks 5, 6.
- `seed_admin_if_missing(store, username, email, password, now)` — Tasks 5, 6.
- `orchestrator.auth.Principal` fields `user_id (UUID), username, role` — Tasks 7, 8.
- `orchestrator.auth.AuthError(status, message)` — Tasks 7, 8.
- `orchestrator.auth.decode_token(token, secret, now)` — Tasks 7, 8 (test uses).
- `orchestrator.auth.make_auth_middleware(secret, now)` — Tasks 7, 8 (mounted in api.py).
- `OrchestratorConfig.jwt_secret` — Tasks 8, 10.
- `build_api(store, wazuh, jwt_secret, now)` — Tasks 8, 10.
- Frontend `apiClient.ts` exports `AUTH_API_URL, ORCH_API_URL, getToken, clearSession, apiFetch` — Tasks 11, 12.
- `AuthContext` exports `useAuth, AuthProvider, UserRole, User` — Tasks 11, 12.
- Env vars consistent across compose + scripts: `JWT_SECRET, ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD, VITE_AUTH_API_URL, VITE_ORCHESTRATOR_API_URL` — Tasks 9, 10, 12.

All consistent.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-05-20-admin-console-v1.md`.** Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, two-stage review between tasks (spec + code quality), user commits at each boundary. Same proven pattern from sub-projects #1–#5.

**2. Inline Execution** — Tasks in this session via `superpowers:executing-plans`, batch with checkpoints.

When ready: commit this plan to main alongside the spec, create branch `feat/admin-console-v1` off main, then start dispatching Task 1.
