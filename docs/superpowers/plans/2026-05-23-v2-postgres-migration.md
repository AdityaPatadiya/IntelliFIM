# Postgres Migration (v2-1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace SQLite in auth-backend (`users.db`), response-orchestrator (`approvals.db`), and reporting (`reporting.db` + PDF metadata) with a single Postgres 16 instance hosting 3 isolated databases. The 3 service-stores keep their existing class shape + method signatures intact — only the transport (`aiosqlite` → `asyncpg`) changes.

**Architecture:** New `postgres:16-alpine` Compose service with a one-shot init shell script that creates 3 service users + 3 databases on first boot. Each service rewrites its `store.py` to use `asyncpg.create_pool()` instead of `aiosqlite.connect()`. Test infrastructure swaps `tmp_path` SQLite fixtures for `testcontainers-python` Postgres fixtures (session-scoped container + per-test random database). No data migration — fresh-start; auth-backend re-seeds admin user from env on first boot. Stack grows 27 → 28 services. Test counts unchanged (~290 total).

**Tech Stack:** Python 3.12, `asyncpg>=0.29,<0.31`, `testcontainers[postgres]>=4.0,<5`, `postgres:16-alpine`. pytest + existing service test harnesses. Removes `aiosqlite` from 3 services. Hand-rolled `CREATE TABLE IF NOT EXISTS` for schema management (no alembic in v2-1).

**Reference spec:** [`docs/superpowers/specs/2026-05-23-v2-postgres-migration-design.md`](../specs/2026-05-23-v2-postgres-migration-design.md)

**Reference patterns:**
- `data-plane/auth_backend/src/auth_backend/store.py` — v1 `UsersStore` (aiosqlite + asyncio.Lock + idempotent `init_schema()`). All 3 stores follow this shape; we keep the shape, swap the driver.
- `data-plane/orchestrator/src/orchestrator/store.py` — v1 `ApprovalStore` with partial index (`WHERE state = 'PENDING'`). Postgres supports this identically.
- `data-plane/reporting/src/reporting/store.py` — v1 `ReportingStore` with `_to_utc_iso(dt)` helper (REMOVED in v2 — asyncpg handles `TIMESTAMPTZ` natively).
- `data-plane/scripts/init-secrets.sh` — v1 idempotent JWT_SECRET generator pattern; extended in this plan to also generate 4 Postgres passwords.

**Branch:** Create `feat/v2-postgres-migration` off `main` before Task 0.

---

## File Map

```
data-plane/
├── postgres/                                ← NEW
│   └── init.sh                              (3 users + 3 databases; runs once on first boot)
├── scripts/
│   ├── check-postgres.sh                    (NEW; verification smoke)
│   └── init-secrets.sh                      (MODIFIED; appends Postgres password generation)
├── docker-compose.yml                       (MODIFIED; +postgres service, +postgres_data volume, +DATABASE_URL on 3 services, -2 volumes)
├── .env.dataplane.example                   (MODIFIED; +4 blank Postgres password lines)
├── README.md                                (MODIFIED; document Postgres + cleanup steps)
│
├── auth_backend/
│   ├── pyproject.toml                       (MODIFIED; +asyncpg, +testcontainers[postgres], -aiosqlite)
│   ├── src/auth_backend/
│   │   ├── config.py                        (MODIFIED; +database_url field, -db_path field)
│   │   ├── store.py                         (REWRITTEN; aiosqlite → asyncpg)
│   │   └── __main__.py                      (MODIFIED; pass database_url instead of db_path)
│   └── tests/
│       ├── conftest.py                      (MODIFIED; replace tmp_db_path with pg_pool fixture)
│       └── test_*.py                        (MINIMAL CHANGES; pg_pool fixture replaces db_path arg)
│
├── orchestrator/                            (same shape of changes)
│   ├── pyproject.toml
│   ├── src/orchestrator/{config.py, store.py, __main__.py}
│   └── tests/{conftest.py, test_*.py}
│
└── reporting/                               (same shape of changes; reporting_data volume kept for PDFs)
    ├── pyproject.toml
    ├── src/reporting/{config.py, store.py, __main__.py}
    └── tests/{conftest.py, test_*.py}
```

**Test totals after this sub-project:** unchanged from v1 final = **~290 Python + 5 Rego** (~285 + 12 obs + 5 Rego = ~290). Each service's suite passes the same test count.

---

## Standing Rules (carried from v1)

- **NEVER run `git commit` yourself.** Stage with `git add <specific paths>` only.
- **Never** `docker compose down -v` unless explicitly in DoD #2 (wipes Wazuh state).
- **Never** `git add .` or `git add -A`. Stage only files the task lists.
- **Never** `--no-verify` or bypass hooks/signing.
- Use the `[dev]` extra in pyproject.toml (NOT `[test]`) — matches every other service.
- Cross-package pins are RANGES (`>=X,<Y`), never `==`.
- Bash tool calls don't persist `cwd` between invocations — use absolute paths or `git -C <repo-root>`.
- Use `python3 -m venv .venv` (not `python`) — host machines may not have `python` on PATH.

---

## Task 0: Postgres bootstrap (service + init script + secrets)

**Files:**
- Create: `data-plane/postgres/init.sh`
- Modify: `data-plane/scripts/init-secrets.sh` (append Postgres password generation)
- Modify: `data-plane/.env.dataplane.example` (add 4 blank password lines)

- [ ] **Step 1: Create the branch + stage spec+plan**

```bash
git checkout main
git pull --ff-only
git checkout -b feat/v2-postgres-migration
git -C /home/aditya/Documents/IntelliFIM add \
    docs/superpowers/specs/2026-05-23-v2-postgres-migration-design.md \
    docs/superpowers/plans/2026-05-23-v2-postgres-migration.md
git -C /home/aditya/Documents/IntelliFIM status --short
```

- [ ] **Step 2: Create the postgres init shell script**

`data-plane/postgres/init.sh`:

```bash
#!/usr/bin/env bash
# data-plane/postgres/init.sh
# Runs ONCE on first postgres boot when $PGDATA is empty.
# Creates the 3 service users + 3 databases for IntelliFIM v2 Postgres.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER auth         WITH PASSWORD '${POSTGRES_AUTH_PASSWORD}';
    CREATE USER orchestrator WITH PASSWORD '${POSTGRES_ORCH_PASSWORD}';
    CREATE USER reporting    WITH PASSWORD '${POSTGRES_REPORTING_PASSWORD}';

    CREATE DATABASE auth_backend OWNER auth;
    CREATE DATABASE orchestrator OWNER orchestrator;
    CREATE DATABASE reporting    OWNER reporting;
EOSQL
```

Make it executable:
```bash
chmod +x /home/aditya/Documents/IntelliFIM/data-plane/postgres/init.sh
```

- [ ] **Step 3: Extend `init-secrets.sh` to generate the 4 Postgres passwords**

Find `data-plane/scripts/init-secrets.sh`. After the existing `JWT_SECRET written to ${ENV_FILE}` echo (last line of file), append:

```bash

# v2: 4 Postgres passwords (root + 3 service users)
for var in POSTGRES_ROOT_PASSWORD POSTGRES_AUTH_PASSWORD POSTGRES_ORCH_PASSWORD POSTGRES_REPORTING_PASSWORD; do
    if grep -q "^${var}=.\+" "$ENV_FILE"; then
        echo "${var} already set in ${ENV_FILE}; skipping."
        continue
    fi
    PG_SECRET=$(openssl rand -base64 24 | tr -d '\n')
    if grep -q "^${var}=$" "$ENV_FILE"; then
        sed -i "s|^${var}=$|${var}=${PG_SECRET}|" "$ENV_FILE"
    else
        echo "${var}=${PG_SECRET}" >> "$ENV_FILE"
    fi
    echo "${var} written to ${ENV_FILE}"
done
```

- [ ] **Step 4: Add the 4 blank password lines to `.env.dataplane.example`**

Find `data-plane/.env.dataplane.example`. After the existing `JWT_SECRET=` line, add:

```
# Postgres passwords (v2). Generated by ./scripts/init-secrets.sh
POSTGRES_ROOT_PASSWORD=
POSTGRES_AUTH_PASSWORD=
POSTGRES_ORCH_PASSWORD=
POSTGRES_REPORTING_PASSWORD=
```

- [ ] **Step 5: Smoke `init-secrets.sh`**

Test the idempotent + fresh-start behaviors:

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane

# Save current .env.dataplane
cp .env.dataplane /tmp/env-backup-$(date +%s)

# Append 4 blank Postgres lines manually if not already present (simulates fresh checkout)
grep -q "^POSTGRES_ROOT_PASSWORD" .env.dataplane || echo "POSTGRES_ROOT_PASSWORD=" >> .env.dataplane
grep -q "^POSTGRES_AUTH_PASSWORD" .env.dataplane || echo "POSTGRES_AUTH_PASSWORD=" >> .env.dataplane
grep -q "^POSTGRES_ORCH_PASSWORD" .env.dataplane || echo "POSTGRES_ORCH_PASSWORD=" >> .env.dataplane
grep -q "^POSTGRES_REPORTING_PASSWORD" .env.dataplane || echo "POSTGRES_REPORTING_PASSWORD=" >> .env.dataplane

./scripts/init-secrets.sh
grep "^POSTGRES_" .env.dataplane
```

Expected: 4 lines each shows a non-empty base64-ish value. Re-run should be a no-op (`already set; skipping`).

- [ ] **Step 6: Stage**

```bash
git -C /home/aditya/Documents/IntelliFIM add \
    data-plane/postgres/init.sh \
    data-plane/scripts/init-secrets.sh \
    data-plane/.env.dataplane.example
git -C /home/aditya/Documents/IntelliFIM status --short
```

DO NOT stage `data-plane/.env.dataplane` — that file is per-user and gitignored.

Suggested commit message: `feat(v2-postgres): add postgres init.sh + extend init-secrets.sh for 4 db passwords`

---

## Task 1: auth-backend migration to asyncpg

**Files:**
- Modify: `data-plane/auth_backend/pyproject.toml` (deps swap)
- Modify: `data-plane/auth_backend/src/auth_backend/config.py` (db_path → database_url)
- Modify: `data-plane/auth_backend/src/auth_backend/store.py` (REWRITE; aiosqlite → asyncpg)
- Modify: `data-plane/auth_backend/src/auth_backend/__main__.py` (pass database_url, not db_path)
- Modify: `data-plane/auth_backend/tests/conftest.py` (pg_pool fixture replaces tmp_db_path)
- Modify: existing `tests/test_*.py` files as needed for the new fixture

- [ ] **Step 1: Read the existing auth-backend code to understand the shape**

```bash
cat /home/aditya/Documents/IntelliFIM/data-plane/auth_backend/src/auth_backend/store.py
cat /home/aditya/Documents/IntelliFIM/data-plane/auth_backend/src/auth_backend/config.py
cat /home/aditya/Documents/IntelliFIM/data-plane/auth_backend/src/auth_backend/__main__.py
cat /home/aditya/Documents/IntelliFIM/data-plane/auth_backend/tests/conftest.py
ls /home/aditya/Documents/IntelliFIM/data-plane/auth_backend/tests/
```

Note: `UsersStore.create_user(...)` signature, the existing `init_schema()` / `aclose()` pattern, the `_row_to_user()` helper, and which test fixtures consume the store (likely `tmp_db_path` / `store` / `deps`).

- [ ] **Step 2: Update `pyproject.toml`**

In `data-plane/auth_backend/pyproject.toml`, inside the `dependencies` list:
- REMOVE: `"aiosqlite>=0.20,<0.22",`
- ADD: `"asyncpg>=0.29,<0.31",`

Inside the `[project.optional-dependencies]` `dev` list, ADD:
```toml
    "testcontainers[postgres]>=4.0,<5",
```

- [ ] **Step 3: Update `config.py`**

Find the `AuthBackendConfig` dataclass. Replace the `db_path: str` field with `database_url: str`.

In `AuthBackendConfig.from_env()`:
- REMOVE: `db_path=os.environ.get("DB_PATH", "/data/users.db"),`
- ADD: validation that `DATABASE_URL` env var is set (fail-fast `AuthBackendConfigError(...)` if missing); the `.from_env()` body should treat it like the other required vars (JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD).
- ADD: `database_url=os.environ["DATABASE_URL"],` to the returned dataclass.

- [ ] **Step 4: Rewrite `store.py`**

Replace the entire contents of `data-plane/auth_backend/src/auth_backend/store.py` with:

```python
"""Postgres-backed users store (v2).

asyncpg connection pool + native UUID / TIMESTAMPTZ types. The class shape +
method signatures match the v1 aiosqlite version exactly — callers don't
notice the swap.

Pattern: asyncpg.create_pool(minsize=1, maxsize=8). Postgres handles
concurrent writes natively; no application-level asyncio.Lock needed.
`init_schema()` is idempotent (CREATE TABLE IF NOT EXISTS). `aclose()`
closes the pool.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

import asyncpg
from passlib.context import CryptContext


logger = logging.getLogger(__name__)

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


_CREATE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ
);
"""
_IDX_USERS_EMAIL = "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);"


class DuplicateUserError(ValueError):
    """Raised when a username or email collides."""


@dataclass(frozen=True)
class UserRow:
    id: UUID
    username: str
    email: str
    password_hash: str
    role: str
    created_at: datetime
    last_login_at: Optional[datetime]


def _row_to_user(record) -> UserRow:
    return UserRow(
        id=record["id"],
        username=record["username"],
        email=record["email"],
        password_hash=record["password_hash"],
        role=record["role"],
        created_at=record["created_at"],
        last_login_at=record["last_login_at"],
    )


class UsersStore:
    def __init__(self, database_url: str | None = None, *, pool: asyncpg.Pool | None = None) -> None:
        # Either `database_url` (production) or `pool` (tests with testcontainers fixture).
        self._database_url = database_url
        self._pool: asyncpg.Pool | None = pool
        self._pool_owned = pool is None   # if we created it, we close it

    async def init_schema(self) -> None:
        if self._pool is None:
            assert self._database_url is not None, "database_url required when pool not provided"
            self._pool = await asyncpg.create_pool(self._database_url, min_size=1, max_size=8)
        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_USERS)
            await conn.execute(_IDX_USERS_EMAIL)

    async def aclose(self) -> None:
        if self._pool is not None and self._pool_owned:
            await self._pool.close()
            self._pool = None

    # --- queries ---

    async def get_by_email(self, email: str) -> UserRow | None:
        assert self._pool is not None, "init_schema() not called"
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
        return _row_to_user(row) if row else None

    async def get_by_id(self, user_id: UUID) -> UserRow | None:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
        return _row_to_user(row) if row else None

    async def create_user(
        self,
        *,
        username: str,
        email: str,
        password: str,
        role: str,
        now: datetime,
    ) -> UserRow:
        assert self._pool is not None
        # Pre-check for duplicates (clearer error than the unique-violation race)
        existing = await self.get_by_email(email)
        if existing is not None:
            raise DuplicateUserError(f"email already exists: {email}")
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO users(id, username, email, password_hash, role, created_at, last_login_at)
                VALUES($1, $2, $3, $4, $5, $6, NULL)
                RETURNING *
                """,
                uuid4(),
                username,
                email,
                _pwd.hash(password),
                role,
                now,
            )
        return _row_to_user(row)

    async def verify_password(self, user: UserRow, password: str) -> bool:
        return _pwd.verify(password, user.password_hash)

    async def update_last_login(self, user_id: UUID, *, now: datetime) -> None:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            await conn.execute("UPDATE users SET last_login_at = $1 WHERE id = $2", now, user_id)
```

> **IMPORTANT — method signatures:** keep `create_user`, `get_by_email`, `get_by_id`, `update_last_login`, `verify_password` with the EXACT same names + kwargs the existing `api.py` and `__main__.py` already call. If the v1 store has additional methods (`get_by_username`, etc.), keep them too — read v1's `store.py` first and preserve every external entry point.

> **password hashing import:** v1 used passlib + bcrypt 4.0.x (pinned via the explicit `bcrypt>=4.0,<4.1` to avoid the passlib 4.1+ incompatibility). Keep that pin in `pyproject.toml`.

- [ ] **Step 5: Update `__main__.py`**

Find where `UsersStore(...)` is instantiated. Replace:
```python
store = UsersStore(db_path=cfg.db_path)
```
with:
```python
store = UsersStore(database_url=cfg.database_url)
```

Everything else in `__main__.py` stays the same.

- [ ] **Step 6: Update `tests/conftest.py`**

Read the existing fixture first:
```bash
cat /home/aditya/Documents/IntelliFIM/data-plane/auth_backend/tests/conftest.py
```

Replace the `tmp_db_path` (or equivalent SQLite-based) fixture with the testcontainers pattern. Append/modify to match this canonical shape:

```python
import uuid as _uuid

import asyncpg
import pytest
import pytest_asyncio
from testcontainers.postgres import PostgresContainer


@pytest.fixture(scope="session")
def pg_container():
    """Spin up a Postgres container once per test session."""
    with PostgresContainer("postgres:16-alpine") as pg:
        yield pg


def _root_url(pg_container) -> str:
    """Extract the bare asyncpg-compatible URL from the testcontainers container."""
    raw = pg_container.get_connection_url(driver=None)
    # testcontainers may return postgresql+psycopg2://... — strip dialect for asyncpg
    return raw.replace("postgresql+psycopg2://", "postgresql://").replace("postgresql+asyncpg://", "postgresql://")


@pytest_asyncio.fixture
async def pg_pool(pg_container):
    """Per-test pool against a fresh database (random name)."""
    db_name = f"test_{_uuid.uuid4().hex[:12]}"
    root_url = _root_url(pg_container)

    # Create per-test database via the admin connection
    root_conn = await asyncpg.connect(root_url)
    try:
        await root_conn.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        await root_conn.close()

    # Per-test pool against the new db
    db_url = root_url.rsplit("/", 1)[0] + f"/{db_name}"
    pool = await asyncpg.create_pool(db_url, min_size=1, max_size=4)
    yield pool
    await pool.close()
```

> **IMPORTANT — fixture compatibility:** if the existing tests use a fixture named `store` that took `tmp_db_path` as an argument, rewrite that fixture to take `pg_pool` instead:

```python
@pytest_asyncio.fixture
async def store(pg_pool):
    s = UsersStore(pool=pg_pool)
    await s.init_schema()
    yield s
    await s.aclose()
```

Adapt this exactly to whatever fixture names exist in the current conftest.

> If there's a `deps` fixture returning `(store, jwt_secret)` (from the metrics test in v1), keep that shape — just have it consume `pg_pool` instead of `tmp_db_path` internally.

- [ ] **Step 7: Update any test files that call `UsersStore(...)` directly**

Search:
```bash
grep -rn "UsersStore(" /home/aditya/Documents/IntelliFIM/data-plane/auth_backend/tests/
```

For every call that passes `db_path=...`, replace with `pool=pg_pool` (where `pg_pool` is a fixture). Most calls should already go through the `store` conftest fixture; only direct instantiations in test bodies need touching.

- [ ] **Step 8: Verify the test suite passes against Postgres**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane/auth_backend
python3 -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest -v
```

Expected: **21 passed** (same count as v1).

If the test container fails to start (most likely error: "Cannot connect to Docker daemon"), the implementer needs Docker running. If asyncpg complains about UUID/datetime serialization, check that all queries use native types (no `str(uuid)`, no `dt.isoformat()`) — that was the most common v1→v2 translation miss.

- [ ] **Step 9: Cleanup + stage**

```bash
deactivate
rm -rf .venv
rm -rf /home/aditya/Documents/IntelliFIM/data-plane/schemas/build/
git -C /home/aditya/Documents/IntelliFIM add \
    data-plane/auth_backend/pyproject.toml \
    data-plane/auth_backend/src/auth_backend/config.py \
    data-plane/auth_backend/src/auth_backend/store.py \
    data-plane/auth_backend/src/auth_backend/__main__.py \
    data-plane/auth_backend/tests/conftest.py
# Stage any test files the implementer touched:
git -C /home/aditya/Documents/IntelliFIM add data-plane/auth_backend/tests/test_*.py 2>/dev/null || true
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(v2-postgres): migrate auth-backend store from aiosqlite to asyncpg`

---

## Task 2: response-orchestrator migration to asyncpg

**Files:**
- Modify: `data-plane/orchestrator/pyproject.toml` (deps swap)
- Modify: `data-plane/orchestrator/src/orchestrator/config.py` (db_path → database_url)
- Modify: `data-plane/orchestrator/src/orchestrator/store.py` (REWRITE; aiosqlite → asyncpg)
- Modify: `data-plane/orchestrator/src/orchestrator/__main__.py` (pass database_url, not db_path)
- Modify: `data-plane/orchestrator/tests/conftest.py` (pg_pool fixture)
- Modify: tests using `ApprovalStore(...)` directly

- [ ] **Step 1: Read existing orchestrator code**

```bash
cat /home/aditya/Documents/IntelliFIM/data-plane/orchestrator/src/orchestrator/store.py
cat /home/aditya/Documents/IntelliFIM/data-plane/orchestrator/src/orchestrator/config.py
cat /home/aditya/Documents/IntelliFIM/data-plane/orchestrator/src/orchestrator/__main__.py
cat /home/aditya/Documents/IntelliFIM/data-plane/orchestrator/tests/conftest.py
ls /home/aditya/Documents/IntelliFIM/data-plane/orchestrator/tests/
```

Note: `ApprovalStore` methods (likely `create_approval`, `get_approval`, `list_approvals`, `transition_state`, etc.), the partial index `idx_approvals_host_pending WHERE state = 'PENDING'`, and any v1 race-detection (`UPDATE ... WHERE state = ?` + rowcount check).

- [ ] **Step 2: Update `pyproject.toml`**

In `data-plane/orchestrator/pyproject.toml`:
- REMOVE: `"aiosqlite>=0.20,<0.22",`
- ADD to dependencies: `"asyncpg>=0.29,<0.31",`
- ADD to `[project.optional-dependencies] dev`: `"testcontainers[postgres]>=4.0,<5",`

- [ ] **Step 3: Update `config.py`**

Replace the `db_path: str` field on `OrchestratorConfig` with `database_url: str`. In `OrchestratorConfig.from_env()`:
- REMOVE: any `DB_PATH` env reading.
- ADD: `database_url=os.environ["DATABASE_URL"],` (with fail-fast check matching the `jwt_secret` pattern already in the file).

- [ ] **Step 4: Rewrite `store.py`**

Replace `data-plane/orchestrator/src/orchestrator/store.py` with:

```python
"""Postgres-backed approval-request store (v2).

asyncpg pool + native UUID / TIMESTAMPTZ types. External class shape +
method signatures match the v1 aiosqlite version.

The partial index `idx_approvals_host_pending WHERE state = 'PENDING'`
enforces the per-host PENDING-singleton guarantee. State transitions use
`UPDATE ... WHERE id = ? AND state = ?` + rowcount check (same as v1).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

import asyncpg


logger = logging.getLogger(__name__)


_CREATE_APPROVALS = """
CREATE TABLE IF NOT EXISTS approvals (
    id            UUID PRIMARY KEY,
    host_id       TEXT NOT NULL,
    priority      TEXT NOT NULL,
    score         DOUBLE PRECISION NOT NULL,
    last_reason   TEXT NOT NULL,
    state         TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    decided_at    TIMESTAMPTZ,
    executed_at   TIMESTAMPTZ,
    decided_by    TEXT,
    error_message TEXT
);
"""

_IDX_APPROVALS_HOST_PENDING = """
CREATE INDEX IF NOT EXISTS idx_approvals_host_pending
    ON approvals(host_id) WHERE state = 'PENDING';
"""


@dataclass(frozen=True)
class ApprovalRow:
    id: UUID
    host_id: str
    priority: str
    score: float
    last_reason: str
    state: str
    created_at: datetime
    decided_at: Optional[datetime]
    executed_at: Optional[datetime]
    decided_by: Optional[str]
    error_message: Optional[str]


def _row(record) -> ApprovalRow:
    return ApprovalRow(
        id=record["id"],
        host_id=record["host_id"],
        priority=record["priority"],
        score=float(record["score"]),
        last_reason=record["last_reason"],
        state=record["state"],
        created_at=record["created_at"],
        decided_at=record["decided_at"],
        executed_at=record["executed_at"],
        decided_by=record["decided_by"],
        error_message=record["error_message"],
    )


class ApprovalStore:
    def __init__(self, database_url: str | None = None, *, pool: asyncpg.Pool | None = None) -> None:
        self._database_url = database_url
        self._pool: asyncpg.Pool | None = pool
        self._pool_owned = pool is None

    async def init_schema(self) -> None:
        if self._pool is None:
            assert self._database_url is not None
            self._pool = await asyncpg.create_pool(self._database_url, min_size=1, max_size=8)
        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_APPROVALS)
            await conn.execute(_IDX_APPROVALS_HOST_PENDING)

    async def aclose(self) -> None:
        if self._pool is not None and self._pool_owned:
            await self._pool.close()
            self._pool = None

    # The full method surface — adapt these to match v1's API exactly.
    # Read v1 store.py first and preserve every public method's signature.

    async def insert_if_no_pending(
        self,
        *,
        id: UUID,
        host_id: str,
        priority: str,
        score: float,
        last_reason: str,
        created_at: datetime,
    ) -> ApprovalRow | None:
        """Insert a new PENDING approval; return None if host already has PENDING."""
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            # Use INSERT ... ON CONFLICT DO NOTHING via the partial index?
            # Simpler: check then insert in a transaction.
            async with conn.transaction():
                existing = await conn.fetchval(
                    "SELECT id FROM approvals WHERE host_id = $1 AND state = 'PENDING'",
                    host_id,
                )
                if existing is not None:
                    return None
                row = await conn.fetchrow(
                    """
                    INSERT INTO approvals(id, host_id, priority, score, last_reason, state, created_at)
                    VALUES($1, $2, $3, $4, $5, 'PENDING', $6)
                    RETURNING *
                    """,
                    id, host_id, priority, score, last_reason, created_at,
                )
        return _row(row)

    async def get(self, id: UUID) -> ApprovalRow | None:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM approvals WHERE id = $1", id)
        return _row(row) if row else None

    async def list(self, *, state: str | None = None) -> list[ApprovalRow]:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            if state:
                rows = await conn.fetch("SELECT * FROM approvals WHERE state = $1 ORDER BY created_at DESC", state)
            else:
                rows = await conn.fetch("SELECT * FROM approvals ORDER BY created_at DESC")
        return [_row(r) for r in rows]

    async def transition_state(
        self,
        *,
        id: UUID,
        from_state: str,
        to_state: str,
        now: datetime,
        decided_by: str | None = None,
        executed_at: datetime | None = None,
        error_message: str | None = None,
    ) -> bool:
        """Atomic state transition. Returns True if the row was in `from_state` and is now in `to_state`."""
        assert self._pool is not None
        # Build the SET clause based on which fields are provided
        set_fields = ["state = $1"]
        params: list = [to_state]
        idx = 2
        if decided_by is not None:
            set_fields.append(f"decided_by = ${idx}")
            params.append(decided_by)
            idx += 1
            set_fields.append(f"decided_at = ${idx}")
            params.append(now)
            idx += 1
        if executed_at is not None:
            set_fields.append(f"executed_at = ${idx}")
            params.append(executed_at)
            idx += 1
        if error_message is not None:
            set_fields.append(f"error_message = ${idx}")
            params.append(error_message)
            idx += 1
        # Where-clause params
        params.append(id)         # ${idx}
        params.append(from_state) # ${idx+1}

        sql = (
            f"UPDATE approvals SET {', '.join(set_fields)} "
            f"WHERE id = ${idx} AND state = ${idx+1}"
        )
        async with self._pool.acquire() as conn:
            result = await conn.execute(sql, *params)
        # asyncpg's execute returns "UPDATE n" — parse rowcount
        rowcount = int(result.split()[-1]) if result.startswith("UPDATE ") else 0
        return rowcount == 1
```

> **IMPORTANT — preserve v1's exact public method set.** Read v1 `store.py` carefully. v1 may have additional methods like `update_executed`, `update_failed`, `mark_executed`, etc. Translate each one to asyncpg, preserve the kwarg names, preserve the return shape. The `transition_state` shown above is a generic template; v1 likely has more specific helpers.

> **`INSERT ... ON CONFLICT DO NOTHING` alternative:** Postgres-native way to enforce the per-host PENDING singleton would be a partial UNIQUE index + `ON CONFLICT`. The above pattern (transaction + check-then-insert) preserves v1 semantics exactly. The native variant is a v2 cleanup, not required here.

- [ ] **Step 5: Update `__main__.py`**

Replace:
```python
store = ApprovalStore(db_path=cfg.db_path)
```
with:
```python
store = ApprovalStore(database_url=cfg.database_url)
```

- [ ] **Step 6: Update `tests/conftest.py`**

Read existing conftest:
```bash
cat /home/aditya/Documents/IntelliFIM/data-plane/orchestrator/tests/conftest.py
```

Add the `pg_container` + `pg_pool` fixtures (same shape as Task 1 Step 6). If the existing conftest defines a `_make_store` helper or a `store` fixture, rewrite it to consume `pg_pool`.

- [ ] **Step 7: Update test files**

```bash
grep -rn "ApprovalStore(" /home/aditya/Documents/IntelliFIM/data-plane/orchestrator/tests/
```

Replace every direct `ApprovalStore(db_path=...)` instantiation with `ApprovalStore(pool=pg_pool)`. Most are likely through the conftest helper.

- [ ] **Step 8: Verify**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane/orchestrator
python3 -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest -v
```

Expected: **48 passed** (same as v1 final).

- [ ] **Step 9: Stage**

```bash
deactivate
rm -rf .venv
rm -rf /home/aditya/Documents/IntelliFIM/data-plane/schemas/build/
git -C /home/aditya/Documents/IntelliFIM add \
    data-plane/orchestrator/pyproject.toml \
    data-plane/orchestrator/src/orchestrator/config.py \
    data-plane/orchestrator/src/orchestrator/store.py \
    data-plane/orchestrator/src/orchestrator/__main__.py \
    data-plane/orchestrator/tests/conftest.py
git -C /home/aditya/Documents/IntelliFIM add data-plane/orchestrator/tests/test_*.py 2>/dev/null || true
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(v2-postgres): migrate response-orchestrator store from aiosqlite to asyncpg`

---

## Task 3: reporting migration to asyncpg

**Files:**
- Modify: `data-plane/reporting/pyproject.toml` (deps swap)
- Modify: `data-plane/reporting/src/reporting/config.py` (db_path → database_url)
- Modify: `data-plane/reporting/src/reporting/store.py` (REWRITE; aiosqlite → asyncpg; remove `_to_utc_iso`)
- Modify: `data-plane/reporting/src/reporting/__main__.py` (pass database_url)
- Modify: `data-plane/reporting/tests/conftest.py` (pg_pool fixture)
- Modify: tests using `ReportingStore(...)` directly

> **Special note:** reporting also writes PDF FILES to `/data/reports/*.pdf`. Those stay on the filesystem (`reporting_data` volume). Only the DB moves to Postgres.

- [ ] **Step 1: Read existing reporting code**

```bash
cat /home/aditya/Documents/IntelliFIM/data-plane/reporting/src/reporting/store.py
cat /home/aditya/Documents/IntelliFIM/data-plane/reporting/src/reporting/config.py
cat /home/aditya/Documents/IntelliFIM/data-plane/reporting/src/reporting/__main__.py
cat /home/aditya/Documents/IntelliFIM/data-plane/reporting/tests/conftest.py
```

Note: `ReportingStore` methods (`insert_score`, `query_scores`, `top_hosts_by_max_score`, `insert_report`, `list_reports`, `get_report`, `delete_report`), the `_to_utc_iso(dt)` helper (REMOVED in v2), and the `reports_dir` property which stays.

- [ ] **Step 2: Update `pyproject.toml`**

In `data-plane/reporting/pyproject.toml`:
- REMOVE: `"aiosqlite>=0.20,<0.22",`
- ADD to dependencies: `"asyncpg>=0.29,<0.31",`
- ADD to `[project.optional-dependencies] dev`: `"testcontainers[postgres]>=4.0,<5",`

- [ ] **Step 3: Update `config.py`**

Replace `db_path: str` field on the reporting config dataclass with `database_url: str`. In `.from_env()`:
- REMOVE: `db_path=os.environ.get("DB_PATH", "/data/reporting.db"),`
- ADD: `database_url=os.environ["DATABASE_URL"],` with fail-fast on missing.

Keep `reports_dir: str` (PDF filesystem path) — that doesn't change.

- [ ] **Step 4: Rewrite `store.py`**

Replace `data-plane/reporting/src/reporting/store.py` with:

```python
"""Postgres-backed reporting store (v2).

Two tables:
- `threat_scores` — append-log populated by the Kafka consumer.
- `reports` — generated-report metadata; PDF bytes live on filesystem (NOT here).

Pattern: asyncpg pool + native UUID/TIMESTAMPTZ types. The v1 `_to_utc_iso(dt)`
helper is REMOVED — asyncpg handles TIMESTAMPTZ natively. External class shape
matches v1.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

import asyncpg


logger = logging.getLogger(__name__)


_CREATE_THREAT_SCORES = """
CREATE TABLE IF NOT EXISTS threat_scores (
    id      BIGSERIAL PRIMARY KEY,
    host_id TEXT NOT NULL,
    score   DOUBLE PRECISION NOT NULL,
    reason  TEXT NOT NULL,
    ts      TIMESTAMPTZ NOT NULL
);
"""
_IDX_THREAT_SCORES_TS = "CREATE INDEX IF NOT EXISTS idx_threat_scores_ts ON threat_scores(ts);"
_IDX_THREAT_SCORES_HOST_TS = (
    "CREATE INDEX IF NOT EXISTS idx_threat_scores_host_ts "
    "ON threat_scores(host_id, ts);"
)

_CREATE_REPORTS = """
CREATE TABLE IF NOT EXISTS reports (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL,
    range_start     TIMESTAMPTZ NOT NULL,
    range_end       TIMESTAMPTZ NOT NULL,
    generated_at    TIMESTAMPTZ NOT NULL,
    generated_by    TEXT NOT NULL,
    pdf_path        TEXT NOT NULL,
    size_bytes      BIGINT NOT NULL,
    approvals_count INTEGER NOT NULL,
    scores_count    INTEGER NOT NULL
);
"""
_IDX_REPORTS_GEN_AT = (
    "CREATE INDEX IF NOT EXISTS idx_reports_generated_at "
    "ON reports(generated_at DESC);"
)


@dataclass(frozen=True)
class ScoreRow:
    host_id: str
    score: float
    reason: str
    ts: datetime


@dataclass(frozen=True)
class ReportRow:
    id: UUID
    name: str
    range_start: datetime
    range_end: datetime
    generated_at: datetime
    generated_by: str
    pdf_path: str
    size_bytes: int
    approvals_count: int
    scores_count: int


class ReportingStore:
    def __init__(
        self,
        database_url: str | None = None,
        reports_dir: str = "/data/reports",
        *,
        pool: asyncpg.Pool | None = None,
    ) -> None:
        self._database_url = database_url
        self._reports_dir = reports_dir
        self._pool: asyncpg.Pool | None = pool
        self._pool_owned = pool is None

    @property
    def reports_dir(self) -> str:
        return self._reports_dir

    async def init_schema(self) -> None:
        if self._pool is None:
            assert self._database_url is not None
            self._pool = await asyncpg.create_pool(self._database_url, min_size=1, max_size=8)
        os.makedirs(self._reports_dir, exist_ok=True)
        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_THREAT_SCORES)
            await conn.execute(_IDX_THREAT_SCORES_TS)
            await conn.execute(_IDX_THREAT_SCORES_HOST_TS)
            await conn.execute(_CREATE_REPORTS)
            await conn.execute(_IDX_REPORTS_GEN_AT)

    async def aclose(self) -> None:
        if self._pool is not None and self._pool_owned:
            await self._pool.close()
            self._pool = None

    # --- threat_scores --------------------------------------------------

    async def insert_score(self, *, host_id: str, score: float, reason: str, ts: datetime) -> None:
        assert self._pool is not None
        if ts.tzinfo is None:
            raise ValueError("naive datetime not allowed; pass tz-aware UTC")
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO threat_scores(host_id, score, reason, ts) VALUES($1, $2, $3, $4)",
                host_id, score, reason, ts,
            )

    async def query_scores(
        self, *, start: datetime, end: datetime, host_id: str | None = None
    ) -> list[ScoreRow]:
        assert self._pool is not None
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("naive datetimes not allowed; pass tz-aware UTC")
        async with self._pool.acquire() as conn:
            if host_id is not None:
                rows = await conn.fetch(
                    "SELECT host_id, score, reason, ts FROM threat_scores "
                    "WHERE ts >= $1 AND ts < $2 AND host_id = $3 ORDER BY ts ASC",
                    start, end, host_id,
                )
            else:
                rows = await conn.fetch(
                    "SELECT host_id, score, reason, ts FROM threat_scores "
                    "WHERE ts >= $1 AND ts < $2 ORDER BY ts ASC",
                    start, end,
                )
        return [ScoreRow(host_id=r["host_id"], score=float(r["score"]), reason=r["reason"], ts=r["ts"]) for r in rows]

    async def top_hosts_by_max_score(
        self, *, start: datetime, end: datetime, limit: int = 10
    ) -> list[tuple[str, float]]:
        assert self._pool is not None
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("naive datetimes not allowed")
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT host_id, MAX(score) AS max_score FROM threat_scores "
                "WHERE ts >= $1 AND ts < $2 "
                "GROUP BY host_id ORDER BY max_score DESC, host_id ASC LIMIT $3",
                start, end, limit,
            )
        return [(r["host_id"], float(r["max_score"])) for r in rows]

    # --- reports --------------------------------------------------------

    async def insert_report(
        self,
        *,
        id: UUID,
        name: str,
        range_start: datetime,
        range_end: datetime,
        generated_at: datetime,
        generated_by: str,
        pdf_path: str,
        size_bytes: int,
        approvals_count: int,
        scores_count: int,
    ) -> None:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO reports(
                    id, name, range_start, range_end, generated_at,
                    generated_by, pdf_path, size_bytes, approvals_count, scores_count
                ) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                """,
                id, name, range_start, range_end, generated_at,
                generated_by, pdf_path, size_bytes, approvals_count, scores_count,
            )

    async def list_reports(self, *, limit: int, offset: int) -> tuple[list[ReportRow], int]:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM reports ORDER BY generated_at DESC LIMIT $1 OFFSET $2",
                limit, offset,
            )
            total = await conn.fetchval("SELECT COUNT(*) FROM reports")
        return [_row_to_report(r) for r in rows], int(total)

    async def get_report(self, id: UUID) -> ReportRow | None:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM reports WHERE id = $1", id)
        return _row_to_report(row) if row else None

    async def delete_report(self, id: UUID) -> bool:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT pdf_path FROM reports WHERE id = $1", id)
            if row is None:
                return False
            pdf_path = row["pdf_path"]
            await conn.execute("DELETE FROM reports WHERE id = $1", id)
        try:
            os.unlink(pdf_path)
        except FileNotFoundError:
            pass   # idempotent — file already gone is fine
        return True


def _row_to_report(record) -> ReportRow:
    return ReportRow(
        id=record["id"],
        name=record["name"],
        range_start=record["range_start"],
        range_end=record["range_end"],
        generated_at=record["generated_at"],
        generated_by=record["generated_by"],
        pdf_path=record["pdf_path"],
        size_bytes=int(record["size_bytes"]),
        approvals_count=int(record["approvals_count"]),
        scores_count=int(record["scores_count"]),
    )
```

> **NOTE:** This changes `insert_report` to take `datetime` instead of the v1 `range_start_iso: str` / `range_end_iso: str` / `generated_at_iso: str` string args. Callers in `api.py` were passing `.isoformat()` strings; v2 callers pass `datetime` objects directly. The `api.py` already has the datetime objects (`body.range_start`, `generated_at = now()`) — it just stops calling `.isoformat()` on them. Verify with `grep -n "insert_report" /home/aditya/Documents/IntelliFIM/data-plane/reporting/src/reporting/api.py` and update the call sites to pass datetimes instead of ISO strings.

> Similarly `ReportRow` fields go from `str` to `datetime`. The api.py's `_row_to_metadata(row)` will already work because Pydantic's `AwareDatetime` accepts either string or datetime. Check.

- [ ] **Step 5: Update `__main__.py`**

Replace:
```python
store = ReportingStore(db_path=cfg.db_path, reports_dir=cfg.reports_dir)
```
with:
```python
store = ReportingStore(database_url=cfg.database_url, reports_dir=cfg.reports_dir)
```

- [ ] **Step 6: Update `api.py` call sites if any string conversions need removal**

```bash
grep -n "isoformat\|insert_report" /home/aditya/Documents/IntelliFIM/data-plane/reporting/src/reporting/api.py
```

If `api.py`'s `insert_report(...)` call passes `range_start_iso=body.range_start.isoformat()`, change to `range_start=body.range_start` (and similarly for `range_end`, `generated_at`).

- [ ] **Step 7: Update `tests/conftest.py`**

Add the `pg_container` + `pg_pool` fixtures (Task 1 Step 6 template). Rewrite the existing `store` fixture (if any) to consume `pg_pool`. Many of the reporting tests construct `ReportingStore` inline — those need the new `pool=pg_pool` kwarg.

- [ ] **Step 8: Update test files for new signature**

```bash
grep -rn "ReportingStore(\|insert_report(" /home/aditya/Documents/IntelliFIM/data-plane/reporting/tests/
```

Two changes propagate:
1. `ReportingStore(db_path=..., reports_dir=...)` → `ReportingStore(pool=pg_pool, reports_dir=...)`
2. `insert_report(... range_start_iso="2030-01-01T00:00:00+00:00", ...)` → `insert_report(... range_start=datetime(2030, 1, 1, tzinfo=timezone.utc), ...)`

- [ ] **Step 9: Verify**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane/reporting
python3 -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest -v
```

Expected: **33 passed**.

- [ ] **Step 10: Stage**

```bash
deactivate
rm -rf .venv
rm -rf /home/aditya/Documents/IntelliFIM/data-plane/schemas/build/
git -C /home/aditya/Documents/IntelliFIM add \
    data-plane/reporting/pyproject.toml \
    data-plane/reporting/src/reporting/config.py \
    data-plane/reporting/src/reporting/store.py \
    data-plane/reporting/src/reporting/__main__.py \
    data-plane/reporting/src/reporting/api.py \
    data-plane/reporting/tests/conftest.py
git -C /home/aditya/Documents/IntelliFIM add data-plane/reporting/tests/test_*.py 2>/dev/null || true
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(v2-postgres): migrate reporting store from aiosqlite to asyncpg`

---

## Task 4: docker-compose.yml integration

**Files:**
- Modify: `data-plane/docker-compose.yml`

This task makes the new `postgres` service real in Compose AND swaps the 3 services' DB env vars from `DB_PATH` to `DATABASE_URL` AND drops the 2 SQLite-only volumes.

- [ ] **Step 1: Add the `postgres` service block**

Find the `auth-backend:` service block in `data-plane/docker-compose.yml`. Insert the `postgres:` block IMMEDIATELY BEFORE it (so postgres comes first, services that depend on it come after — keeps the file's natural read order):

```yaml
  postgres:
    image: postgres:16-alpine
    container_name: postgres
    networks: [bus]
    ports:
      - "127.0.0.1:5432:5432"
    environment:
      POSTGRES_USER: "postgres"
      POSTGRES_PASSWORD: "${POSTGRES_ROOT_PASSWORD}"
      POSTGRES_DB: "postgres"
      POSTGRES_AUTH_PASSWORD: "${POSTGRES_AUTH_PASSWORD}"
      POSTGRES_ORCH_PASSWORD: "${POSTGRES_ORCH_PASSWORD}"
      POSTGRES_REPORTING_PASSWORD: "${POSTGRES_REPORTING_PASSWORD}"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./postgres/init.sh:/docker-entrypoint-initdb.d/01-init.sh:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d postgres"]
      interval: 5s
      timeout: 5s
      retries: 10
```

- [ ] **Step 2: Update auth-backend block**

Find the `auth-backend:` service block. Two changes:

(a) Under `environment:`, REMOVE the `DB_PATH:` line and ADD:
```yaml
      DATABASE_URL: "postgresql://auth:${POSTGRES_AUTH_PASSWORD}@postgres:5432/auth_backend"
```

(b) Under `depends_on:`, ADD:
```yaml
      postgres:
        condition: service_healthy
```

(c) REMOVE the `volumes:` block entirely (the `- auth_backend_data:/data` line) — auth-backend no longer needs persistent volume. The mkdir `/data` in the Dockerfile is harmless legacy; leave the Dockerfile alone.

- [ ] **Step 3: Update response-orchestrator block**

Same shape:

(a) REMOVE the `DB_PATH:` line under `environment:`, ADD:
```yaml
      DATABASE_URL: "postgresql://orchestrator:${POSTGRES_ORCH_PASSWORD}@postgres:5432/orchestrator"
```

(b) ADD `postgres: condition: service_healthy` to depends_on.

(c) REMOVE the `volumes:` block (the `- orchestrator_data:/data` line).

- [ ] **Step 4: Update reporting block**

(a) REMOVE the `DB_PATH:` line under `environment:`, ADD:
```yaml
      DATABASE_URL: "postgresql://reporting:${POSTGRES_REPORTING_PASSWORD}@postgres:5432/reporting"
```

(b) ADD `postgres: condition: service_healthy` to depends_on.

(c) **KEEP** the `volumes:` block — reporting still mounts `reporting_data:/data` for PDF files.

- [ ] **Step 5: Update top-level `volumes:` block**

At the bottom of the file:
- REMOVE: `auth_backend_data:`
- REMOVE: `orchestrator_data:`
- ADD: `postgres_data:`
- KEEP: `reporting_data:` (used for PDFs)

- [ ] **Step 6: Validate compose config**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane config --services 2>&1 | grep -v "^time=" | sort | wc -l
```

Expected: `28` (27 v1 services + postgres).

```bash
docker compose --env-file .env.dataplane config 2>&1 | grep -E "postgres_data|auth_backend_data|orchestrator_data|reporting_data"
```

Expected: shows `postgres_data` + `reporting_data` only. No `auth_backend_data` or `orchestrator_data`.

- [ ] **Step 7: Stage**

```bash
git -C /home/aditya/Documents/IntelliFIM add data-plane/docker-compose.yml
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(v2-postgres): wire postgres into Compose; switch 3 services to DATABASE_URL; drop 2 SQLite volumes`

---

## Task 5: Verification script

**Files:**
- Create: `data-plane/scripts/check-postgres.sh`

- [ ] **Step 1: Write the script**

`data-plane/scripts/check-postgres.sh`:

```bash
#!/usr/bin/env bash
# Verify the Postgres-backed v2 stores are healthy + populated.
set -uo pipefail
cd "$(dirname "$0")/.."

echo "=== Postgres health ==="
docker exec postgres pg_isready -U postgres -d postgres && echo " OK"

echo "=== 3 databases exist ==="
DB_COUNT=$(docker exec postgres psql -U postgres -tAc \
  "SELECT count(*) FROM pg_database WHERE datname IN ('auth_backend','orchestrator','reporting')")
echo "databases: $DB_COUNT / 3"
[ "$DB_COUNT" = "3" ] || { echo "ERROR"; exit 2; }

echo "=== 3 service users exist ==="
USER_COUNT=$(docker exec postgres psql -U postgres -tAc \
  "SELECT count(*) FROM pg_user WHERE usename IN ('auth','orchestrator','reporting')")
echo "service users: $USER_COUNT / 3"
[ "$USER_COUNT" = "3" ] || { echo "ERROR"; exit 2; }

echo "=== Each service can connect + has its tables ==="
docker exec postgres psql -U postgres -d auth_backend -tAc "SELECT count(*) FROM users" \
  | awk '{print "auth_backend.users rows:", $0}'
docker exec postgres psql -U postgres -d orchestrator -tAc "SELECT count(*) FROM approvals" \
  | awk '{print "orchestrator.approvals rows:", $0}'
docker exec postgres psql -U postgres -d reporting -tAc "SELECT count(*) FROM threat_scores" \
  | awk '{print "reporting.threat_scores rows:", $0}'
docker exec postgres psql -U postgres -d reporting -tAc "SELECT count(*) FROM reports" \
  | awk '{print "reporting.reports rows:", $0}'

echo "PASS"
```

- [ ] **Step 2: chmod + run against the live stack**

The stack must be running with the new Postgres service. If not already up:
```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
./scripts/init-secrets.sh
docker compose --env-file .env.dataplane up -d
sleep 45   # wait for postgres init + service startup
```

Then:
```bash
chmod +x /home/aditya/Documents/IntelliFIM/data-plane/scripts/check-postgres.sh
./scripts/check-postgres.sh
echo "exit=$?"
```

Expected: ends with `PASS` + `exit=0`. All 3 databases, all 3 service users, all 4 tables exist.

If `docker compose up -d` fails because the previous v1 stack is still running with `auth_backend_data` + `orchestrator_data` mounted — wipe those volumes (their data is dead anyway):
```bash
docker compose --env-file .env.dataplane down
docker volume rm $(docker volume ls -q | grep -E "_(auth_backend_data|orchestrator_data)$") 2>/dev/null || true
docker compose --env-file .env.dataplane up -d
```

- [ ] **Step 3: Smoke each service's API end-to-end (DoD #6, #7, #8)**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
export ADMIN_EMAIL=$(grep ^ADMIN_EMAIL= .env.dataplane | cut -d= -f2-)
export ADMIN_PASSWORD=$(grep ^ADMIN_PASSWORD= .env.dataplane | cut -d= -f2-)

# Auth login (DoD #6)
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "Login OK; JWT length=${#TOKEN}"

# Wait for scenarios to flow → policy-engine → orchestrator to create PENDING rows
echo "Waiting 60s for the live pipeline to land a PENDING approval..."
sleep 60
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8200/approvals | python3 -m json.tool | head -20

# Reporting smoke (DoD #8)
./scripts/generate-report.py
echo "exit=$?"
```

Expected:
- Login returns a valid JWT.
- `/approvals` returns a non-empty list (assumes the live data plane has been generating threat scores; if not, run `./scripts/run-scenario.sh data-exfil` first to seed).
- `generate-report.py` exits 0 + writes PDF to `/tmp/`.

- [ ] **Step 4: Persistence-across-restart check (DoD #9)**

```bash
docker compose restart auth-backend response-orchestrator reporting
sleep 15

# All 3 service users + admin user should still exist
docker exec postgres psql -U postgres -d auth_backend -tAc "SELECT count(*) FROM users WHERE role='admin'"   # expect: 1
docker exec postgres psql -U postgres -d orchestrator -tAc "SELECT count(*) FROM approvals"                 # expect: >= 1
docker exec postgres psql -U postgres -d reporting -tAc "SELECT count(*) FROM reports"                       # expect: >= 1 (the one from Step 3)
```

- [ ] **Step 5: No-SQLite-artifacts check (DoD #10)**

```bash
docker exec auth-backend ls -la /data 2>/dev/null    # expect: no /data, or empty (no users.db)
docker exec response-orchestrator ls -la /data 2>/dev/null   # expect: no /data, or empty (no approvals.db)
docker exec reporting ls -la /data 2>/dev/null       # expect: only `reports/` subdirectory (no reporting.db)
```

If reporting's `/data` shows a legacy `reporting.db` (from a v1→v2 in-place upgrade rather than a fresh `down -v`), document it in the README as an operator cleanup step (`docker exec reporting rm /data/reporting.db`).

- [ ] **Step 6: Stage**

```bash
git -C /home/aditya/Documents/IntelliFIM add data-plane/scripts/check-postgres.sh
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(v2-postgres): add check-postgres.sh verification script`

---

## Task 6: README updates + DoD walkthrough

**Files:**
- Modify: `data-plane/README.md`

- [ ] **Step 1: Update the services count + add postgres bullet**

Find the "What's in the box" section. Update count `27 services` → `28 services`. Add a new bullet (after Observability):

```markdown
- **Persistence:** `postgres` (port 5432, internal `bus` network) hosts 3 separate databases (`auth_backend`, `orchestrator`, `reporting`) for the 3 services that previously used SQLite. PDFs continue to live on the `reporting_data` Docker volume (only metadata is in Postgres). See [postgres/](postgres/).
```

- [ ] **Step 2: Update "Prerequisites" or "Bring up the stack" sections**

Find the section that lists `./scripts/init-secrets.sh`. Extend the explanation:

```markdown
- `./scripts/init-secrets.sh` — generates `JWT_SECRET` (v1) AND 4 Postgres passwords (v2). Idempotent; safe to re-run.
```

- [ ] **Step 3: Add a new "Postgres (v2)" section before "Tear down"**

```markdown
## Postgres (v2)

Sub-project v2-1 migrated 3 SQLite-backed services (auth-backend, response-orchestrator, reporting) to a single Postgres 16 instance hosting 3 isolated databases:

| Database | Owner user | Used by |
|---|---|---|
| `auth_backend` | `auth` | auth-backend (`/auth/*` endpoints) |
| `orchestrator` | `orchestrator` | response-orchestrator (approval state machine) |
| `reporting` | `reporting` | reporting (threat_scores append-log + reports metadata) |

The root `postgres` superuser is used only by the one-shot init script at first boot.

```bash
# From data-plane/:
./scripts/check-postgres.sh                    # verify all 3 DBs + 3 users + tables exist
docker exec postgres psql -U postgres -l       # list databases
docker exec postgres psql -U postgres -d auth_backend -c "\dt"   # show tables
```

**Backend connection strings** (live in `.env.dataplane`, generated by `init-secrets.sh`):
- `auth-backend` → `postgresql://auth:${POSTGRES_AUTH_PASSWORD}@postgres:5432/auth_backend`
- `response-orchestrator` → `postgresql://orchestrator:${POSTGRES_ORCH_PASSWORD}@postgres:5432/orchestrator`
- `reporting` → `postgresql://reporting:${POSTGRES_REPORTING_PASSWORD}@postgres:5432/reporting`

**v2 limitations** (deferred to later v2/v3 work):
- No alembic migrations — schemas managed by `CREATE TABLE IF NOT EXISTS` at startup. v3 production hardening adds alembic.
- No TLS to Postgres — plain connections within the `bus` network. Pairs with the TLS-everywhere v2 theme.
- No HA — single Postgres replica. v3 adds streaming replication.
- No `postgres-exporter` for Prometheus — pairs with the observability v2 theme.
- No backup tooling — `pg_dump` cron + restore script is a v2/v3 follow-up.
- Db passwords in env vars, not Vault — Vault is its own v2 theme.

**For operators migrating from v1**: the legacy SQLite files in the OLD `auth_backend_data` and `orchestrator_data` volumes are unreferenced after the v2 swap. Remove them with:
```bash
docker volume rm $(docker volume ls -q | grep -E "_(auth_backend_data|orchestrator_data)$")
```
The `reporting_data` volume STAYS (it hosts PDFs); just remove the legacy `reporting.db` file inside it:
```bash
docker exec reporting rm -f /data/reporting.db
```
```

- [ ] **Step 4: DoD walk-through summary (verification only — no file changes)**

Run the full DoD checklist on a clean stack:

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
# DoD #1 — pytest green per service
cd auth_backend && python3 -m venv .venv && . .venv/bin/activate && \
    pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas && pip install -e .[dev] && \
    pytest -v && deactivate && rm -rf .venv && cd ..
# Repeat for orchestrator + reporting
```

- [ ] **Step 5: Stage README**

```bash
git -C /home/aditya/Documents/IntelliFIM add data-plane/README.md
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `docs(v2-postgres): document Postgres v2 in data-plane README`

---

## Post-merge checklist (after PR merges to main)

1. Sync local `main`:
   ```bash
   git checkout main && git pull --ff-only
   ```
2. Update memory files:
   - `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/MEMORY.md`:
     - Add an entry for v2-1 (Postgres migration shipped).
     - Note the v2 phase has begun.
   - `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/project_intellifim_roadmap.md`:
     - Add a "v2 themes shipped" section near the top with v2-1 ✅ SHIPPED + the PR # + squash sha.
     - Append new patterns to the "Critical patterns" section (asyncpg pool, testcontainers, postgres init.sh shell-script for variable interpolation).
     - Append a "From v2-1" deferral block.
   - Create `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/project_intellifim_v2_postgres_shipped.md` as the frozen snapshot.
   - Update `project_intellifim_v1_shipped.md`: note that v2-1 has moved the 3 services off SQLite (stack count is now 28).

---

## Plan self-review

### Spec coverage (each spec section → task that implements it)

| Spec section | Implemented in |
|---|---|
| §1 Goal | Tasks 0–6 (end-to-end) |
| §2 Architecture (postgres service + 3 DBs + asyncpg + testcontainers) | Tasks 0, 1, 2, 3 |
| §3 Scope (in/out) | Whole plan respects scope; §10 deferrals not implemented |
| §4.1 postgres Compose block | Task 4 Step 1 |
| §4.2 init.sh | Task 0 Step 2 |
| §4.3 extended init-secrets.sh | Task 0 Step 3 |
| §4.4 .env.dataplane.example | Task 0 Step 4 |
| §4.5 bootstrap order | Verified in Task 5 Steps 2–3 |
| §5 per-service store refactor | Tasks 1, 2, 3 |
| §5.5 volume changes | Task 4 Step 5 |
| §6 per-service Compose changes | Task 4 Steps 2–4 |
| §7 repo layout | Tasks 0–6 (each file maps) |
| §8.1 testcontainers pattern | Tasks 1, 2, 3 (Step 6 in each) |
| §8.3 test counts unchanged | Verified at each service's Step 8 |
| §8.4 10-item DoD | Task 5 + Task 6 Step 4 |
| §8.5 smoke script | Task 5 |
| §9 error handling | Tasks 1, 2, 3 (assert checks + raise on naive datetimes) |
| §10 v2/v3 deferrals | Not implemented (documented in spec + README) |

No gaps.

### Placeholder scan
- No "TBD" / "TODO" / "implement later" / "fill in".
- Every store rewrite shows full code.
- Every conftest update shows the canonical pattern.
- Every Compose change shows the exact yaml diff.
- Where the implementer needs to adapt to existing fixture names, the plan explicitly says READ the existing file first and shows the search command.

### Type / method-name consistency

- `UsersStore(database_url=...)` / `UsersStore(pool=pg_pool)` — both signatures supported via `__init__(database_url=None, *, pool=None)`. Same pattern in `ApprovalStore` and `ReportingStore`. ✓
- `init_schema()` / `aclose()` — public method names identical across all 3 stores in v1 and v2. ✓
- `_row_to_user(record)` / `_row(record)` / `_row_to_report(record)` — naming follows v1 convention per service. ✓
- `pg_container` (session-scoped) + `pg_pool` (function-scoped) — same fixture names across all 3 services' conftests. ✓
- `DATABASE_URL` env var — same name in all 3 service Compose blocks; different value per service. ✓
- `postgres:16-alpine` — identical image tag in Compose AND in testcontainers fixture. ✓
- ReportingStore `insert_report` signature CHANGES: v1 took `range_start_iso: str`, v2 takes `range_start: datetime`. Documented in Task 3 Step 4's NOTE; Task 3 Step 6 covers updating the `api.py` caller. ✓

All consistent.

---

**Plan ready for execution.**
