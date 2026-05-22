# Reporting Subsystem v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a `reporting` service (24th in the data-plane stack) that consumes `threat.scores` Kafka into a local SQLite table, fetches approvals from the response-orchestrator HTTP API on demand, and generates persistent PDF "Security Summary" reports via WeasyPrint + Jinja2 + matplotlib; wire the existing React `Reports.tsx` page to the new service.

**Architecture:** One new FastAPI + uvicorn service (`reporting` on :8300) with co-resident aiokafka consumer + HTTP API in a single asyncio event loop. Local aiosqlite database holds the threat-score append log and the generated-report metadata; PDF bytes live on a named volume. JWT validation reuses the HS256 shared secret pattern from #6 — `admin|analyst` can generate/delete, any role can list/download. Frontend Reports page rewrites mock content to real `useQuery` against the new service and uses a blob-based download flow to preserve `Authorization: Bearer` headers.

**Tech Stack:** Python 3.12, FastAPI ~0.115, uvicorn, aiokafka, aiosqlite, httpx, python-jose[cryptography], WeasyPrint, Jinja2, matplotlib (Agg backend), pytest, pytest-asyncio, respx. React 18 + TypeScript + Vite + @tanstack/react-query (pre-existing). Docker Compose.

**Reference spec:** [`docs/superpowers/specs/2026-05-20-reporting-v1-design.md`](../specs/2026-05-20-reporting-v1-design.md)

**Reference for patterns:**
- `data-plane/orchestrator/` — context-at-`data-plane/` Dockerfile, console-script entry point, `aclose()` discipline on httpx, aiokafka + HTTP server co-resident in one loop.
- `data-plane/auth_backend/` — FastAPI factory `build_app(...)` pattern, `now: Callable` injection, `@app.exception_handler` for `{"error": ...}` shape, `_current_user` Depends helper.
- `chronos-ai-guard/src/lib/apiClient.ts` — Bearer-token fetch wrapper + 401-handling. Reuse unchanged.

**Branch:** Create `feat/reporting-v1` off `main` before Task 1.

---

## File Map

```
data-plane/reporting/                            ← NEW package
├── pyproject.toml
├── Dockerfile
├── .dockerignore
├── README.md
├── src/reporting/
│   ├── __init__.py                              (empty)
│   ├── __main__.py                              (entry point — uvicorn launcher + consumer task)
│   ├── config.py                                (ReportingConfig — env-var parser)
│   ├── models.py                                (Pydantic + Principal frozen dataclass)
│   ├── store.py                                 (ReportingStore + ScoreRow + ReportRow)
│   ├── auth.py                                  (decode_token + FastAPI Depends helper)
│   ├── consumer.py                              (KafkaScoreConsumer + _extract_score)
│   ├── orchestrator_client.py                   (OrchestratorClient with list_approvals)
│   ├── renderer.py                              (render_chart + render_html + render_pdf)
│   ├── api.py                                   (FastAPI app factory `build_app(...)`)
│   └── templates/
│       └── security_summary.html.j2
└── tests/
    ├── __init__.py                              (empty)
    ├── conftest.py                              (shared fixtures + _T0 + _make_token)
    ├── test_config.py                           (4 tests)
    ├── test_store.py                            (6 tests)
    ├── test_consumer.py                         (3 tests)
    ├── test_orchestrator_client.py              (3 tests)
    ├── test_renderer.py                         (4 tests)
    └── test_api.py                              (7 tests)

data-plane/scripts/
└── generate-report.py                           (NEW smoke script — login → generate → download)

# Modified
data-plane/docker-compose.yml                    (add `reporting` service + admin-console depends_on + volume)
chronos-ai-guard/src/lib/apiClient.ts            (add REPORTING_API_URL export)
chronos-ai-guard/src/pages/Reports.tsx           (rewrite — real data, generate form, list, blob download)
chronos-ai-guard/.env.development                (add VITE_REPORTING_API_URL)
data-plane/README.md                             (note reporting service + scripts/generate-report.py)
```

**Test totals after this sub-project:**
- New: 4 (config) + 6 (store) + 3 (consumer) + 3 (orchestrator client) + 4 (renderer) + 7 (api) = **27 new Python tests**.
- Suite total: 210 Python + 5 Rego → **237 Python + 5 Rego = 242 total**.

---

## Standing Rules (carried from prior sub-projects)

- **NEVER run `git commit` yourself.** Stage files via `git add <specific paths>` and ask the user to commit. (`feedback_no_self_commits.md`.)
- **Never** `docker compose down -v` unless explicitly part of a fresh-checkout DoD test (wipes Wazuh state).
- **Never** `git add .` or `git add -A`. Stage only files the task lists.
- **Never** `--no-verify` or bypass hooks/signing.
- Time always UTC, ISO-8601 with explicit `+00:00`. Pydantic `AwareDatetime`. Datetimes constructed with `tzinfo=timezone.utc`.
- Cross-package pins are RANGES (`>=X,<Y`), never `==`.
- `_extract_event`/`_extract_score` patterns accept EITHER a typed instance OR an object with `.value` bytes (production aiokafka path).
- `now: Callable[[], datetime]` defaults to `lambda: datetime.now(tz=timezone.utc)`; threaded into every component that calls `now()`.
- Pydantic models: `ConfigDict(extra="forbid")`. Field length / range constraints declared at type level.
- Test fixed clock: `_T0 = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)`. (Chosen far enough in the future that real wall-clock never catches up during a test run — the lesson from #6 Task 8.)

---

## Task 0: Branch + package skeleton

**Files:**
- Create: `data-plane/reporting/pyproject.toml`
- Create: `data-plane/reporting/.dockerignore`
- Create: `data-plane/reporting/README.md`
- Create: `data-plane/reporting/src/reporting/__init__.py` (empty)
- Create: `data-plane/reporting/tests/__init__.py` (empty)

- [ ] **Step 1: Create branch + directories**

```bash
git checkout main
git pull --ff-only
git checkout -b feat/reporting-v1
mkdir -p data-plane/reporting/src/reporting/templates
mkdir -p data-plane/reporting/tests
```

- [ ] **Step 2: Write pyproject.toml**

`data-plane/reporting/pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "intellifim-reporting"
version = "0.1.0"
description = "IntelliFIM reporting service — PDF Security Summary reports from threat scores + approvals."
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115,<0.116",
    "uvicorn[standard]>=0.30,<0.35",
    "pydantic[email]>=2.7,<3",
    "aiokafka>=0.10,<0.13",
    "aiosqlite>=0.20,<0.22",
    "httpx>=0.27,<0.29",
    "python-jose[cryptography]>=3.3,<4",
    "weasyprint>=62,<63",
    "jinja2>=3.1,<4",
    "matplotlib>=3.8,<4",
    "intellifim-schemas>=0.4,<1.0",
]

[project.optional-dependencies]
test = [
    "pytest>=8,<9",
    "pytest-asyncio>=0.23,<0.25",
    "respx>=0.21,<0.23",
    "httpx>=0.27,<0.29",
]

[project.scripts]
intellifim-reporting = "reporting.__main__:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
reporting = ["templates/*.html.j2"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

- [ ] **Step 3: Write .dockerignore**

`data-plane/reporting/.dockerignore`:

```
__pycache__/
*.pyc
*.pyo
.pytest_cache/
.venv/
tests/
*.egg-info/
build/
dist/
```

- [ ] **Step 4: Write README.md**

`data-plane/reporting/README.md`:

````markdown
# reporting

IntelliFIM v1 reporting service — generates persistent PDF "Security Summary" reports from `threat.scores` (consumed from Kafka into local SQLite) + `/approvals` (fetched on-demand from `response-orchestrator`).

**Port:** 8300 (bound to `127.0.0.1`).
**Storage:** `/data/reporting.db` + `/data/reports/*.pdf` on the `reporting_data` Compose volume.
**Auth:** HS256 JWT (shared `JWT_SECRET` with `auth-backend` + `response-orchestrator`).
**Roles:** `admin | analyst` can generate/delete; any logged-in user can list/download.

## Endpoints

- `GET /healthz`
- `POST /reports/generate` (admin|analyst)
- `GET /reports?limit=N&offset=M` (any role)
- `GET /reports/{id}` (any role)
- `GET /reports/{id}/download` (any role)
- `DELETE /reports/{id}` (admin)

## Local dev

```bash
cd data-plane/reporting
pip install -e .[test]
pytest -v
```

The service is built and run via Docker Compose; see `data-plane/docker-compose.yml`.

## Smoke

```bash
# from data-plane/
docker compose up -d
./scripts/generate-report.py
```

See `data-plane/scripts/generate-report.py` for the end-to-end happy path.
````

- [ ] **Step 5: Create empty `__init__.py` files**

```bash
touch data-plane/reporting/src/reporting/__init__.py
touch data-plane/reporting/tests/__init__.py
```

- [ ] **Step 6: Verify local install**

```bash
cd data-plane/reporting
python -m venv .venv
. .venv/bin/activate
pip install -e .[test]
python -c "import reporting; print('ok')"
deactivate
rm -rf .venv
cd ../..
```

Expected: `ok` printed. No import errors. (WeasyPrint native deps may not be present in your local Python env — that's fine; install errors related to libpango/libcairo can be tolerated locally because the Docker image will have them. If pip install fails on the WeasyPrint *wheel* itself, debug it; if it fails at *import time* due to missing native libs, ignore for now.)

- [ ] **Step 7: Stage + ask user to commit**

```bash
git add data-plane/reporting/pyproject.toml \
        data-plane/reporting/.dockerignore \
        data-plane/reporting/README.md \
        data-plane/reporting/src/reporting/__init__.py \
        data-plane/reporting/tests/__init__.py
git status
```

Then **ask the user to commit** with message:
```
feat(reporting): scaffold reporting package skeleton
```

---

## Task 1: ReportingConfig

**Files:**
- Create: `data-plane/reporting/src/reporting/config.py`
- Create: `data-plane/reporting/tests/conftest.py`
- Create: `data-plane/reporting/tests/test_config.py`

- [ ] **Step 1: Write conftest.py shared fixtures**

`data-plane/reporting/tests/conftest.py`:

```python
"""Shared pytest fixtures.

`_T0` is a fixed test clock far enough in the future that real wall-clock
never catches up to it during a test run — the lesson from sub-project #6's
Task 8 (JWT expiry checks were going stale overnight against a 2026-fixed clock).
"""
from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime, timezone

import pytest

_T0 = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def fixed_now() -> Callable[[], datetime]:
    """Returns a `now` callable that always returns `_T0`."""
    return lambda: _T0


@pytest.fixture
def jwt_secret() -> str:
    return "test-jwt-secret-not-for-prod-use"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Each test starts with a clean reporting-relevant env."""
    for k in list(os.environ):
        if k.startswith(("KAFKA_", "JWT_", "ORCHESTRATOR_", "DB_PATH",
                         "REPORTS_DIR", "CORS_", "BIND_", "PORT", "JWT_TTL")):
            monkeypatch.delenv(k, raising=False)
```

- [ ] **Step 2: Write failing tests for ReportingConfig**

`data-plane/reporting/tests/test_config.py`:

```python
"""ReportingConfig env-var parsing tests."""
from __future__ import annotations

import pytest

from reporting.config import ReportingConfig, ReportingConfigError


def _set_required(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "secret")
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka:9092")
    monkeypatch.setenv("ORCHESTRATOR_URL", "http://response-orchestrator:8200")


def test_required_fields_have_no_defaults(monkeypatch):
    """JWT_SECRET, KAFKA_BOOTSTRAP, ORCHESTRATOR_URL are required."""
    for missing in ("JWT_SECRET", "KAFKA_BOOTSTRAP", "ORCHESTRATOR_URL"):
        _set_required(monkeypatch)
        monkeypatch.delenv(missing, raising=False)
        with pytest.raises(ReportingConfigError) as exc:
            ReportingConfig.from_env()
        assert missing in str(exc.value)


def test_defaults_applied_for_optional_fields(monkeypatch):
    _set_required(monkeypatch)
    cfg = ReportingConfig.from_env()
    assert cfg.jwt_secret == "secret"
    assert cfg.kafka_bootstrap == "kafka:9092"
    assert cfg.orchestrator_url == "http://response-orchestrator:8200"
    assert cfg.db_path == "/data/reporting.db"
    assert cfg.reports_dir == "/data/reports"
    assert cfg.bind_host == "0.0.0.0"
    assert cfg.port == 8300
    assert cfg.jwt_ttl_seconds == 8 * 60 * 60
    assert cfg.cors_origins == ("http://localhost:5173",)
    assert cfg.kafka_topic == "threat.scores"
    assert cfg.kafka_group_id == "intellifim-reporting"


def test_overrides_from_env(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("DB_PATH", "/tmp/reporting.db")
    monkeypatch.setenv("REPORTS_DIR", "/tmp/reports")
    monkeypatch.setenv("BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("PORT", "9300")
    monkeypatch.setenv("JWT_TTL_SECONDS", "300")
    monkeypatch.setenv("CORS_ORIGINS", "http://a.example, http://b.example")
    cfg = ReportingConfig.from_env()
    assert cfg.db_path == "/tmp/reporting.db"
    assert cfg.reports_dir == "/tmp/reports"
    assert cfg.bind_host == "127.0.0.1"
    assert cfg.port == 9300
    assert cfg.jwt_ttl_seconds == 300
    assert cfg.cors_origins == ("http://a.example", "http://b.example")


def test_bad_orchestrator_url_rejected(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("ORCHESTRATOR_URL", "not-a-url")
    with pytest.raises(ReportingConfigError) as exc:
        ReportingConfig.from_env()
    assert "ORCHESTRATOR_URL" in str(exc.value)
```

- [ ] **Step 3: Run failing tests**

```bash
cd data-plane/reporting && pip install -e .[test] && pytest tests/test_config.py -v
```

Expected: 4 FAIL with `ImportError: cannot import name 'ReportingConfig'` (and `ReportingConfigError`).

- [ ] **Step 4: Implement ReportingConfig**

`data-plane/reporting/src/reporting/config.py`:

```python
"""Env-var parser for the reporting service.

Fail-fast on missing required fields; conservative defaults for the rest.
URL validation is intentionally cheap — full URL parsing is httpx's job.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


class ReportingConfigError(ValueError):
    """Raised when env-var parsing fails."""


@dataclass(frozen=True)
class ReportingConfig:
    jwt_secret: str
    kafka_bootstrap: str
    orchestrator_url: str
    db_path: str
    reports_dir: str
    bind_host: str
    port: int
    jwt_ttl_seconds: int
    cors_origins: tuple[str, ...]
    kafka_topic: str
    kafka_group_id: str

    @classmethod
    def from_env(cls) -> "ReportingConfig":
        for k in ("JWT_SECRET", "KAFKA_BOOTSTRAP", "ORCHESTRATOR_URL"):
            if not os.environ.get(k):
                raise ReportingConfigError(f"missing required env var: {k}")

        orchestrator_url = os.environ["ORCHESTRATOR_URL"]
        parsed = urlparse(orchestrator_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ReportingConfigError(
                f"ORCHESTRATOR_URL must be an http(s) URL with a host; got {orchestrator_url!r}"
            )

        cors = os.environ.get("CORS_ORIGINS", "http://localhost:5173")
        cors_origins = tuple(o.strip() for o in cors.split(",") if o.strip())

        return cls(
            jwt_secret=os.environ["JWT_SECRET"],
            kafka_bootstrap=os.environ["KAFKA_BOOTSTRAP"],
            orchestrator_url=orchestrator_url,
            db_path=os.environ.get("DB_PATH", "/data/reporting.db"),
            reports_dir=os.environ.get("REPORTS_DIR", "/data/reports"),
            bind_host=os.environ.get("BIND_HOST", "0.0.0.0"),
            port=int(os.environ.get("PORT", "8300")),
            jwt_ttl_seconds=int(os.environ.get("JWT_TTL_SECONDS", str(8 * 60 * 60))),
            cors_origins=cors_origins,
            kafka_topic=os.environ.get("KAFKA_TOPIC", "threat.scores"),
            kafka_group_id=os.environ.get("KAFKA_GROUP_ID", "intellifim-reporting"),
        )
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_config.py -v
```

Expected: `4 passed`.

- [ ] **Step 6: Stage + ask user to commit**

```bash
git add data-plane/reporting/src/reporting/config.py \
        data-plane/reporting/tests/conftest.py \
        data-plane/reporting/tests/test_config.py
git status
```

Commit message: `feat(reporting): add ReportingConfig env parser`

---

## Task 2: Internal Pydantic models + Principal

**Files:**
- Create: `data-plane/reporting/src/reporting/models.py`

(No standalone test file — models are exercised by `test_api.py` later. Validator behavior is tested via API request handling.)

- [ ] **Step 1: Write models.py**

`data-plane/reporting/src/reporting/models.py`:

```python
"""Internal Pydantic models for the reporting service.

Kept OUT of `intellifim-schemas` because these types are not on any Kafka
topic — they're only on the HTTP wire to/from this service. Bumping
intellifim-schemas would force every other consumer to rev, for no benefit.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeInt,
    model_validator,
)

Role = Literal["admin", "analyst", "viewer"]


@dataclass(frozen=True)
class Principal:
    """JWT subject extracted by the auth middleware.

    Field shape matches data-plane/orchestrator/src/orchestrator/auth.py
    so a single JWT contract holds across the two backend services.
    """
    user_id: UUID
    username: str
    role: Role


class GenerateReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    range_start: AwareDatetime
    range_end: AwareDatetime

    @model_validator(mode="after")
    def _validate_range(self) -> "GenerateReportRequest":
        if self.range_end <= self.range_start:
            raise ValueError("range_end must be strictly after range_start")
        if self.range_end - self.range_start > timedelta(days=90):
            raise ValueError("range may not exceed 90 days")
        return self


class ReportMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    name: str
    range_start: AwareDatetime
    range_end: AwareDatetime
    generated_at: AwareDatetime
    generated_by: str
    size_bytes: NonNegativeInt
    approvals_count: NonNegativeInt
    scores_count: NonNegativeInt


class ReportListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reports: list[ReportMetadata]
    total: NonNegativeInt
```

- [ ] **Step 2: Verify import**

```bash
cd data-plane/reporting && python -c "from reporting.models import GenerateReportRequest, ReportMetadata, ReportListResponse, Principal, Role; print('ok')"
```

Expected: `ok`.

- [ ] **Step 3: Stage + ask user to commit**

```bash
git add data-plane/reporting/src/reporting/models.py
git status
```

Commit message: `feat(reporting): add Pydantic models + Principal dataclass`

---

## Task 3: ReportingStore — schema + threat_scores half

**Files:**
- Create: `data-plane/reporting/src/reporting/store.py`
- Create: `data-plane/reporting/tests/test_store.py`

- [ ] **Step 1: Write failing tests for the threat_scores half of the store**

`data-plane/reporting/tests/test_store.py`:

```python
"""ReportingStore tests — Part 1: schema + threat_scores."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from reporting.store import ReportingStore


_T = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
async def store(tmp_path):
    db = tmp_path / "reporting.db"
    s = ReportingStore(db_path=str(db), reports_dir=str(tmp_path / "reports"))
    await s.init_schema()
    yield s
    await s.aclose()


async def test_init_schema_is_idempotent(tmp_path):
    db = tmp_path / "reporting.db"
    s = ReportingStore(db_path=str(db), reports_dir=str(tmp_path / "reports"))
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
```

- [ ] **Step 2: Run failing tests**

```bash
pytest tests/test_store.py -v
```

Expected: 4 FAIL with `ImportError: cannot import name 'ReportingStore'`.

- [ ] **Step 3: Implement ReportingStore — schema + threat_scores half**

`data-plane/reporting/src/reporting/store.py`:

```python
"""SQLite-backed store for reporting service.

Two tables:
- `threat_scores` — append-log populated by the Kafka consumer.
- `reports` — generated-report metadata; PDF bytes live on filesystem.

Pattern: aiosqlite + asyncio.Lock single-writer. Reads are concurrent.
`init_schema()` is idempotent. `aclose()` discipline matches orchestrator's
WazuhClient + auth-backend's UsersStore.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import aiosqlite


_CREATE_THREAT_SCORES = """
CREATE TABLE IF NOT EXISTS threat_scores (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id TEXT NOT NULL,
    score   REAL NOT NULL,
    reason  TEXT NOT NULL,
    ts      TEXT NOT NULL
);
"""
_IDX_THREAT_SCORES_TS = "CREATE INDEX IF NOT EXISTS idx_threat_scores_ts ON threat_scores(ts);"
_IDX_THREAT_SCORES_HOST_TS = (
    "CREATE INDEX IF NOT EXISTS idx_threat_scores_host_ts "
    "ON threat_scores(host_id, ts);"
)

_CREATE_REPORTS = """
CREATE TABLE IF NOT EXISTS reports (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    range_start     TEXT NOT NULL,
    range_end       TEXT NOT NULL,
    generated_at    TEXT NOT NULL,
    generated_by    TEXT NOT NULL,
    pdf_path        TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
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
    ts: str  # ISO-8601 UTC


@dataclass(frozen=True)
class ReportRow:
    id: UUID
    name: str
    range_start: str
    range_end: str
    generated_at: str
    generated_by: str
    pdf_path: str
    size_bytes: int
    approvals_count: int
    scores_count: int


class ReportingStore:
    def __init__(self, db_path: str, reports_dir: str) -> None:
        self._db_path = db_path
        self._reports_dir = reports_dir
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def init_schema(self) -> None:
        if self._conn is not None:
            return
        os.makedirs(self._reports_dir, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        async with self._lock:
            await self._conn.execute(_CREATE_THREAT_SCORES)
            await self._conn.execute(_IDX_THREAT_SCORES_TS)
            await self._conn.execute(_IDX_THREAT_SCORES_HOST_TS)
            await self._conn.execute(_CREATE_REPORTS)
            await self._conn.execute(_IDX_REPORTS_GEN_AT)
            await self._conn.commit()

    async def aclose(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def reports_dir(self) -> str:
        return self._reports_dir

    # --- threat_scores --------------------------------------------------

    async def insert_score(
        self, *, host_id: str, score: float, reason: str, ts: datetime
    ) -> None:
        assert self._conn is not None, "init_schema() not called"
        ts_iso = ts.isoformat()
        async with self._lock:
            await self._conn.execute(
                "INSERT INTO threat_scores(host_id, score, reason, ts) "
                "VALUES(?, ?, ?, ?)",
                (host_id, score, reason, ts_iso),
            )
            await self._conn.commit()

    async def query_scores(
        self, *, start: datetime, end: datetime, host_id: str | None = None
    ) -> list[ScoreRow]:
        assert self._conn is not None
        sql = (
            "SELECT host_id, score, reason, ts FROM threat_scores "
            "WHERE ts >= ? AND ts < ?"
        )
        params: list = [start.isoformat(), end.isoformat()]
        if host_id is not None:
            sql += " AND host_id = ?"
            params.append(host_id)
        sql += " ORDER BY ts ASC"
        async with self._conn.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
        return [
            ScoreRow(host_id=r["host_id"], score=r["score"], reason=r["reason"], ts=r["ts"])
            for r in rows
        ]

    async def top_hosts_by_max_score(
        self, *, start: datetime, end: datetime, limit: int = 10
    ) -> list[tuple[str, float]]:
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT host_id, MAX(score) AS max_score FROM threat_scores "
            "WHERE ts >= ? AND ts < ? "
            "GROUP BY host_id ORDER BY max_score DESC LIMIT ?",
            (start.isoformat(), end.isoformat(), limit),
        ) as cursor:
            rows = await cursor.fetchall()
        return [(r["host_id"], r["max_score"]) for r in rows]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_store.py -v
```

Expected: `4 passed`.

- [ ] **Step 5: Stage + ask user to commit**

```bash
git add data-plane/reporting/src/reporting/store.py \
        data-plane/reporting/tests/test_store.py
git status
```

Commit message: `feat(reporting): add ReportingStore schema + threat_scores half`

---

## Task 4: ReportingStore — reports table half

**Files:**
- Modify: `data-plane/reporting/src/reporting/store.py` (append `insert_report`, `list_reports`, `get_report`, `delete_report`)
- Modify: `data-plane/reporting/tests/test_store.py` (append 2 more tests — final total 6)

- [ ] **Step 1: Append failing tests to test_store.py**

Append to `data-plane/reporting/tests/test_store.py`:

```python
from uuid import uuid4


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
        id=rid1, name="r1", range_start_iso="2030-01-01T00:00:00+00:00",
        range_end_iso="2030-01-02T00:00:00+00:00",
        generated_at_iso="2030-01-01T00:00:00+00:00", generated_by="alice",
        pdf_path=pdf_path1, size_bytes=9, approvals_count=2, scores_count=10,
    )
    await store.insert_report(
        id=rid2, name="r2", range_start_iso="2030-01-02T00:00:00+00:00",
        range_end_iso="2030-01-03T00:00:00+00:00",
        generated_at_iso="2030-01-02T00:00:00+00:00", generated_by="bob",
        pdf_path=pdf_path2, size_bytes=9, approvals_count=5, scores_count=20,
    )

    rows, total = await store.list_reports(limit=10, offset=0)
    assert total == 2
    assert [r.id for r in rows] == [rid2, rid1]   # newest first

    fetched = await store.get_report(rid1)
    assert fetched is not None
    assert fetched.name == "r1"
    assert fetched.generated_by == "alice"

    assert await store.delete_report(rid1) is True
    assert await store.get_report(rid1) is None
    assert os.path.exists(pdf_path1) is False  # file removed too


async def test_delete_report_idempotent_on_missing_file(store):
    rid = uuid4()
    ghost_path = f"{store.reports_dir}/ghost-{rid}.pdf"
    # Do NOT create the file
    await store.insert_report(
        id=rid, name="ghost", range_start_iso="2030-01-01T00:00:00+00:00",
        range_end_iso="2030-01-02T00:00:00+00:00",
        generated_at_iso="2030-01-01T00:00:00+00:00", generated_by="alice",
        pdf_path=ghost_path, size_bytes=0, approvals_count=0, scores_count=0,
    )
    assert await store.delete_report(rid) is True   # row removed even though file absent

    # Second delete returns False (no row)
    assert await store.delete_report(rid) is False
```

- [ ] **Step 2: Run failing tests**

```bash
pytest tests/test_store.py -v
```

Expected: 2 NEW FAILs with `AttributeError: 'ReportingStore' object has no attribute 'insert_report'`. 4 prior tests still pass.

- [ ] **Step 3: Append `insert_report`/`list_reports`/`get_report`/`delete_report` to store.py**

Append at the end of `data-plane/reporting/src/reporting/store.py`:

```python

    # --- reports --------------------------------------------------------

    async def insert_report(
        self, *,
        id: UUID,
        name: str,
        range_start_iso: str,
        range_end_iso: str,
        generated_at_iso: str,
        generated_by: str,
        pdf_path: str,
        size_bytes: int,
        approvals_count: int,
        scores_count: int,
    ) -> None:
        assert self._conn is not None
        async with self._lock:
            await self._conn.execute(
                "INSERT INTO reports("
                "id, name, range_start, range_end, generated_at, "
                "generated_by, pdf_path, size_bytes, approvals_count, scores_count"
                ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(id), name, range_start_iso, range_end_iso, generated_at_iso,
                    generated_by, pdf_path, size_bytes, approvals_count, scores_count,
                ),
            )
            await self._conn.commit()

    async def list_reports(
        self, *, limit: int, offset: int
    ) -> tuple[list[ReportRow], int]:
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM reports ORDER BY generated_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()
        async with self._conn.execute("SELECT COUNT(*) AS n FROM reports") as cursor:
            total_row = await cursor.fetchone()
        total = int(total_row["n"]) if total_row else 0
        return [_row_to_report(r) for r in rows], total

    async def get_report(self, id: UUID) -> ReportRow | None:
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM reports WHERE id = ?", (str(id),)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_report(row)

    async def delete_report(self, id: UUID) -> bool:
        assert self._conn is not None
        async with self._lock:
            async with self._conn.execute(
                "SELECT pdf_path FROM reports WHERE id = ?", (str(id),)
            ) as cursor:
                row = await cursor.fetchone()
            if row is None:
                return False
            pdf_path = row["pdf_path"]
            await self._conn.execute("DELETE FROM reports WHERE id = ?", (str(id),))
            await self._conn.commit()
        try:
            os.unlink(pdf_path)
        except FileNotFoundError:
            pass   # idempotent — file already gone is fine
        return True


def _row_to_report(record) -> ReportRow:
    return ReportRow(
        id=UUID(record["id"]),
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

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_store.py -v
```

Expected: `6 passed`.

- [ ] **Step 5: Stage + ask user to commit**

```bash
git add data-plane/reporting/src/reporting/store.py \
        data-plane/reporting/tests/test_store.py
git status
```

Commit message: `feat(reporting): add reports table CRUD to ReportingStore`

---

## Task 5: JWT auth helper + Principal decoder

**Files:**
- Create: `data-plane/reporting/src/reporting/auth.py`

(Tests cover this transitively via `test_api.py`'s 401/403 tests. The unit shape is mostly identical to `data-plane/orchestrator/src/orchestrator/auth.py`, which is already independently tested.)

- [ ] **Step 1: Write auth.py**

`data-plane/reporting/src/reporting/auth.py`:

```python
"""JWT auth helpers for the reporting service.

Conceptually identical to orchestrator/auth.py but exposes a FastAPI
`Depends` style entry point (the orchestrator uses an aiohttp middleware).
The HS256 secret + claim shape match auth-backend so a single JWT works
across all three services.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import cast
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from reporting.models import Principal, Role


REQUIRED_CLAIMS = ("sub", "username", "role", "exp")


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def decode_token(
    token: str, secret: str, *, now: Callable[[], datetime] = _default_now
) -> Principal:
    """Decode + validate an HS256 JWT, returning a Principal.

    Raises HTTPException(401) on any failure: bad signature, missing claims,
    expired, malformed role.
    """
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"], options={"verify_exp": False})
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"invalid token: {e}") from e

    for claim in REQUIRED_CLAIMS:
        if claim not in payload:
            raise HTTPException(status_code=401, detail=f"missing claim: {claim}")

    exp = int(payload["exp"])
    if exp <= int(now().timestamp()):
        raise HTTPException(status_code=401, detail="token expired")

    role = payload["role"]
    if role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=401, detail=f"unknown role: {role}")

    try:
        principal_id = UUID(payload["sub"])
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=401, detail=f"bad subject: {e}") from e

    return Principal(
        user_id=principal_id,
        username=str(payload["username"]),
        role=cast(Role, role),
    )


bearer_scheme = HTTPBearer(auto_error=False)


def make_get_current_principal(
    jwt_secret: str, *, now: Callable[[], datetime] = _default_now
) -> Callable[..., Principal]:
    """Factory that returns a FastAPI dependency closing over the secret+clock."""

    async def _dep(
        creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> Principal:
        if creds is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing authorization header",
            )
        return decode_token(creds.credentials, jwt_secret, now=now)

    return _dep


def require_roles(*roles: Role) -> Callable[[Principal], Principal]:
    """Factory: returns a dep that 403s unless principal.role is in `roles`."""

    def _dep(principal: Principal) -> Principal:
        if principal.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role {principal.role!r} not permitted",
            )
        return principal

    return _dep
```

- [ ] **Step 2: Verify import**

```bash
cd data-plane/reporting && python -c "from reporting.auth import decode_token, make_get_current_principal, require_roles; print('ok')"
```

Expected: `ok`.

- [ ] **Step 3: Stage + ask user to commit**

```bash
git add data-plane/reporting/src/reporting/auth.py
git status
```

Commit message: `feat(reporting): add JWT auth helpers + Principal decoder`

---

## Task 6: Kafka consumer (threat.scores → store)

**Files:**
- Create: `data-plane/reporting/src/reporting/consumer.py`
- Create: `data-plane/reporting/tests/test_consumer.py`

- [ ] **Step 1: Write failing tests**

`data-plane/reporting/tests/test_consumer.py`:

```python
"""Consumer tests — dual-mode _extract_score + run-one-iteration shape."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from intellifim_schemas import ThreatScoreUpdate

from reporting.consumer import _extract_score
from reporting.store import ReportingStore


@dataclass
class FakeMessage:
    """Stand-in for aiokafka.ConsumerRecord — only needs .value bytes."""
    value: bytes


_T = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _make_update(host_id: str = "001", score: float = 42.0) -> ThreatScoreUpdate:
    return ThreatScoreUpdate(
        host_id=host_id, score=score, reason="r", ts=_T,
    )


def test_extract_score_typed_fast_path():
    upd = _make_update()
    result = _extract_score(upd)
    assert result is upd   # identity — fast path returns the instance


def test_extract_score_bytes_path():
    upd = _make_update()
    raw = upd.model_dump_json().encode()
    result = _extract_score(FakeMessage(value=raw))
    assert isinstance(result, ThreatScoreUpdate)
    assert result.host_id == upd.host_id
    assert result.score == upd.score


def test_extract_score_malformed_returns_none():
    # garbage JSON
    assert _extract_score(FakeMessage(value=b"not-json")) is None
    # well-formed JSON but missing required fields
    assert _extract_score(FakeMessage(value=b'{"host_id":"001"}')) is None


@pytest.mark.asyncio
async def test_consumer_writes_to_store(tmp_path):
    """`process_one` writes a valid update into the store."""
    from reporting.consumer import KafkaScoreConsumer

    store = ReportingStore(
        db_path=str(tmp_path / "reporting.db"),
        reports_dir=str(tmp_path / "reports"),
    )
    await store.init_schema()
    try:
        consumer = KafkaScoreConsumer(
            store=store, bootstrap="ignored", topic="threat.scores", group_id="g"
        )
        upd = _make_update(host_id="999", score=77.0)
        await consumer.process_one(FakeMessage(value=upd.model_dump_json().encode()))
        rows = await store.query_scores(
            start=_T.replace(year=2029), end=_T.replace(year=2031)
        )
        assert len(rows) == 1
        assert rows[0].host_id == "999"
        assert rows[0].score == 77.0

        # Malformed message must NOT raise; partition must keep moving.
        await consumer.process_one(FakeMessage(value=b"garbage"))
        rows2 = await store.query_scores(
            start=_T.replace(year=2029), end=_T.replace(year=2031)
        )
        assert len(rows2) == 1   # still only one row
    finally:
        await store.aclose()
```

- [ ] **Step 2: Run failing tests**

```bash
pytest tests/test_consumer.py -v
```

Expected: All FAIL with `ImportError`.

- [ ] **Step 3: Implement consumer.py**

`data-plane/reporting/src/reporting/consumer.py`:

```python
"""aiokafka consumer that tails `threat.scores` into the reporting store."""
from __future__ import annotations

import json
import logging
from collections.abc import Awaitable

from aiokafka import AIOKafkaConsumer
from pydantic import ValidationError

from intellifim_schemas import ThreatScoreUpdate

from reporting.store import ReportingStore


logger = logging.getLogger(__name__)


def _extract_score(message) -> ThreatScoreUpdate | None:
    """Dual-mode: accept a typed ThreatScoreUpdate OR an object with .value bytes.

    Returns None for any decode/validation failure — the loop logs + skips so a
    single bad message can't stall the partition.
    """
    if isinstance(message, ThreatScoreUpdate):
        return message

    raw = getattr(message, "value", None)
    if not isinstance(raw, (bytes, bytearray)):
        return None
    try:
        payload = json.loads(raw)
        return ThreatScoreUpdate.model_validate(payload)
    except (json.JSONDecodeError, ValidationError, ValueError) as e:
        logger.warning("malformed threat.scores message: %s", e)
        return None


class KafkaScoreConsumer:
    def __init__(
        self,
        *,
        store: ReportingStore,
        bootstrap: str,
        topic: str,
        group_id: str,
    ) -> None:
        self._store = store
        self._bootstrap = bootstrap
        self._topic = topic
        self._group_id = group_id
        self._consumer: AIOKafkaConsumer | None = None

    async def start(self) -> None:
        self._consumer = AIOKafkaConsumer(
            self._topic,
            bootstrap_servers=self._bootstrap,
            group_id=self._group_id,
            auto_offset_reset="latest",
            enable_auto_commit=True,
        )
        await self._consumer.start()
        logger.info("kafka consumer started: topic=%s group=%s", self._topic, self._group_id)

    async def stop(self) -> None:
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None

    async def process_one(self, message) -> None:
        """Decode + persist a single message. Never raises on bad payload."""
        upd = _extract_score(message)
        if upd is None:
            return
        await self._store.insert_score(
            host_id=upd.host_id, score=upd.score, reason=upd.reason, ts=upd.ts
        )

    async def run(self) -> None:
        """Long-running consume loop. Caller is responsible for cancelation."""
        assert self._consumer is not None, "start() not called"
        async for msg in self._consumer:
            try:
                await self.process_one(msg)
            except Exception:   # defensive — never let a single bad event kill the loop
                logger.exception("error processing threat.scores message; continuing")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_consumer.py -v
```

Expected: `4 passed` (the 3 stated tests + the async `test_consumer_writes_to_store` which covers extra ground).

> Note: this task ships **4** tests (3 unit + 1 integration with store). The plan's spec target was 3; that was the unit-only count. Adding the store-integration test brings us to a useful 4 with no scope creep.

- [ ] **Step 5: Stage + ask user to commit**

```bash
git add data-plane/reporting/src/reporting/consumer.py \
        data-plane/reporting/tests/test_consumer.py
git status
```

Commit message: `feat(reporting): add Kafka consumer for threat.scores`

---

## Task 7: Orchestrator HTTP client

**Files:**
- Create: `data-plane/reporting/src/reporting/orchestrator_client.py`
- Create: `data-plane/reporting/tests/test_orchestrator_client.py`

- [ ] **Step 1: Write failing tests**

`data-plane/reporting/tests/test_orchestrator_client.py`:

```python
"""Orchestrator client tests — uses respx to mock /approvals responses."""
from __future__ import annotations

import httpx
import pytest
import respx

from reporting.orchestrator_client import (
    OrchestratorClient,
    OrchestratorError,
)


@pytest.fixture
async def client():
    c = OrchestratorClient(base_url="http://orch:8200")
    yield c
    await c.aclose()


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_list_approvals_happy_path(respx_mock, client):
    respx_mock.get("http://orch:8200/approvals").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "host_id": "001", "priority": "HIGH", "score": 42.0,
                    "last_reason": "r", "state": "PENDING",
                    "created_at": "2030-01-01T00:00:00+00:00",
                    "decided_at": None, "executed_at": None,
                    "decided_by": None, "error_message": None,
                },
            ],
        )
    )
    rows = await client.list_approvals(jwt="ey.fake.token")
    assert len(rows) == 1
    assert rows[0]["host_id"] == "001"


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_list_approvals_forwards_bearer_header(respx_mock, client):
    route = respx_mock.get("http://orch:8200/approvals").mock(
        return_value=httpx.Response(200, json=[])
    )
    await client.list_approvals(jwt="abc.def.ghi")
    sent = route.calls.last.request
    assert sent.headers["authorization"] == "Bearer abc.def.ghi"


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_list_approvals_raises_on_5xx(respx_mock, client):
    respx_mock.get("http://orch:8200/approvals").mock(
        return_value=httpx.Response(503, json={"error": "down"})
    )
    with pytest.raises(OrchestratorError) as exc:
        await client.list_approvals(jwt="t")
    assert exc.value.status == 503
```

- [ ] **Step 2: Run failing tests**

```bash
pytest tests/test_orchestrator_client.py -v
```

Expected: 3 FAIL with `ImportError`.

- [ ] **Step 3: Implement orchestrator_client.py**

`data-plane/reporting/src/reporting/orchestrator_client.py`:

```python
"""HTTP client wrapper for the response-orchestrator /approvals API.

Single shared httpx.AsyncClient instance per process. `aclose()` discipline
matches OpaClient + RedisScoreStore from sub-project #4.
"""
from __future__ import annotations

from typing import Any

import httpx


class OrchestratorError(RuntimeError):
    """Raised when the orchestrator returns a non-2xx or is unreachable."""

    def __init__(self, message: str, *, status: int) -> None:
        super().__init__(message)
        self.status = status


class OrchestratorClient:
    def __init__(self, base_url: str, *, timeout: float = 5.0) -> None:
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def list_approvals(self, *, jwt: str) -> list[dict[str, Any]]:
        """Fetch all approvals (no server-side filter in v1).

        Forwards the caller's Bearer token verbatim so the orchestrator's
        existing JWT middleware + RBAC sees the actual requesting user.
        """
        try:
            response = await self._client.get(
                "/approvals",
                headers={"Authorization": f"Bearer {jwt}"},
            )
        except httpx.RequestError as e:
            raise OrchestratorError(
                f"could not reach response-orchestrator: {e}", status=502
            ) from e
        if response.status_code >= 500:
            raise OrchestratorError(
                f"orchestrator returned {response.status_code}",
                status=response.status_code,
            )
        if response.status_code >= 400:
            raise OrchestratorError(
                f"orchestrator rejected request: {response.status_code} {response.text}",
                status=response.status_code,
            )
        data = response.json()
        if not isinstance(data, list):
            raise OrchestratorError(
                f"unexpected /approvals body shape: {type(data).__name__}", status=502
            )
        return data
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_orchestrator_client.py -v
```

Expected: `3 passed`.

- [ ] **Step 5: Stage + ask user to commit**

```bash
git add data-plane/reporting/src/reporting/orchestrator_client.py \
        data-plane/reporting/tests/test_orchestrator_client.py
git status
```

Commit message: `feat(reporting): add OrchestratorClient httpx wrapper`

---

## Task 8: Renderer (Jinja2 + matplotlib + WeasyPrint)

**Files:**
- Create: `data-plane/reporting/src/reporting/templates/security_summary.html.j2`
- Create: `data-plane/reporting/src/reporting/renderer.py`
- Create: `data-plane/reporting/tests/test_renderer.py`

- [ ] **Step 1: Write failing tests**

`data-plane/reporting/tests/test_renderer.py`:

```python
"""Renderer tests — chart SVG bytes, Jinja2 HTML, WeasyPrint PDF bytes."""
from __future__ import annotations

from reporting.renderer import render_chart, render_html, render_pdf


def test_render_chart_returns_svg_bytes():
    rows = [("hostA", 80.0), ("hostB", 50.0), ("hostC", 10.0)]
    svg = render_chart(rows, title="Top hosts")
    # SVG must start with <?xml ...?> or <svg ...>; just sanity check
    assert svg.startswith(b"<?xml") or svg.startswith(b"<svg"), svg[:80]
    # Hosts should appear in the SVG text
    assert b"hostA" in svg


def test_render_chart_handles_empty_data():
    svg = render_chart([], title="Top hosts")
    assert svg.startswith(b"<?xml") or svg.startswith(b"<svg")
    assert b"No data" in svg


def test_render_html_contains_expected_strings():
    html = render_html({
        "title": "My Report",
        "range_start": "2030-01-01T00:00:00+00:00",
        "range_end": "2030-01-02T00:00:00+00:00",
        "generated_at": "2030-01-01T12:00:00+00:00",
        "generated_by": "alice",
        "stats": {
            "approvals_total": 3,
            "approvals_by_state": {"PENDING": 1, "EXECUTED": 2},
            "approvals_by_priority": {"HIGH": 2, "LOW": 1},
            "scores_total": 10,
            "unique_hosts": 2,
        },
        "chart_svg_b64": "PHN2Zy8+",   # tiny fake base64
        "approvals": [
            {
                "id": "00000000-0000-0000-0000-000000000001",
                "host_id": "001", "priority": "HIGH", "score": 42.0,
                "last_reason": "r", "state": "EXECUTED",
                "created_at": "2030-01-01T01:00:00+00:00",
                "decided_at": "2030-01-01T01:05:00+00:00",
                "decided_by": "alice",
            },
        ],
    })
    assert "My Report" in html
    assert "alice" in html
    assert "001" in html
    assert "EXECUTED" in html
    assert "data:image/svg+xml;base64,PHN2Zy8+" in html


def test_render_pdf_starts_with_pdf_magic():
    """End-to-end: minimal HTML → PDF bytes start with %PDF-."""
    html = "<html><body><h1>Hi</h1></body></html>"
    pdf = render_pdf(html)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 200
```

- [ ] **Step 2: Run failing tests**

```bash
pytest tests/test_renderer.py -v
```

Expected: 4 FAIL with `ImportError` (renderer module missing).

> Note: if your local Python lacks WeasyPrint native deps (libpango/libcairo), this test file will fail at import time of `weasyprint` even after the implementation lands. That's expected — the tests are intended to run inside the Docker image. If you want to validate locally, install the libs (`brew install pango cairo` on macOS; `apt install libpango-1.0-0 libcairo2` on Debian).

- [ ] **Step 3: Write the Jinja2 template**

`data-plane/reporting/src/reporting/templates/security_summary.html.j2`:

```jinja
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{{ title }}</title>
  <style>
    @page { size: A4; margin: 2cm; }
    body { font-family: "DejaVu Sans", Helvetica, Arial, sans-serif; color: #1a1a1a; font-size: 11pt; }
    h1 { font-size: 22pt; margin-bottom: 0.2em; }
    h2 { font-size: 14pt; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 32px; }
    .meta { color: #666; font-size: 10pt; margin-bottom: 24px; }
    .meta div { margin: 2px 0; }
    .stats { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 8px; }
    .stat-card { border: 1px solid #ddd; border-radius: 4px; padding: 10px 14px; min-width: 130px; }
    .stat-card .label { font-size: 9pt; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-card .value { font-size: 18pt; font-weight: bold; }
    .chart { margin: 16px 0; text-align: center; }
    .chart img { max-width: 100%; height: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 10pt; margin-top: 8px; }
    th, td { padding: 6px 8px; border-bottom: 1px solid #eee; text-align: left; vertical-align: top; }
    th { background: #f5f5f5; font-weight: 600; text-transform: uppercase; font-size: 9pt; color: #444; }
    .priority-HIGH { color: #c0392b; font-weight: bold; }
    .priority-LOW { color: #2980b9; }
    .state-PENDING { color: #c0a000; }
    .state-EXECUTED { color: #27ae60; }
    .state-REJECTED { color: #888; }
    .state-FAILED { color: #c0392b; }
    .state-APPROVED { color: #2980b9; }
    .empty { color: #888; font-style: italic; padding: 12px 0; }
  </style>
</head>
<body>
  <h1>{{ title }}</h1>
  <div class="meta">
    <div><strong>Range:</strong> {{ range_start }} → {{ range_end }}</div>
    <div><strong>Generated:</strong> {{ generated_at }} by {{ generated_by }}</div>
  </div>

  <h2>Executive Summary</h2>
  <div class="stats">
    <div class="stat-card">
      <div class="label">Approvals</div>
      <div class="value">{{ stats.approvals_total }}</div>
    </div>
    {% for state, count in stats.approvals_by_state.items() %}
      <div class="stat-card">
        <div class="label">{{ state }}</div>
        <div class="value">{{ count }}</div>
      </div>
    {% endfor %}
    {% for priority, count in stats.approvals_by_priority.items() %}
      <div class="stat-card">
        <div class="label">{{ priority }} priority</div>
        <div class="value">{{ count }}</div>
      </div>
    {% endfor %}
    <div class="stat-card">
      <div class="label">Score samples</div>
      <div class="value">{{ stats.scores_total }}</div>
    </div>
    <div class="stat-card">
      <div class="label">Unique hosts</div>
      <div class="value">{{ stats.unique_hosts }}</div>
    </div>
  </div>

  <h2>Threat Scores — top hosts by max</h2>
  <div class="chart">
    <img src="data:image/svg+xml;base64,{{ chart_svg_b64 }}" alt="Top hosts by max threat score" />
  </div>

  <h2>Approvals</h2>
  {% if approvals %}
    <table>
      <thead>
        <tr>
          <th>Host</th><th>Priority</th><th>State</th><th>Score</th>
          <th>Created</th><th>Decided</th><th>Decided by</th><th>Reason</th>
        </tr>
      </thead>
      <tbody>
      {% for a in approvals %}
        <tr>
          <td>{{ a.host_id }}</td>
          <td class="priority-{{ a.priority }}">{{ a.priority }}</td>
          <td class="state-{{ a.state }}">{{ a.state }}</td>
          <td>{{ "%.1f"|format(a.score) }}</td>
          <td>{{ a.created_at }}</td>
          <td>{{ a.decided_at or "" }}</td>
          <td>{{ a.decided_by or "" }}</td>
          <td>{{ a.last_reason }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  {% else %}
    <div class="empty">No approvals in range.</div>
  {% endif %}
</body>
</html>
```

- [ ] **Step 4: Implement renderer.py**

`data-plane/reporting/src/reporting/renderer.py`:

```python
"""Renderer: matplotlib chart → SVG bytes; Jinja2 + WeasyPrint → PDF bytes.

Pattern:
  render_chart(rows, title)  ->  bytes (SVG)
  render_html(context)       ->  str   (HTML)
  render_pdf(html)           ->  bytes (PDF)
"""
from __future__ import annotations

import io
import logging
from pathlib import Path

import matplotlib
matplotlib.use("Agg")     # MUST be before matplotlib.pyplot import
import matplotlib.pyplot as plt   # noqa: E402

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML


logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "htm", "xml"]),
)


def render_chart(rows: list[tuple[str, float]], *, title: str) -> bytes:
    """Render a top-hosts-by-max-score bar chart to SVG bytes."""
    fig, ax = plt.subplots(figsize=(8, 4), dpi=100)
    if not rows:
        ax.text(0.5, 0.5, "No data in range", ha="center", va="center",
                transform=ax.transAxes, color="#888", fontsize=14)
        ax.set_xticks([])
        ax.set_yticks([])
    else:
        hosts = [r[0] for r in rows]
        scores = [r[1] for r in rows]
        ax.barh(hosts, scores, color="#c0392b")
        ax.invert_yaxis()
        ax.set_xlabel("Max threat score")
        ax.set_xlim(0, max(100.0, max(scores) * 1.1))
        for i, v in enumerate(scores):
            ax.text(v + 1, i, f"{v:.1f}", va="center", fontsize=9)
    ax.set_title(title)
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="svg")
    plt.close(fig)
    return buf.getvalue()


def render_html(context: dict) -> str:
    template = _env.get_template("security_summary.html.j2")
    return template.render(**context)


def render_pdf(html: str) -> bytes:
    return HTML(string=html).write_pdf()
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_renderer.py -v
```

Expected: `4 passed` (assuming WeasyPrint native deps are present; if you only have a Docker-validated env, run from inside the built image — see Task 11 for `docker run` invocation).

- [ ] **Step 6: Stage + ask user to commit**

```bash
git add data-plane/reporting/src/reporting/renderer.py \
        data-plane/reporting/src/reporting/templates/security_summary.html.j2 \
        data-plane/reporting/tests/test_renderer.py
git status
```

Commit message: `feat(reporting): add Jinja2 + matplotlib + WeasyPrint renderer`

---

## Task 9: FastAPI app factory

**Files:**
- Create: `data-plane/reporting/src/reporting/api.py`
- Create: `data-plane/reporting/tests/test_api.py`

- [ ] **Step 1: Write failing tests**

`data-plane/reporting/tests/test_api.py`:

```python
"""FastAPI app factory tests using TestClient + respx for orchestrator mock."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from jose import jwt

from reporting.api import build_app
from reporting.orchestrator_client import OrchestratorClient
from reporting.store import ReportingStore


_T0 = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_SECRET = "test-jwt-secret"


def _make_token(*, username: str, role: str, exp_offset_s: int = 3600) -> str:
    iat = int(_T0.timestamp())
    exp = iat + exp_offset_s
    payload = {
        "sub": str(UUID("00000000-0000-0000-0000-000000000010")),
        "username": username, "email": f"{username}@x.io",
        "role": role, "iat": iat, "exp": exp,
    }
    return jwt.encode(payload, _SECRET, algorithm="HS256")


@pytest.fixture
async def deps(tmp_path):
    store = ReportingStore(
        db_path=str(tmp_path / "reporting.db"),
        reports_dir=str(tmp_path / "reports"),
    )
    await store.init_schema()
    orch = OrchestratorClient(base_url="http://orch:8200")
    yield store, orch
    await orch.aclose()
    await store.aclose()


def _client(store, orch) -> TestClient:
    app = build_app(
        store=store, orchestrator=orch,
        jwt_secret=_SECRET, jwt_ttl_seconds=3600,
        cors_origins=("http://localhost:5173",),
        now=lambda: _T0,
    )
    return TestClient(app)


@pytest.mark.asyncio
async def test_healthz_returns_ok(deps):
    store, orch = deps
    with _client(store, orch) as c:
        r = c.get("/healthz")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_missing_jwt_returns_401(deps):
    store, orch = deps
    with _client(store, orch) as c:
        r = c.get("/reports")
        assert r.status_code == 401
        assert "error" in r.json()


@pytest.mark.asyncio
async def test_viewer_cannot_generate(deps):
    store, orch = deps
    token = _make_token(username="vix", role="viewer")
    with _client(store, orch) as c:
        r = c.post(
            "/reports/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "summary",
                "range_start": "2030-01-01T00:00:00+00:00",
                "range_end": "2030-01-02T00:00:00+00:00",
            },
        )
        assert r.status_code == 403
        assert "error" in r.json()


@pytest.mark.asyncio
async def test_range_too_long_returns_400(deps):
    store, orch = deps
    token = _make_token(username="alice", role="admin")
    with _client(store, orch) as c:
        r = c.post(
            "/reports/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "summary",
                "range_start": "2030-01-01T00:00:00+00:00",
                "range_end": "2030-06-01T00:00:00+00:00",   # > 90 days
            },
        )
        assert r.status_code == 422 or r.status_code == 400
        assert "error" in r.json()


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_generate_happy_path(respx_mock, deps, tmp_path):
    store, orch = deps
    # Insert a couple of scores in range
    await store.insert_score(host_id="001", score=42.0, reason="r", ts=_T0)
    await store.insert_score(host_id="002", score=99.0, reason="r", ts=_T0)
    respx_mock.get("http://orch:8200/approvals").mock(
        return_value=httpx.Response(200, json=[
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "host_id": "001", "priority": "HIGH", "score": 80.0,
                "last_reason": "r", "state": "EXECUTED",
                "created_at": "2030-01-01T01:00:00+00:00",
                "decided_at": "2030-01-01T01:05:00+00:00",
                "executed_at": "2030-01-01T01:05:30+00:00",
                "decided_by": "alice", "error_message": None,
            },
        ])
    )
    token = _make_token(username="alice", role="admin")
    with _client(store, orch) as c:
        r = c.post(
            "/reports/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "daily",
                "range_start": "2030-01-01T00:00:00+00:00",
                "range_end": "2030-01-02T00:00:00+00:00",
            },
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["name"] == "daily"
        assert body["generated_by"] == "alice"
        assert body["size_bytes"] > 0
        assert body["approvals_count"] == 1
        assert body["scores_count"] == 2

        # Download endpoint returns PDF bytes
        rid = body["id"]
        r2 = c.get(
            f"/reports/{rid}/download",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r2.status_code == 200
        assert r2.headers["content-type"] == "application/pdf"
        assert r2.content.startswith(b"%PDF-")


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_orchestrator_unreachable_returns_502(respx_mock, deps):
    store, orch = deps
    respx_mock.get("http://orch:8200/approvals").mock(
        side_effect=httpx.ConnectError("nope")
    )
    token = _make_token(username="alice", role="admin")
    with _client(store, orch) as c:
        r = c.post(
            "/reports/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "x",
                "range_start": "2030-01-01T00:00:00+00:00",
                "range_end": "2030-01-02T00:00:00+00:00",
            },
        )
        assert r.status_code == 502
        assert "error" in r.json()


@pytest.mark.asyncio
async def test_delete_admin_only(deps, tmp_path):
    store, orch = deps
    rid = uuid4()
    pdf_path = f"{tmp_path / 'reports'}/2030-01-01-{rid}.pdf"
    import os
    os.makedirs(str(tmp_path / "reports"), exist_ok=True)
    with open(pdf_path, "wb") as f:
        f.write(b"%PDF-1.4\n")
    await store.insert_report(
        id=rid, name="x", range_start_iso="2030-01-01T00:00:00+00:00",
        range_end_iso="2030-01-02T00:00:00+00:00",
        generated_at_iso="2030-01-01T00:00:00+00:00", generated_by="alice",
        pdf_path=pdf_path, size_bytes=9, approvals_count=0, scores_count=0,
    )

    analyst_token = _make_token(username="ann", role="analyst")
    admin_token = _make_token(username="alice", role="admin")
    with _client(store, orch) as c:
        r = c.delete(f"/reports/{rid}",
                     headers={"Authorization": f"Bearer {analyst_token}"})
        assert r.status_code == 403

        r = c.delete(f"/reports/{rid}",
                     headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200

        r = c.delete(f"/reports/{rid}",
                     headers={"Authorization": f"Bearer {admin_token}"})
        # second delete returns 404 (idempotent: it's gone)
        assert r.status_code == 404
```

- [ ] **Step 2: Run failing tests**

```bash
pytest tests/test_api.py -v
```

Expected: 7 FAIL with `ImportError`.

- [ ] **Step 3: Implement api.py**

`data-plane/reporting/src/reporting/api.py`:

```python
"""FastAPI app factory for the reporting service.

`build_app(...)` returns a configured FastAPI instance with all routes,
auth wiring, exception handlers, and CORS. `now` is threaded through to
the JWT decoder so tests share the fixed test clock (lesson from #6 Task 8).
"""
from __future__ import annotations

import base64
import logging
import os
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from reporting.auth import make_get_current_principal, require_roles
from reporting.models import (
    GenerateReportRequest,
    Principal,
    ReportListResponse,
    ReportMetadata,
)
from reporting.orchestrator_client import OrchestratorClient, OrchestratorError
from reporting.renderer import render_chart, render_html, render_pdf
from reporting.store import ReportingStore


logger = logging.getLogger(__name__)


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _row_to_metadata(row) -> ReportMetadata:
    return ReportMetadata(
        id=row.id, name=row.name,
        range_start=row.range_start, range_end=row.range_end,
        generated_at=row.generated_at, generated_by=row.generated_by,
        size_bytes=row.size_bytes,
        approvals_count=row.approvals_count,
        scores_count=row.scores_count,
    )


def build_app(
    *,
    store: ReportingStore,
    orchestrator: OrchestratorClient,
    jwt_secret: str,
    jwt_ttl_seconds: int,
    cors_origins: tuple[str, ...],
    now: Callable[[], datetime] = _default_now,
) -> FastAPI:
    app = FastAPI(title="intellifim-reporting", default_response_class=JSONResponse)
    app.state.now = now

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # --- exception handlers (uniform error envelope) ---
    @app.exception_handler(HTTPException)
    async def _http_exc(_: Request, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"error": str(exc.detail)})

    @app.exception_handler(ValidationError)
    async def _validation_exc(_: Request, exc: ValidationError):
        return JSONResponse(status_code=400, content={"error": exc.errors()[0]["msg"]})

    @app.exception_handler(Exception)
    async def _unknown_exc(_: Request, exc: Exception):
        logger.exception("unhandled exception")
        return JSONResponse(status_code=500, content={"error": "internal server error"})

    # FastAPI's own RequestValidationError → 400
    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(RequestValidationError)
    async def _request_validation_exc(_: Request, exc: RequestValidationError):
        msgs = exc.errors()
        first = msgs[0] if msgs else {"msg": "invalid request"}
        return JSONResponse(status_code=422, content={"error": first.get("msg", "invalid request")})

    # --- auth deps ---
    get_principal = make_get_current_principal(jwt_secret, now=now)
    require_admin_or_analyst = require_roles("admin", "analyst")
    require_admin = require_roles("admin")

    def admin_or_analyst_dep(p: Principal = Depends(get_principal)) -> Principal:
        return require_admin_or_analyst(p)

    def admin_dep(p: Principal = Depends(get_principal)) -> Principal:
        return require_admin(p)

    # --- routes ---
    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/reports/generate", status_code=201, response_model=ReportMetadata)
    async def generate(
        body: GenerateReportRequest,
        request: Request,
        principal: Principal = Depends(admin_or_analyst_dep),
    ) -> ReportMetadata:
        # Forward the caller's bearer token to the orchestrator
        auth_header = request.headers.get("authorization", "")
        jwt_token = auth_header.removeprefix("Bearer ").strip()

        try:
            approvals = await orchestrator.list_approvals(jwt=jwt_token)
        except OrchestratorError as e:
            raise HTTPException(status_code=e.status if e.status >= 500 else 502,
                                detail=str(e)) from e

        # Filter approvals by date range client-side
        approvals_in_range = [
            a for a in approvals
            if body.range_start.isoformat() <= a["created_at"] < body.range_end.isoformat()
        ]

        scores = await store.query_scores(start=body.range_start, end=body.range_end)
        top = await store.top_hosts_by_max_score(
            start=body.range_start, end=body.range_end, limit=10
        )

        # Summary stats
        by_state: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        for a in approvals_in_range:
            by_state[a["state"]] = by_state.get(a["state"], 0) + 1
            by_priority[a["priority"]] = by_priority.get(a["priority"], 0) + 1
        unique_hosts = len({s.host_id for s in scores})

        # Chart → SVG → base64
        svg_bytes = render_chart(top, title="Top hosts by max threat score")
        chart_b64 = base64.b64encode(svg_bytes).decode("ascii")

        generated_at = now()
        rid = uuid4()
        context: dict[str, Any] = {
            "title": body.name,
            "range_start": body.range_start.isoformat(),
            "range_end": body.range_end.isoformat(),
            "generated_at": generated_at.isoformat(),
            "generated_by": principal.username,
            "stats": {
                "approvals_total": len(approvals_in_range),
                "approvals_by_state": by_state,
                "approvals_by_priority": by_priority,
                "scores_total": len(scores),
                "unique_hosts": unique_hosts,
            },
            "chart_svg_b64": chart_b64,
            "approvals": approvals_in_range,
        }

        html = render_html(context)
        pdf_bytes = render_pdf(html)

        date_part = generated_at.strftime("%Y-%m-%d")
        pdf_path = os.path.join(store.reports_dir, f"{date_part}-{rid}.pdf")
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)

        await store.insert_report(
            id=rid, name=body.name,
            range_start_iso=body.range_start.isoformat(),
            range_end_iso=body.range_end.isoformat(),
            generated_at_iso=generated_at.isoformat(),
            generated_by=principal.username,
            pdf_path=pdf_path, size_bytes=len(pdf_bytes),
            approvals_count=len(approvals_in_range),
            scores_count=len(scores),
        )

        return ReportMetadata(
            id=rid, name=body.name,
            range_start=body.range_start, range_end=body.range_end,
            generated_at=generated_at, generated_by=principal.username,
            size_bytes=len(pdf_bytes),
            approvals_count=len(approvals_in_range),
            scores_count=len(scores),
        )

    @app.get("/reports", response_model=ReportListResponse)
    async def list_reports(
        limit: int = 50,
        offset: int = 0,
        principal: Principal = Depends(get_principal),
    ) -> ReportListResponse:
        if limit < 1 or limit > 200:
            raise HTTPException(status_code=400, detail="limit must be in [1, 200]")
        if offset < 0:
            raise HTTPException(status_code=400, detail="offset must be >= 0")
        rows, total = await store.list_reports(limit=limit, offset=offset)
        return ReportListResponse(
            reports=[_row_to_metadata(r) for r in rows], total=total
        )

    @app.get("/reports/{report_id}", response_model=ReportMetadata)
    async def get_one(
        report_id: UUID,
        principal: Principal = Depends(get_principal),
    ) -> ReportMetadata:
        row = await store.get_report(report_id)
        if row is None:
            raise HTTPException(status_code=404, detail="report not found")
        return _row_to_metadata(row)

    @app.get("/reports/{report_id}/download")
    async def download(
        report_id: UUID,
        principal: Principal = Depends(get_principal),
    ) -> Response:
        row = await store.get_report(report_id)
        if row is None:
            raise HTTPException(status_code=404, detail="report not found")
        try:
            with open(row.pdf_path, "rb") as f:
                data = f.read()
        except FileNotFoundError as e:
            raise HTTPException(status_code=500, detail="pdf file missing on disk") from e
        filename = f"{row.name.replace(' ', '_')}-{row.generated_at[:10]}.pdf"
        return Response(
            content=data,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(data)),
            },
        )

    @app.delete("/reports/{report_id}")
    async def delete_one(
        report_id: UUID,
        principal: Principal = Depends(admin_dep),
    ) -> dict[str, str]:
        removed = await store.delete_report(report_id)
        if not removed:
            raise HTTPException(status_code=404, detail="report not found")
        return {"status": "deleted"}

    return app
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_api.py -v
```

Expected: `7 passed`. (Recall: WeasyPrint native deps required — run inside the Docker image if local env can't provide them.)

- [ ] **Step 5: Stage + ask user to commit**

```bash
git add data-plane/reporting/src/reporting/api.py \
        data-plane/reporting/tests/test_api.py
git status
```

Commit message: `feat(reporting): add FastAPI app factory with /reports endpoints`

---

## Task 10: Entry point (__main__.py — uvicorn + consumer co-resident)

**Files:**
- Create: `data-plane/reporting/src/reporting/__main__.py`

(No new tests — the entry point is integration-tested by Compose smoke / DoD #2-#4.)

- [ ] **Step 1: Write __main__.py**

`data-plane/reporting/src/reporting/__main__.py`:

```python
"""Reporting service entry point.

Pattern: nested try/finally over store / orchestrator / consumer; uvicorn
Server runs in the same event loop as the Kafka consumer task. Lifespan
matches the orchestrator's aiohttp+aiokafka co-resident pattern.

`intellifim-reporting` (console_scripts entry in pyproject.toml) invokes
`main()`.
"""
from __future__ import annotations

import asyncio
import logging

import uvicorn

from reporting.api import build_app
from reporting.config import ReportingConfig
from reporting.consumer import KafkaScoreConsumer
from reporting.orchestrator_client import OrchestratorClient
from reporting.store import ReportingStore


logger = logging.getLogger(__name__)


async def _run(cfg: ReportingConfig) -> None:
    store = ReportingStore(db_path=cfg.db_path, reports_dir=cfg.reports_dir)
    await store.init_schema()
    try:
        orchestrator = OrchestratorClient(base_url=cfg.orchestrator_url)
        try:
            consumer = KafkaScoreConsumer(
                store=store,
                bootstrap=cfg.kafka_bootstrap,
                topic=cfg.kafka_topic,
                group_id=cfg.kafka_group_id,
            )
            await consumer.start()
            try:
                app = build_app(
                    store=store,
                    orchestrator=orchestrator,
                    jwt_secret=cfg.jwt_secret,
                    jwt_ttl_seconds=cfg.jwt_ttl_seconds,
                    cors_origins=cfg.cors_origins,
                )
                server_config = uvicorn.Config(
                    app,
                    host=cfg.bind_host,
                    port=cfg.port,
                    log_level="info",
                    access_log=False,
                    loop="asyncio",
                )
                server = uvicorn.Server(server_config)

                consumer_task = asyncio.create_task(
                    consumer.run(), name="kafka-score-consumer"
                )

                logger.info(
                    "reporting service listening: %s:%s | jwt=enabled | "
                    "kafka=%s topic=%s",
                    cfg.bind_host, cfg.port, cfg.kafka_bootstrap, cfg.kafka_topic,
                )

                try:
                    await server.serve()
                finally:
                    consumer_task.cancel()
                    try:
                        await consumer_task
                    except asyncio.CancelledError:
                        pass
            finally:
                await consumer.stop()
        finally:
            await orchestrator.aclose()
    finally:
        await store.aclose()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )
    cfg = ReportingConfig.from_env()
    asyncio.run(_run(cfg))


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify import**

```bash
cd data-plane/reporting && python -c "from reporting.__main__ import main; print('ok')"
```

Expected: `ok`.

- [ ] **Step 3: Run full test suite**

```bash
pytest -v
```

Expected: `27 passed`. (4 config + 6 store + 4 consumer + 3 orchestrator client + 4 renderer + 7 api — taking the +1 bonus from Task 6.)

> **If renderer tests fail locally due to WeasyPrint native deps**, that's expected. The full suite will run green inside the Docker image after Task 11.

- [ ] **Step 4: Stage + ask user to commit**

```bash
git add data-plane/reporting/src/reporting/__main__.py
git status
```

Commit message: `feat(reporting): add service entry point (uvicorn + kafka consumer)`

---

## Task 11: Dockerfile + local build verification

**Files:**
- Create: `data-plane/reporting/Dockerfile`

- [ ] **Step 1: Write Dockerfile**

`data-plane/reporting/Dockerfile`:

```dockerfile
# data-plane/reporting/Dockerfile
# Build context must be data-plane/ (one level up) so we can COPY both
# schemas/ and reporting/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# WeasyPrint native deps + matplotlib font
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 \
        libcairo2 libgdk-pixbuf-2.0-0 \
        libffi-dev shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY reporting /app/reporting
RUN pip install /app/reporting

RUN mkdir -p /data /data/reports

CMD ["intellifim-reporting"]
```

- [ ] **Step 2: Build the image**

```bash
cd data-plane
docker build -f reporting/Dockerfile -t intellifim-reporting:dev .
```

Expected: image builds successfully. First build will take 2–4 minutes (apt + WeasyPrint + matplotlib wheel pulls).

- [ ] **Step 3: Run the test suite inside the image to verify WeasyPrint works**

```bash
docker run --rm \
    -v "$(pwd)/reporting":/work \
    -w /work \
    --entrypoint sh \
    intellifim-reporting:dev \
    -c "pip install -e .[test] && pytest -v"
```

Expected: `27 passed`. All tests including renderer pass because the image has the native libpango/libcairo deps.

- [ ] **Step 4: Stage + ask user to commit**

```bash
git add data-plane/reporting/Dockerfile
git status
```

Commit message: `feat(reporting): add Dockerfile with WeasyPrint native deps`

---

## Task 12: docker-compose.yml integration

**Files:**
- Modify: `data-plane/docker-compose.yml` (add `reporting` service block; add `reporting` to `admin-console` depends_on; add `VITE_REPORTING_API_URL` env; add `reporting_data` volume.)

- [ ] **Step 1: Identify insertion point in docker-compose.yml**

```bash
grep -n "auth-backend:\|admin-console:\|^volumes:\|^services:" data-plane/docker-compose.yml
```

You'll see the existing structure. Insert the new `reporting:` block AFTER `auth-backend:` and BEFORE `admin-console:` so the dependency-order reads top-down.

- [ ] **Step 2: Add the reporting service block**

Locate the `admin-console:` block and insert immediately above it:

```yaml
  reporting:
    build:
      context: .                       # data-plane/ — one level above reporting/
      dockerfile: reporting/Dockerfile
    image: intellifim-reporting:dev
    depends_on:
      kafka:
        condition: service_healthy
      response-orchestrator:
        condition: service_healthy
      auth-backend:
        condition: service_healthy
    environment:
      KAFKA_BOOTSTRAP: kafka:9092
      JWT_SECRET: "${JWT_SECRET}"
      ORCHESTRATOR_URL: "http://response-orchestrator:8200"
      DB_PATH: "/data/reporting.db"
      REPORTS_DIR: "/data/reports"
      CORS_ORIGINS: "http://localhost:5173"
      BIND_HOST: "0.0.0.0"
      PORT: "8300"
    volumes:
      - reporting_data:/data
    ports:
      - "127.0.0.1:8300:8300"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8300/healthz').read()"]
      interval: 10s
      timeout: 5s
      retries: 5
```

- [ ] **Step 3: Add the new volume to the top-level `volumes:` block**

In the `volumes:` mapping at the bottom of the file, add:

```yaml
  reporting_data:
```

(Keep alongside the existing `auth_backend_data`, `orchestrator_data`, etc.)

- [ ] **Step 4: Update `admin-console` to depend on `reporting` + add env var**

Find the `admin-console:` service block and:

1. Under `depends_on:`, add `reporting: { condition: service_healthy }`.
2. Under `environment:`, add `VITE_REPORTING_API_URL: "http://localhost:8300"`.

Resulting `admin-console:` `depends_on:` should look like (existing entries + new one):

```yaml
    depends_on:
      auth-backend:
        condition: service_healthy
      response-orchestrator:
        condition: service_healthy
      reporting:
        condition: service_healthy
```

And `environment:` gains:
```yaml
      VITE_REPORTING_API_URL: "http://localhost:8300"
```

- [ ] **Step 5: Bring the stack up + verify reporting is healthy**

```bash
cd data-plane
# Ensure JWT_SECRET is set (idempotent)
./scripts/init-secrets.sh
docker compose up -d
docker compose ps
```

Expected: `reporting` service shows `Up (healthy)` within ~30 seconds. Total services: **24**.

```bash
curl -s http://127.0.0.1:8300/healthz
```

Expected: `{"status":"ok"}`.

- [ ] **Step 6: Verify the consumer is writing to SQLite**

Wait ~30 seconds for some `threat.scores` traffic to land (the victim-server keeps the pipeline busy).

```bash
docker exec reporting sqlite3 /data/reporting.db "SELECT count(*) FROM threat_scores"
```

Expected: a positive integer. If 0, wait another 30s and retry — the policy-engine emits sparingly.

- [ ] **Step 7: Stage + ask user to commit**

```bash
git add data-plane/docker-compose.yml
git status
```

Commit message: `feat(reporting): wire reporting service into Compose stack (24 services)`

---

## Task 13: React frontend — apiClient + Reports.tsx rewrite

**Files:**
- Modify: `chronos-ai-guard/src/lib/apiClient.ts` (add REPORTING_API_URL export)
- Modify: `chronos-ai-guard/src/pages/Reports.tsx` (rewrite)
- Create (or modify if exists): `chronos-ai-guard/.env.development` (add `VITE_REPORTING_API_URL`)

- [ ] **Step 1: Add REPORTING_API_URL to apiClient.ts**

Open `chronos-ai-guard/src/lib/apiClient.ts`. After the existing `ORCH_API_URL` export, add:

```ts
export const REPORTING_API_URL =
  import.meta.env.VITE_REPORTING_API_URL ?? "http://localhost:8300";
```

Leave `apiFetch()` and 401 handling unchanged.

- [ ] **Step 2: Add VITE_REPORTING_API_URL to .env.development**

`chronos-ai-guard/.env.development`:

If the file exists, append:
```
VITE_REPORTING_API_URL=http://localhost:8300
```

If it doesn't exist, create it with at least:
```
VITE_AUTH_API_URL=http://localhost:8000
VITE_ORCH_API_URL=http://localhost:8200
VITE_REPORTING_API_URL=http://localhost:8300
```

- [ ] **Step 3: Rewrite Reports.tsx**

Replace the entire contents of `chronos-ai-guard/src/pages/Reports.tsx` with:

```tsx
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

import { DashboardLayout } from "@/components/DashboardLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { FileText, Download, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { apiFetch, REPORTING_API_URL } from "@/lib/apiClient";


type ReportMetadata = {
  id: string;
  name: string;
  range_start: string;
  range_end: string;
  generated_at: string;
  generated_by: string;
  size_bytes: number;
  approvals_count: number;
  scores_count: number;
};

type ReportListResponse = {
  reports: ReportMetadata[];
  total: number;
};


function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}


export default function Reports() {
  const { toast } = useToast();
  const { user } = useAuth();
  const qc = useQueryClient();

  const canGenerate = user?.role === "admin" || user?.role === "analyst";

  const today = new Date();
  const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
  const [name, setName] = useState("Daily Security Summary");
  const [rangeStart, setRangeStart] = useState(yesterday.toISOString().slice(0, 16));
  const [rangeEnd, setRangeEnd] = useState(today.toISOString().slice(0, 16));

  const list = useQuery<ReportListResponse, Error>({
    queryKey: ["reports"],
    queryFn: async () => {
      const r = await apiFetch(`${REPORTING_API_URL}/reports?limit=50`);
      if (!r.ok) throw new Error((await r.json()).error ?? `HTTP ${r.status}`);
      return r.json();
    },
  });

  const generate = useMutation({
    mutationFn: async () => {
      const body = {
        name,
        range_start: new Date(rangeStart).toISOString(),
        range_end: new Date(rangeEnd).toISOString(),
      };
      const r = await apiFetch(`${REPORTING_API_URL}/reports/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) throw new Error((await r.json()).error ?? `HTTP ${r.status}`);
      return (await r.json()) as ReportMetadata;
    },
    onSuccess: (created) => {
      toast({ title: "Report generated", description: created.name });
      qc.invalidateQueries({ queryKey: ["reports"] });
    },
    onError: (e: Error) => {
      toast({ title: "Generate failed", description: e.message, variant: "destructive" });
    },
  });

  async function downloadReport(id: string, name: string, generatedAt: string) {
    const r = await apiFetch(`${REPORTING_API_URL}/reports/${id}/download`);
    if (!r.ok) {
      const msg = (await r.json()).error ?? `HTTP ${r.status}`;
      toast({ title: "Download failed", description: msg, variant: "destructive" });
      return;
    }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${name.replace(/\s+/g, "_")}-${generatedAt.slice(0, 10)}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Reports</h1>
            <p className="text-muted-foreground">Generate and download Security Summary PDFs</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled title="CSV export — v2">
              <Download className="mr-2 h-4 w-4" />
              Export CSV
            </Button>
          </div>
        </div>

        {canGenerate && (
          <Card>
            <CardHeader>
              <CardTitle>Generate report</CardTitle>
            </CardHeader>
            <CardContent>
              <form
                className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end"
                onSubmit={(e) => { e.preventDefault(); generate.mutate(); }}
              >
                <div className="md:col-span-2">
                  <Label htmlFor="r-name">Name</Label>
                  <Input id="r-name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} />
                </div>
                <div>
                  <Label htmlFor="r-start">Range start (UTC)</Label>
                  <Input id="r-start" type="datetime-local" value={rangeStart} onChange={(e) => setRangeStart(e.target.value)} required />
                </div>
                <div>
                  <Label htmlFor="r-end">Range end (UTC)</Label>
                  <Input id="r-end" type="datetime-local" value={rangeEnd} onChange={(e) => setRangeEnd(e.target.value)} required />
                </div>
                <div className="md:col-span-4">
                  <Button type="submit" disabled={generate.isPending}>
                    {generate.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <FileText className="mr-2 h-4 w-4" />}
                    Generate PDF
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle>Past reports {list.data ? `(${list.data.total})` : ""}</CardTitle>
          </CardHeader>
          <CardContent>
            {list.isLoading ? (
              <div className="flex items-center text-muted-foreground"><Loader2 className="mr-2 h-4 w-4 animate-spin" />Loading…</div>
            ) : list.error ? (
              <div className="text-destructive">Error: {list.error.message}</div>
            ) : list.data && list.data.reports.length === 0 ? (
              <div className="text-muted-foreground">No reports yet.</div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Range</TableHead>
                    <TableHead>Generated by</TableHead>
                    <TableHead>Generated at</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead>Download</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.data?.reports.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="font-medium">{r.name}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {r.range_start.slice(0, 16)} → {r.range_end.slice(0, 16)}
                      </TableCell>
                      <TableCell>{r.generated_by}</TableCell>
                      <TableCell className="text-sm">{r.generated_at.slice(0, 19)}</TableCell>
                      <TableCell className="text-sm">{fmtBytes(r.size_bytes)}</TableCell>
                      <TableCell>
                        <Button size="sm" variant="outline" onClick={() => downloadReport(r.id, r.name, r.generated_at)}>
                          <Download className="mr-2 h-4 w-4" />
                          Download
                        </Button>
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
}
```

- [ ] **Step 4: Restart admin-console + verify page loads**

```bash
cd data-plane
docker compose restart admin-console
docker compose logs admin-console --tail 30
```

Open browser at `http://localhost:5173`, log in as admin (`admin@intellifim.dev` / `changeme` per Compose defaults), and navigate to the Reports tab. Verify the page renders without console errors, shows the "Generate report" form, and the empty table reads "No reports yet."

- [ ] **Step 5: Stage + ask user to commit**

```bash
git add chronos-ai-guard/src/lib/apiClient.ts \
        chronos-ai-guard/src/pages/Reports.tsx \
        chronos-ai-guard/.env.development
git status
```

Commit message: `feat(reporting): wire React Reports page to reporting service`

---

## Task 14: Smoke script (`generate-report.py`)

**Files:**
- Create: `data-plane/scripts/generate-report.py`

- [ ] **Step 1: Write generate-report.py**

`data-plane/scripts/generate-report.py`:

```python
#!/usr/bin/env python3
"""End-to-end smoke for the reporting service.

Logs into auth-backend, generates a 24h-window report via reporting,
downloads it to /tmp, and reports exit codes per failure mode.

Exit codes:
  0 success
  1 login failed
  2 generate failed
  3 download failed
  4 missing creds env (ADMIN_EMAIL / ADMIN_PASSWORD)
  5 reporting unreachable / auth-backend unreachable
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone


AUTH_URL = os.environ.get("AUTH_URL", "http://127.0.0.1:8000")
REPORTING_URL = os.environ.get("REPORTING_URL", "http://127.0.0.1:8300")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")


def _post(url: str, body: dict, *, token: str | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        method="POST",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read())
        except Exception:
            payload = {"error": str(e)}
        return e.code, payload


def _get_raw(url: str, *, token: str) -> tuple[int, bytes, str]:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read(), r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("Content-Type", "")


def main() -> int:
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        print("missing ADMIN_EMAIL or ADMIN_PASSWORD in env", file=sys.stderr)
        return 4

    # 1. Login
    try:
        status, body = _post(
            f"{AUTH_URL}/auth/login",
            {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
    except urllib.error.URLError as e:
        print(f"auth-backend unreachable: {e}", file=sys.stderr)
        return 5
    if status != 200 or "access_token" not in body:
        print(f"login failed: status={status} body={body}", file=sys.stderr)
        return 1
    token = body["access_token"]
    print(f"login ok (user={body.get('user', {}).get('username')})")

    # 2. Generate a 24h-window report
    now = datetime.now(tz=timezone.utc)
    body = {
        "name": "smoke",
        "range_start": (now - timedelta(hours=24)).isoformat(),
        "range_end": now.isoformat(),
    }
    try:
        status, body = _post(f"{REPORTING_URL}/reports/generate", body, token=token)
    except urllib.error.URLError as e:
        print(f"reporting unreachable: {e}", file=sys.stderr)
        return 5
    if status != 201 or "id" not in body:
        print(f"generate failed: status={status} body={body}", file=sys.stderr)
        return 2
    print(f"generated id={body['id']} size_bytes={body['size_bytes']} "
          f"approvals={body['approvals_count']} scores={body['scores_count']}")

    # 3. Download
    rid = body["id"]
    status, pdf_bytes, ctype = _get_raw(
        f"{REPORTING_URL}/reports/{rid}/download", token=token
    )
    if status != 200:
        print(f"download failed: status={status}", file=sys.stderr)
        return 3
    if not pdf_bytes.startswith(b"%PDF-"):
        print(f"downloaded file is not a PDF (content-type={ctype})", file=sys.stderr)
        return 3
    out_path = f"/tmp/intellifim-smoke-{rid}.pdf"
    with open(out_path, "wb") as f:
        f.write(pdf_bytes)
    print(f"downloaded {len(pdf_bytes)} bytes -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Make executable + run it**

```bash
chmod +x data-plane/scripts/generate-report.py
cd data-plane
# These two env vars are in .env.dataplane; export them in this shell:
export ADMIN_EMAIL=$(grep ^ADMIN_EMAIL= .env.dataplane | cut -d= -f2-)
export ADMIN_PASSWORD=$(grep ^ADMIN_PASSWORD= .env.dataplane | cut -d= -f2-)
./scripts/generate-report.py
echo "exit=$?"
```

Expected:
```
login ok (user=admin)
generated id=<uuid> size_bytes=<n> approvals=<m> scores=<k>
downloaded <n> bytes -> /tmp/intellifim-smoke-<uuid>.pdf
exit=0
```

Open the resulting `/tmp/intellifim-smoke-*.pdf` in any PDF viewer to confirm it's well-formed.

- [ ] **Step 3: Stage + ask user to commit**

```bash
git add data-plane/scripts/generate-report.py
git status
```

Commit message: `feat(reporting): add generate-report.py smoke script`

---

## Task 15: README + DoD walk-through

**Files:**
- Modify: `data-plane/README.md` (add reporting bullets + smoke instructions)

- [ ] **Step 1: Add reporting section to data-plane/README.md**

Find the existing "Services" section in `data-plane/README.md` and add a row/bullet for the reporting service. Find the "Smoke" section (if it exists; sub-projects #4–#6 added similar sections) and add a brief bullet:

In the services list, add (in service-order):
```markdown
- **reporting** (`:8300`) — PDF Security Summary report generation; FastAPI + WeasyPrint + Jinja2 + matplotlib. Consumes `threat.scores` Kafka into local SQLite; fetches `/approvals` from `response-orchestrator` on demand. Persistent report store on `reporting_data` volume.
```

In the smoke section, add:
```markdown
- `./scripts/generate-report.py` — log in as admin, generate a 24h report, download it to `/tmp/`. Requires `ADMIN_EMAIL` + `ADMIN_PASSWORD` in env.
```

Update the service count near the top of the README from "23 services" to "24 services" (if the README states a count — verify before changing).

- [ ] **Step 2: DoD walk-through on a fresh checkout**

This is the final acceptance step. Run from a clean working tree (commits all done, no staged changes).

```bash
cd data-plane

# DoD #1 — full pytest suite green
cd reporting && pytest -v && cd ..
cd ../data-plane && for s in schemas correlator anomaly policy orchestrator auth_backend reporting; do
  echo "--- $s ---"; cd $s && pytest -v && cd ..; done
# Plus Rego: opa eval (skipped here — same as #4)
```

Expected: cumulative 237 passing Python tests + 5 Rego.

```bash
# DoD #2 — fresh compose up brings up 24 services healthy
docker compose down -v   # (DESTRUCTIVE — only run on fresh-checkout DoD; wipes ALL data)
./scripts/init-secrets.sh
docker compose up -d
sleep 30
docker compose ps | grep -c "(healthy)"
```

Expected: ≥ 24 (some services like normalizers don't have healthchecks; count `Up` services separately). Wait until `docker compose ps` shows reporting as `(healthy)`.

```bash
# DoD #3 — healthcheck
curl -s http://127.0.0.1:8300/healthz
```
Expected: `{"status":"ok"}`.

```bash
# DoD #4 — consumer working
sleep 30
docker exec reporting sqlite3 /data/reporting.db "SELECT count(*) FROM threat_scores"
```
Expected: positive integer.

```bash
# DoD #5 — JWT-auth wall
curl -i -X POST http://127.0.0.1:8300/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"name":"x","range_start":"2030-01-01T00:00:00+00:00","range_end":"2030-01-02T00:00:00+00:00"}'
# expect: HTTP/1.1 401
```

```bash
# DoD #6 — end-to-end generate via curl (use smoke script)
export ADMIN_EMAIL=$(grep ^ADMIN_EMAIL= .env.dataplane | cut -d= -f2-)
export ADMIN_PASSWORD=$(grep ^ADMIN_PASSWORD= .env.dataplane | cut -d= -f2-)
./scripts/generate-report.py
```
Expected: exit 0 + `/tmp/intellifim-smoke-*.pdf` exists and starts with `%PDF-`.

```bash
# DoD #7 — persistence across restart
docker compose restart reporting
sleep 10
curl -s -H "Authorization: Bearer $(curl -s -X POST http://127.0.0.1:8000/auth/login \
   -H 'Content-Type: application/json' \
   -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" | jq -r .access_token)" \
   http://127.0.0.1:8300/reports | jq '.total'
```
Expected: ≥ 1 (the one generated in DoD #6 should still be there).

```bash
# DoD #8 — orchestrator unreachable → 502
docker compose stop response-orchestrator
./scripts/generate-report.py
echo "exit=$?"   # expect 2 (generate failed); reporting returned 502
docker compose start response-orchestrator
```

```bash
# DoD #9 — PDF well-formed
pdfinfo /tmp/intellifim-smoke-*.pdf | head -20
```
Expected: Pages: 1 (or more); File size > 200 bytes.

```bash
# DoD #10 — browser end-to-end
# Open http://localhost:5173 in a browser
# Log in as admin (admin@intellifim.dev / changeme)
# Navigate to Reports
# Fill the form, click "Generate PDF"
# Verify the row appears in the table
# Click Download, verify the PDF downloads
```

- [ ] **Step 3: Stage README changes + ask user to commit**

```bash
git add data-plane/README.md
git status
```

Commit message: `docs(reporting): document reporting service in data-plane README`

---

## Post-merge checklist (after PR merges to main)

1. Sync local `main`:
   ```bash
   git checkout main && git pull --ff-only
   ```
2. Update memory files:
   - `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/MEMORY.md`:
     - Add a line for the new shipped sub-project.
     - Move "next up" pointer from #7 to #8 (Simulation lab).
   - `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/project_intellifim_roadmap.md`:
     - Mark row 7 ✅ SHIPPED `YYYY-MM-DD` PR #N squash `<sha>`.
     - Mark row 8 as **next up**.
     - Append new "Critical patterns established in sub-projects #1+…+#7" entries (matplotlib SVG → WeasyPrint inlining, FastAPI + Depends with role gates, blob-based authenticated downloads, etc.).
     - Add a "From #7" v2 deferral block (the §13 list from the spec).
   - Create `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/project_intellifim_reporting_shipped.md` as the frozen snapshot.
   - Update `project_intellifim_v1_shipped.md`: service count 23→24, test total 210→237+5=242.

---

## Plan self-review

### Spec coverage (each spec section → task that implements it)

| Spec section | Implemented in |
|---|---|
| §1 Goal | Tasks 0–15 (end-to-end) |
| §2 Architecture (FastAPI + uvicorn + aiokafka + co-resident loop) | Tasks 0, 9, 10 |
| §3 Scope (in/out) | Whole plan respects scope; deferrals in §13 not implemented |
| §4.1 threat_scores via Kafka | Tasks 3, 6 |
| §4.2 approvals via HTTP forwarding JWT | Tasks 7, 9 |
| §5.1 endpoints | Task 9 |
| §5.2 Pydantic request/response models | Task 2 |
| §5.3 uniform `{"error":...}` envelope | Task 9 (exception handlers) |
| §5.4 JWT validation + `now` injection | Task 5, threaded via Task 9 |
| §6 PDF generation pipeline | Tasks 8, 9 |
| §7.1–7.5 Reports.tsx + apiClient | Task 13 |
| §7.6 zero JS tests (deferred) | Acknowledged — no JS test work |
| §8.1 SQLite tables | Tasks 3, 4 |
| §8.2 ReportingStore class | Tasks 3, 4 |
| §8.3 PDF filesystem layout | Tasks 3, 9 |
| §8.4 internal models | Task 2 |
| §8.5 Jinja2 template | Task 8 |
| §9.1 new Compose service | Task 12 |
| §9.2 admin-console depends_on | Task 12 |
| §9.3 stack count → 24 | Task 12 |
| §9.4 no new Kafka topics | Acknowledged |
| §9.5 no schema bump | Acknowledged |
| §10 Repo layout | Tasks 0–15 (each file maps) |
| §11 testing surface (27 tests) | Tasks 1, 3, 4, 6, 7, 8, 9 |
| §11.2 test infra (`_T0`, `_make_token`) | Tasks 1, 9 |
| §11.3 10 DoD items | Task 15 |
| §11.4 smoke script | Task 14 |
| §12 error handling table | Tasks 6, 9 |
| §13 v2 deferrals | Not implemented (deferred, documented in spec) |
| §14 references | Already in spec |

No gaps.

### Placeholder scan
- No "TBD" / "TODO" / "implement later" / "fill in" found.
- Every test step shows full code.
- Every implementation step shows full code.
- Every command is exact.

### Type / method-name consistency
- `ReportingStore.init_schema/aclose/insert_score/query_scores/top_hosts_by_max_score/insert_report/list_reports/get_report/delete_report` — used identically in tasks 3, 4, 6, 9, 10.
- `ReportingStore.reports_dir` property used in tasks 3 (test), 9 (api).
- `OrchestratorClient(base_url=...).list_approvals(jwt=...)` — used identically in tasks 7, 9, 10.
- `KafkaScoreConsumer(store=..., bootstrap=..., topic=..., group_id=...)` — used identically in tasks 6, 10.
- `render_chart(rows, *, title)` / `render_html(context)` / `render_pdf(html)` — used identically in tasks 8, 9.
- `decode_token(token, secret, *, now)` / `make_get_current_principal(jwt_secret, *, now)` / `require_roles(*roles)` — used identically in tasks 5, 9.
- `Principal(user_id, username, role)` — used identically in tasks 2, 5, 9. Matches orchestrator's analog.
- `GenerateReportRequest` / `ReportMetadata` / `ReportListResponse` — match between models (Task 2) and API (Task 9).
- `build_app(*, store, orchestrator, jwt_secret, jwt_ttl_seconds, cors_origins, now)` — match between Task 9 def and Task 10 call.
- `REPORTING_API_URL` constant — match between Task 13 client + .env.development + Compose env.

All consistent.

---

**Plan ready for execution.**
