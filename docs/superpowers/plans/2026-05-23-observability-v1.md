# Observability v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Prometheus metric instrumentation to all 6 in-house Python services, plus new Prometheus + Grafana + Alertmanager Compose services with auto-provisioned datasource, 2 pre-built dashboards, and 1 example alert rule — bringing the 24-service stack to **27 services** and closing out the v1 walking-skeleton (sub-project #9 of 9).

**Architecture:** Each Python service gains a small `metrics.py` module with 3 lean RED-method metrics (`messages_processed_total`, `errors_total`, `processing_seconds`). FastAPI services auto-instrument HTTP RED via `prometheus-fastapi-instrumentator`; the orchestrator (aiohttp) gets a manual `/metrics` route; the 3 engines (no existing HTTP server) spin up a `prometheus_client.start_http_server()` on a dedicated port (9100/9101/9102). Prometheus scrapes all 6 every 15s, evaluates one example alert rule, and routes firing alerts to Alertmanager's web UI (no Slack/email in v1). Grafana auto-provisions a Prometheus datasource + 2 dashboards (Pipeline overview + Threat & response health).

**Tech Stack:** `prometheus-client>=0.20,<0.22` (all 6 services), `prometheus-fastapi-instrumentator>=7.0,<8` (auth-backend + reporting only), `prom/prometheus:v2.55.0`, `prom/alertmanager:v0.27.0`, `grafana/grafana:11.3.0`. pytest + existing service test harnesses.

**Reference spec:** [`docs/superpowers/specs/2026-05-23-observability-v1-design.md`](../specs/2026-05-23-observability-v1-design.md)

**Reference patterns:**
- `data-plane/reporting/src/reporting/api.py` — FastAPI factory `build_app(...)` pattern (where Instrumentator will mount).
- `data-plane/orchestrator/src/orchestrator/api.py` — aiohttp `app.router.add_get(...)` pattern (where `/metrics` route will land).
- `data-plane/policy/src/policy/engine.py` — engine `_process` pattern (where `with processing_seconds.time():` wraps work).
- `data-plane/docker-compose.yml` — `profiles:`, healthcheck shape, network membership conventions.

**Branch:** Create `feat/observability-v1` off `main` before Task 0.

---

## File Map

```
data-plane/
├── prometheus/                              ← NEW
│   ├── prometheus.yml                       (scrape config + alerting + rule_files)
│   └── alerts.yml                           (IntelliFIMServiceDown rule)
├── alertmanager/                            ← NEW
│   └── alertmanager.yml                     (null-receiver, no outbound integrations)
├── grafana/                                 ← NEW
│   ├── provisioning/
│   │   ├── datasources/
│   │   │   └── prometheus.yml               (auto-provisioned Prometheus datasource)
│   │   └── dashboards/
│   │       └── dashboards.yml               (dashboard provider config)
│   └── dashboards/
│       ├── pipeline-overview.json           (Dashboard 1)
│       └── threat-and-response.json         (Dashboard 2)
├── scripts/
│   └── check-observability.sh               (NEW; verification smoke)

# Each existing service gains a metrics module + 2 tests:
data-plane/auth_backend/src/auth_backend/metrics.py    (NEW)
data-plane/auth_backend/tests/test_metrics.py          (NEW; 2 tests)

data-plane/orchestrator/src/orchestrator/metrics.py    (NEW)
data-plane/orchestrator/tests/test_metrics.py          (NEW; 2 tests)

data-plane/reporting/src/reporting/metrics.py          (NEW)
data-plane/reporting/tests/test_metrics.py             (NEW; 2 tests)

data-plane/correlator/src/correlator/metrics.py        (NEW)
data-plane/correlator/tests/test_metrics.py            (NEW; 2 tests)

data-plane/anomaly/src/anomaly/metrics.py              (NEW)
data-plane/anomaly/tests/test_metrics.py               (NEW; 2 tests)

data-plane/policy/src/policy/metrics.py                (NEW)
data-plane/policy/tests/test_metrics.py                (NEW; 2 tests)

# Existing files modified:
data-plane/auth_backend/pyproject.toml                 (+prometheus-fastapi-instrumentator, +prometheus-client)
data-plane/auth_backend/src/auth_backend/api.py        (+Instrumentator + handler wrap)

data-plane/orchestrator/pyproject.toml                 (+prometheus-client)
data-plane/orchestrator/src/orchestrator/api.py        (+/metrics route + handler wrap)
data-plane/orchestrator/src/orchestrator/engine.py     (+wrap process_one)

data-plane/reporting/pyproject.toml                    (+prometheus-fastapi-instrumentator, +prometheus-client)
data-plane/reporting/src/reporting/api.py              (+Instrumentator + generate wrap)
data-plane/reporting/src/reporting/consumer.py         (+wrap process_one)

data-plane/correlator/pyproject.toml                   (+prometheus-client)
data-plane/correlator/src/correlator/__main__.py       (+start_http_server)
data-plane/correlator/src/correlator/engine.py         (+wrap process_one)

data-plane/anomaly/pyproject.toml                      (+prometheus-client)
data-plane/anomaly/src/anomaly/__main__.py             (+start_http_server)
data-plane/anomaly/src/anomaly/engine.py               (+wrap process_one)

data-plane/policy/pyproject.toml                       (+prometheus-client)
data-plane/policy/src/policy/__main__.py               (+start_http_server)
data-plane/policy/src/policy/engine.py                 (+wrap process_one)

data-plane/docker-compose.yml                          (+prometheus, alertmanager, grafana services; +3 volumes; +engine METRICS_PORT env + port mappings)
data-plane/README.md                                   (+observability section)
```

**Test totals after this sub-project:**
- New: 2 (auth-backend) + 2 (orchestrator) + 2 (reporting) + 2 (correlator) + 2 (anomaly) + 2 (policy) = **12 new Python tests**.
- Suite total: 261 → **273 Python + 5 Rego = 278 total**.

---

## Standing Rules (carried from prior sub-projects)

- **NEVER run `git commit` yourself.** Stage files via `git add <specific paths>` and ask the user to commit. (`feedback_no_self_commits.md`.)
- **Never** `docker compose down -v` unless explicitly part of a fresh-checkout DoD test (wipes Wazuh state).
- **Never** `git add .` or `git add -A`. Stage only files the task lists.
- **Never** `--no-verify` or bypass hooks/signing.
- Use the `[dev]` extra in pyproject.toml (NOT `[test]`) — matches every other service.
- Cross-package pins are RANGES (`>=X,<Y`), never `==`.
- Each service's `metrics.py` is a deliberate 6× duplication — keeps dep graphs clean; do NOT create a shared cross-service Python package.
- Test isolation: counters accumulate across tests. Always read the value before the action + after, assert the DELTA (not the absolute value).
- Bash tool calls don't persist `cwd` between invocations — use absolute paths or `git -C <repo-root>`.

---

## Task 0: Branch + plan/spec staging

**Files:**
- None to create — this is a preparation step.

- [ ] **Step 1: Create branch**

```bash
git checkout main
git pull --ff-only
git checkout -b feat/observability-v1
```

- [ ] **Step 2: Stage the spec + plan from main (they're untracked)**

```bash
git -C /home/aditya/Documents/IntelliFIM add \
    docs/superpowers/specs/2026-05-23-observability-v1-design.md \
    docs/superpowers/plans/2026-05-23-observability-v1.md
git -C /home/aditya/Documents/IntelliFIM status --short
```

Expected: 2 files staged. Ready for the implementation tasks.

---

## Task 1: auth-backend metrics

**Files:**
- Create: `data-plane/auth_backend/src/auth_backend/metrics.py`
- Modify: `data-plane/auth_backend/pyproject.toml` (add 2 deps)
- Modify: `data-plane/auth_backend/src/auth_backend/api.py` (mount Instrumentator + wrap handlers)
- Create: `data-plane/auth_backend/tests/test_metrics.py` (2 tests)

- [ ] **Step 1: Write `metrics.py`**

`data-plane/auth_backend/src/auth_backend/metrics.py`:

```python
"""Per-service Prometheus metrics for auth-backend.

3 lean RED-method counters/histograms, uniform across all 6 in-house services.
"""
from __future__ import annotations

from prometheus_client import Counter, Histogram


SERVICE_LABEL = "auth-backend"

messages_processed_total = Counter(
    "intellifim_messages_processed_total",
    "Number of input messages processed by the service",
    ["service"],
)

errors_total = Counter(
    "intellifim_errors_total",
    "Number of errors encountered by the service",
    ["service", "kind"],
)

processing_seconds = Histogram(
    "intellifim_processing_seconds",
    "End-to-end processing latency per input message",
    ["service"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
```

- [ ] **Step 2: Add deps to pyproject.toml**

`data-plane/auth_backend/pyproject.toml` — in the `dependencies` list, append (after the existing `python-jose...` line):

```toml
    "prometheus-client>=0.20,<0.22",
    "prometheus-fastapi-instrumentator>=7.0,<8",
```

- [ ] **Step 3: Wire Instrumentator + counter wraps into `api.py`**

Modify `data-plane/auth_backend/src/auth_backend/api.py`:

(a) Add imports near the top (after existing FastAPI imports):

```python
from prometheus_fastapi_instrumentator import Instrumentator

from auth_backend.metrics import (
    SERVICE_LABEL,
    errors_total,
    messages_processed_total,
    processing_seconds,
)
```

(b) Inside `build_app(...)`, immediately after `app = FastAPI(...)` (before any route definitions), add:

```python
    Instrumentator().instrument(app).expose(app)
```

(c) In the `/auth/login` handler, wrap the body with the metrics. Locate the existing `async def login(...)` and modify so the entire function body is inside the histogram context manager, plus increment the counter at the end and the error counter in the exception path. Example structure (preserve existing logic):

```python
@app.post("/auth/login", ...)
async def login(body: LoginRequest):
    with processing_seconds.labels(SERVICE_LABEL).time():
        try:
            # ... existing login logic ...
            messages_processed_total.labels(SERVICE_LABEL).inc()
            return result
        except Exception as e:
            errors_total.labels(SERVICE_LABEL, kind=type(e).__name__).inc()
            raise
```

Do the same wrap on `/auth/register`. The `/auth/me` endpoint is a read — do NOT wrap it (the auto-instrumented HTTP metrics already cover it).

- [ ] **Step 4: Write failing tests**

`data-plane/auth_backend/tests/test_metrics.py`:

```python
"""Prometheus metrics tests for auth-backend."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from auth_backend.metrics import SERVICE_LABEL


def _counter_value() -> float:
    val = REGISTRY.get_sample_value(
        "intellifim_messages_processed_total",
        {"service": SERVICE_LABEL},
    )
    return val if val is not None else 0.0


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_prometheus_format(deps):
    """GET /metrics returns 200 with the standard prometheus content type."""
    store, jwt_secret = deps
    from auth_backend.api import build_app
    app = build_app(store=store, jwt_secret=jwt_secret, jwt_ttl_seconds=3600, cors_origins=("http://localhost:5173",))
    with TestClient(app) as c:
        r = c.get("/metrics")
        assert r.status_code == 200
        assert "text/plain" in r.headers["content-type"]
        # Standard FastAPI auto-instrumented metric
        assert "http_requests_total" in r.text
        # Our custom metric (registered but may have no samples yet)
        assert "intellifim_messages_processed_total" in r.text


@pytest.mark.asyncio
async def test_login_increments_messages_processed_counter(deps):
    """After a successful login, the messages counter increments by 1."""
    store, jwt_secret = deps
    # Seed a user
    from auth_backend.store import UsersStore
    await store.add_user(username="alice", email="alice@x.io", password="s3cr3t!", role="admin")
    from auth_backend.api import build_app
    app = build_app(store=store, jwt_secret=jwt_secret, jwt_ttl_seconds=3600, cors_origins=("http://localhost:5173",))
    before = _counter_value()
    with TestClient(app) as c:
        r = c.post("/auth/login", json={"email": "alice@x.io", "password": "s3cr3t!"})
        assert r.status_code == 200
    after = _counter_value()
    assert after - before == 1.0
```

> **Test infra note:** the `deps` fixture is the same one already used in `data-plane/auth_backend/tests/test_api.py`. If it's defined locally there rather than in `conftest.py`, lift its definition into `data-plane/auth_backend/tests/conftest.py` BEFORE running this test. The fixture yields `(store, jwt_secret)` (or whatever the existing test_api.py expects).

> **add_user signature note:** if the existing `UsersStore.add_user` signature differs from what's shown above, adjust the test's seed call accordingly. The test's intent is "ensure a user exists who can log in".

- [ ] **Step 5: Run failing tests**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane/auth_backend
python3 -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_metrics.py -v
```

Expected: 2 FAILs OR ImportError on `prometheus_fastapi_instrumentator` if the dep wasn't installed.

- [ ] **Step 6: Verify both tests pass**

If they were already passing after Step 3+5, you're done. Otherwise diagnose: check that `Instrumentator().instrument(app).expose(app)` runs BEFORE any route definitions, and that the handler wrap is on the `/auth/login` route.

```bash
pytest tests/test_metrics.py -v
pytest -v   # full auth-backend suite (should be 19 prior + 2 new = 21 passed)
```

Expected:
- `tests/test_metrics.py` → **2 passed**
- Full auth-backend suite → **21 passed** (19 prior + 2 new).

- [ ] **Step 7: Stage (DO NOT COMMIT)**

```bash
deactivate
rm -rf .venv
rm -rf /home/aditya/Documents/IntelliFIM/data-plane/schemas/build/
git -C /home/aditya/Documents/IntelliFIM add \
    data-plane/auth_backend/pyproject.toml \
    data-plane/auth_backend/src/auth_backend/metrics.py \
    data-plane/auth_backend/src/auth_backend/api.py \
    data-plane/auth_backend/tests/test_metrics.py \
    data-plane/auth_backend/tests/conftest.py   # only if you lifted the fixture
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(auth-backend): expose Prometheus metrics + custom RED counters`

---

## Task 2: reporting metrics

**Files:**
- Create: `data-plane/reporting/src/reporting/metrics.py`
- Modify: `data-plane/reporting/pyproject.toml` (add 2 deps)
- Modify: `data-plane/reporting/src/reporting/api.py` (mount Instrumentator + wrap generate handler)
- Modify: `data-plane/reporting/src/reporting/consumer.py` (wrap process_one)
- Create: `data-plane/reporting/tests/test_metrics.py` (2 tests)

- [ ] **Step 1: Write `metrics.py`**

`data-plane/reporting/src/reporting/metrics.py`:

```python
"""Per-service Prometheus metrics for reporting.

3 lean RED-method counters/histograms, uniform across all 6 in-house services.
"""
from __future__ import annotations

from prometheus_client import Counter, Histogram


SERVICE_LABEL = "reporting"

messages_processed_total = Counter(
    "intellifim_messages_processed_total",
    "Number of input messages processed by the service",
    ["service"],
)

errors_total = Counter(
    "intellifim_errors_total",
    "Number of errors encountered by the service",
    ["service", "kind"],
)

processing_seconds = Histogram(
    "intellifim_processing_seconds",
    "End-to-end processing latency per input message",
    ["service"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
```

- [ ] **Step 2: Add deps to pyproject.toml**

`data-plane/reporting/pyproject.toml` — in `dependencies` (after the existing `intellifim-schemas` line), add:

```toml
    "prometheus-client>=0.20,<0.22",
    "prometheus-fastapi-instrumentator>=7.0,<8",
```

- [ ] **Step 3: Wire Instrumentator + counter wraps into `api.py`**

Modify `data-plane/reporting/src/reporting/api.py`:

(a) Add imports near the top:

```python
from prometheus_fastapi_instrumentator import Instrumentator

from reporting.metrics import (
    SERVICE_LABEL,
    errors_total,
    messages_processed_total,
    processing_seconds,
)
```

(b) Inside `build_app(...)`, immediately after `app = FastAPI(...)`:

```python
    Instrumentator().instrument(app).expose(app)
```

(c) Wrap the existing `/reports/generate` handler body with the metrics:

```python
@app.post("/reports/generate", ...)
async def generate(body: GenerateReportRequest, request: Request, principal: Principal = Depends(admin_or_analyst_dep)):
    with processing_seconds.labels(SERVICE_LABEL).time():
        try:
            # ... existing generate logic, including PDF render + store insert ...
            messages_processed_total.labels(SERVICE_LABEL).inc()
            return ReportMetadata(...)
        except HTTPException:
            raise   # already counted as 4xx/5xx by Instrumentator
        except Exception as e:
            errors_total.labels(SERVICE_LABEL, kind=type(e).__name__).inc()
            raise
```

- [ ] **Step 4: Wrap the Kafka consumer's `process_one` in `consumer.py`**

Modify `data-plane/reporting/src/reporting/consumer.py` — locate the existing `async def process_one(self, message)` in `KafkaScoreConsumer`. Wrap the body:

```python
    async def process_one(self, message) -> None:
        """Decode + persist a single message. Never raises on bad payload."""
        from reporting.metrics import (
            SERVICE_LABEL,
            errors_total,
            messages_processed_total,
            processing_seconds,
        )
        with processing_seconds.labels(SERVICE_LABEL).time():
            upd = _extract_score(message)
            if upd is None:
                return
            try:
                await self._store.insert_score(
                    host_id=upd.host_id, score=upd.score, reason=upd.reason, ts=upd.ts
                )
                messages_processed_total.labels(SERVICE_LABEL).inc()
            except Exception as e:
                errors_total.labels(SERVICE_LABEL, kind=type(e).__name__).inc()
                raise
```

> The import inside the method is intentional: keeps the metrics module a soft dep when running this module without prometheus_client installed (only the actual call site needs it). Alternatively hoist to module-top — pick whatever matches the existing import style of the file.

- [ ] **Step 5: Write failing tests**

`data-plane/reporting/tests/test_metrics.py`:

```python
"""Prometheus metrics tests for reporting."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from jose import jwt
from prometheus_client import REGISTRY

from reporting.api import build_app
from reporting.orchestrator_client import OrchestratorClient
from reporting.metrics import SERVICE_LABEL
from reporting.store import ReportingStore


_T0 = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_SECRET = "test-jwt-secret"


def _counter_value() -> float:
    val = REGISTRY.get_sample_value(
        "intellifim_messages_processed_total",
        {"service": SERVICE_LABEL},
    )
    return val if val is not None else 0.0


def _make_token(*, username: str, role: str) -> str:
    payload = {
        "sub": "00000000-0000-0000-0000-000000000010",
        "username": username, "email": f"{username}@x.io",
        "role": role, "iat": int(_T0.timestamp()), "exp": int(_T0.timestamp()) + 3600,
    }
    return jwt.encode(payload, _SECRET, algorithm="HS256")


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_prometheus_format(tmp_path):
    store = ReportingStore(db_path=str(tmp_path / "reporting.db"), reports_dir=str(tmp_path / "reports"))
    await store.init_schema()
    orch = OrchestratorClient(base_url="http://orch:8200")
    try:
        app = build_app(
            store=store, orchestrator=orch,
            jwt_secret=_SECRET, jwt_ttl_seconds=3600,
            cors_origins=("http://localhost:5173",),
            now=lambda: _T0,
        )
        with TestClient(app) as c:
            r = c.get("/metrics")
            assert r.status_code == 200
            assert "text/plain" in r.headers["content-type"]
            assert "intellifim_messages_processed_total" in r.text
    finally:
        await orch.aclose()
        await store.aclose()


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_generate_increments_messages_processed_counter(respx_mock, tmp_path):
    store = ReportingStore(db_path=str(tmp_path / "reporting.db"), reports_dir=str(tmp_path / "reports"))
    await store.init_schema()
    orch = OrchestratorClient(base_url="http://orch:8200")
    respx_mock.get("http://orch:8200/approvals").mock(
        return_value=httpx.Response(200, json={"approvals": []})
    )
    try:
        app = build_app(
            store=store, orchestrator=orch,
            jwt_secret=_SECRET, jwt_ttl_seconds=3600,
            cors_origins=("http://localhost:5173",),
            now=lambda: _T0,
        )
        before = _counter_value()
        token = _make_token(username="alice", role="admin")
        with TestClient(app) as c:
            r = c.post(
                "/reports/generate",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "name": "metrics-smoke",
                    "range_start": "2030-01-01T00:00:00+00:00",
                    "range_end": "2030-01-02T00:00:00+00:00",
                },
            )
            assert r.status_code == 201, r.text
        after = _counter_value()
        assert after - before == 1.0
    finally:
        await orch.aclose()
        await store.aclose()
```

- [ ] **Step 6: Run + verify tests pass**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane/reporting
python3 -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_metrics.py -v
pytest -v   # full reporting suite (31 prior + 2 new = 33 passed)
```

Expected:
- `tests/test_metrics.py` → **2 passed**
- Full reporting suite → **33 passed**

- [ ] **Step 7: Stage**

```bash
deactivate
rm -rf .venv
rm -rf /home/aditya/Documents/IntelliFIM/data-plane/schemas/build/
git -C /home/aditya/Documents/IntelliFIM add \
    data-plane/reporting/pyproject.toml \
    data-plane/reporting/src/reporting/metrics.py \
    data-plane/reporting/src/reporting/api.py \
    data-plane/reporting/src/reporting/consumer.py \
    data-plane/reporting/tests/test_metrics.py
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(reporting): expose Prometheus metrics + custom RED counters`

---

## Task 3: orchestrator metrics (aiohttp pattern)

**Files:**
- Create: `data-plane/orchestrator/src/orchestrator/metrics.py`
- Modify: `data-plane/orchestrator/pyproject.toml` (add 1 dep)
- Modify: `data-plane/orchestrator/src/orchestrator/api.py` (add `/metrics` aiohttp route + wrap approve handler)
- Modify: `data-plane/orchestrator/src/orchestrator/engine.py` (wrap process_one)
- Create: `data-plane/orchestrator/tests/test_metrics.py` (2 tests)

- [ ] **Step 1: Write `metrics.py`**

`data-plane/orchestrator/src/orchestrator/metrics.py`:

```python
"""Per-service Prometheus metrics for response-orchestrator.

3 lean RED-method counters/histograms, uniform across all 6 in-house services.
"""
from __future__ import annotations

from prometheus_client import Counter, Histogram


SERVICE_LABEL = "response-orchestrator"

messages_processed_total = Counter(
    "intellifim_messages_processed_total",
    "Number of input messages processed by the service",
    ["service"],
)

errors_total = Counter(
    "intellifim_errors_total",
    "Number of errors encountered by the service",
    ["service", "kind"],
)

processing_seconds = Histogram(
    "intellifim_processing_seconds",
    "End-to-end processing latency per input message",
    ["service"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
```

- [ ] **Step 2: Add dep to pyproject.toml**

`data-plane/orchestrator/pyproject.toml` — in `dependencies`, add:

```toml
    "prometheus-client>=0.20,<0.22",
```

(NO `prometheus-fastapi-instrumentator` — orchestrator is aiohttp.)

- [ ] **Step 3: Wire `/metrics` route into `api.py` + wrap approve handler**

Modify `data-plane/orchestrator/src/orchestrator/api.py`:

(a) Add imports near the top:

```python
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from orchestrator.metrics import (
    SERVICE_LABEL,
    errors_total,
    messages_processed_total,
    processing_seconds,
)
```

(b) Inside `build_api(...)`, after the existing handlers but before the `app.router.add_*` block, define the metrics handler:

```python
    async def metrics(_request: web.Request) -> web.Response:
        return web.Response(body=generate_latest(), content_type=CONTENT_TYPE_LATEST)
```

(c) In the same routes section, after `add_get("/healthz", healthz)`, add:

```python
    app.router.add_get("/metrics", metrics)
```

(d) Wrap the existing `approve` handler body (and similarly `reject`) with the metrics:

```python
    async def approve(request: web.Request) -> web.Response:
        with processing_seconds.labels(SERVICE_LABEL).time():
            try:
                # ... existing approve logic ...
                messages_processed_total.labels(SERVICE_LABEL).inc()
                return web.json_response(...)
            except ApprovalError:
                raise   # 4xx — not an error we count separately
            except Exception as e:
                errors_total.labels(SERVICE_LABEL, kind=type(e).__name__).inc()
                raise
```

> Note: the JWT middleware's `_is_decide_route` filter ONLY matches `POST /approvals/{id}/{approve|reject}` — `/metrics` is unaffected and remains unauthenticated. This is intentional for v1.

- [ ] **Step 4: Wrap engine `process_one` in `engine.py`**

Modify `data-plane/orchestrator/src/orchestrator/engine.py` — locate the existing `async def process_one(self, message)`. Wrap the body:

```python
    async def process_one(self, message) -> None:
        from orchestrator.metrics import (
            SERVICE_LABEL,
            errors_total,
            messages_processed_total,
            processing_seconds,
        )
        with processing_seconds.labels(SERVICE_LABEL).time():
            try:
                # ... existing process_one logic ...
                messages_processed_total.labels(SERVICE_LABEL).inc()
            except Exception as e:
                errors_total.labels(SERVICE_LABEL, kind=type(e).__name__).inc()
                raise
```

- [ ] **Step 5: Write failing tests**

`data-plane/orchestrator/tests/test_metrics.py`:

```python
"""Prometheus metrics tests for response-orchestrator."""
from __future__ import annotations

import pytest
from aiohttp.test_utils import TestClient, TestServer
from prometheus_client import REGISTRY

from orchestrator.metrics import SERVICE_LABEL


def _counter_value() -> float:
    val = REGISTRY.get_sample_value(
        "intellifim_messages_processed_total",
        {"service": SERVICE_LABEL},
    )
    return val if val is not None else 0.0


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_prometheus_format(api_app):
    async with TestServer(api_app) as server, TestClient(server) as client:
        r = await client.get("/metrics")
        assert r.status == 200
        body = await r.text()
        assert "intellifim_messages_processed_total" in body


@pytest.mark.asyncio
async def test_approve_increments_messages_processed_counter(api_app, pending_approval_id, admin_token):
    async with TestServer(api_app) as server, TestClient(server) as client:
        before = _counter_value()
        r = await client.post(
            f"/approvals/{pending_approval_id}/approve",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status == 200, await r.text()
        after = _counter_value()
        assert after - before == 1.0
```

> **Test fixture notes:** `api_app`, `pending_approval_id`, `admin_token` should reuse existing fixtures from `data-plane/orchestrator/tests/conftest.py` and/or `tests/test_api.py`. If they don't exist with those exact names, adapt to whatever the existing test_api.py uses to (a) get a configured `web.Application` and (b) insert a PENDING approval and (c) make an admin-role JWT.

- [ ] **Step 6: Run + verify tests pass**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane/orchestrator
python3 -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_metrics.py -v
pytest -v   # full orchestrator suite (46 prior + 2 new = 48 passed)
```

Expected:
- `tests/test_metrics.py` → **2 passed**
- Full orchestrator suite → **48 passed**

- [ ] **Step 7: Stage**

```bash
deactivate
rm -rf .venv
rm -rf /home/aditya/Documents/IntelliFIM/data-plane/schemas/build/
git -C /home/aditya/Documents/IntelliFIM add \
    data-plane/orchestrator/pyproject.toml \
    data-plane/orchestrator/src/orchestrator/metrics.py \
    data-plane/orchestrator/src/orchestrator/api.py \
    data-plane/orchestrator/src/orchestrator/engine.py \
    data-plane/orchestrator/tests/test_metrics.py
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(orchestrator): expose Prometheus /metrics route + custom RED counters`

---

## Task 4: The 3 engines (correlator + anomaly + policy)

These 3 services are mechanically identical except for service name + metrics port. The pattern per service:
- Add `metrics.py` (same shape, different `SERVICE_LABEL`)
- Add `prometheus-client` dep
- In `__main__.py`: import + `start_http_server(int(os.environ.get("METRICS_PORT", "<port>")))` right after `cfg = <Config>.from_env()`
- In `engine.py`: wrap `process_one(...)` (or its async equivalent)
- Add `test_metrics.py` (2 tests: counter increments on success, errors_total increments on raise)

**Per-service mapping:**

| Service | Module | Service label | Default METRICS_PORT |
|---|---|---|---|
| correlator | `correlator` | `correlation-engine` | `9100` |
| anomaly | `anomaly` | `anomaly-detector` | `9101` |
| policy | `policy` | `policy-engine` | `9102` |

### Step 1: For each of the 3 services, write `metrics.py`

Each file is the same shape — copy from Task 1's `metrics.py` and change only the `SERVICE_LABEL` value:

- `data-plane/correlator/src/correlator/metrics.py` → `SERVICE_LABEL = "correlation-engine"`
- `data-plane/anomaly/src/anomaly/metrics.py` → `SERVICE_LABEL = "anomaly-detector"`
- `data-plane/policy/src/policy/metrics.py` → `SERVICE_LABEL = "policy-engine"`

Use this template (substitute the label per service):

```python
"""Per-service Prometheus metrics for <service>.

3 lean RED-method counters/histograms, uniform across all 6 in-house services.
"""
from __future__ import annotations

from prometheus_client import Counter, Histogram


SERVICE_LABEL = "<service-label>"

messages_processed_total = Counter(
    "intellifim_messages_processed_total",
    "Number of input messages processed by the service",
    ["service"],
)

errors_total = Counter(
    "intellifim_errors_total",
    "Number of errors encountered by the service",
    ["service", "kind"],
)

processing_seconds = Histogram(
    "intellifim_processing_seconds",
    "End-to-end processing latency per input message",
    ["service"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
```

### Step 2: For each of the 3 services, add `prometheus-client` dep

In each `pyproject.toml` (`data-plane/correlator/pyproject.toml`, `data-plane/anomaly/pyproject.toml`, `data-plane/policy/pyproject.toml`) — append to `dependencies`:

```toml
    "prometheus-client>=0.20,<0.22",
```

### Step 3: For each of the 3 services, modify `__main__.py` to start the HTTP server

Locate the existing `def main()` (or `async def _run(cfg)`) and add this AFTER config load but BEFORE the long-running consume loop:

```python
import os
from prometheus_client import start_http_server

start_http_server(int(os.environ.get("METRICS_PORT", "<default-for-service>")))
```

Use defaults: `9100` for correlator, `9101` for anomaly, `9102` for policy. Place the import at the top of the file with the other imports.

### Step 4: For each of the 3 services, wrap `process_one` in `engine.py`

Locate the existing engine's per-message processor (`process_one`, `_process`, or equivalent). Wrap the body:

```python
    async def process_one(self, message) -> None:
        from <module>.metrics import (
            SERVICE_LABEL,
            errors_total,
            messages_processed_total,
            processing_seconds,
        )
        with processing_seconds.labels(SERVICE_LABEL).time():
            try:
                # ... existing process_one logic ...
                messages_processed_total.labels(SERVICE_LABEL).inc()
            except Exception as e:
                errors_total.labels(SERVICE_LABEL, kind=type(e).__name__).inc()
                raise
```

If the engine's processor is named differently (e.g. `_process`), wrap that one. The intent is "the per-message function that is called once per incoming Kafka record".

### Step 5: For each of the 3 services, write `test_metrics.py`

Each file is the same shape — copy this template and adjust the imports + the `process_one` argument shape per service. Use the appropriate `intellifim_schemas` type (`CanonicalEvent` for correlator, `CorrelatedEvent` for anomaly, `ScoredEvent` for policy):

```python
"""Prometheus metrics tests for <service>."""
from __future__ import annotations

import pytest
from prometheus_client import REGISTRY

from <module>.metrics import SERVICE_LABEL


def _counter_value(name: str, **labels) -> float:
    val = REGISTRY.get_sample_value(name, labels)
    return val if val is not None else 0.0


@pytest.mark.asyncio
async def test_process_one_increments_messages_processed_counter(engine, sample_event):
    """Happy-path process_one bumps messages_processed_total by 1."""
    before = _counter_value("intellifim_messages_processed_total", service=SERVICE_LABEL)
    await engine.process_one(sample_event)
    after = _counter_value("intellifim_messages_processed_total", service=SERVICE_LABEL)
    assert after - before == 1.0


@pytest.mark.asyncio
async def test_process_one_increments_errors_on_raise(engine, bad_event_that_raises):
    """A process_one call that raises bumps errors_total{kind=<ExcType>} by 1."""
    before = _counter_value("intellifim_errors_total", service=SERVICE_LABEL, kind="ValueError")
    with pytest.raises(ValueError):
        await engine.process_one(bad_event_that_raises)
    after = _counter_value("intellifim_errors_total", service=SERVICE_LABEL, kind="ValueError")
    assert after - before == 1.0
```

> **`engine` + `sample_event` + `bad_event_that_raises` fixture notes:**
> - Reuse existing fixtures from each service's `conftest.py` for `engine` and a valid sample event.
> - `bad_event_that_raises` may need to be added to conftest (or constructed inline) — the simplest is to monkeypatch the engine's dependency (e.g. the store, the OPA client) to raise `ValueError("bad")` when called.
> - If the engine swallows exceptions internally (e.g. `try/except` around `process_one` callers), check whether the counter still fires — you may need to test against the inner `_process` method instead.

### Step 6: Run + verify all 3 services' new tests pass

```bash
# correlator
cd /home/aditya/Documents/IntelliFIM/data-plane/correlator
python3 -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_metrics.py -v
pytest -v
deactivate
rm -rf .venv

# anomaly
cd /home/aditya/Documents/IntelliFIM/data-plane/anomaly
python3 -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_metrics.py -v
pytest -v
deactivate
rm -rf .venv

# policy
cd /home/aditya/Documents/IntelliFIM/data-plane/policy
python3 -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_metrics.py -v
pytest -v
deactivate
rm -rf .venv

rm -rf /home/aditya/Documents/IntelliFIM/data-plane/schemas/build/
```

Expected per service: 2 metrics tests pass + the prior suite count + 2.

### Step 7: Stage

```bash
git -C /home/aditya/Documents/IntelliFIM add \
    data-plane/correlator/pyproject.toml \
    data-plane/correlator/src/correlator/metrics.py \
    data-plane/correlator/src/correlator/__main__.py \
    data-plane/correlator/src/correlator/engine.py \
    data-plane/correlator/tests/test_metrics.py \
    data-plane/anomaly/pyproject.toml \
    data-plane/anomaly/src/anomaly/metrics.py \
    data-plane/anomaly/src/anomaly/__main__.py \
    data-plane/anomaly/src/anomaly/engine.py \
    data-plane/anomaly/tests/test_metrics.py \
    data-plane/policy/pyproject.toml \
    data-plane/policy/src/policy/metrics.py \
    data-plane/policy/src/policy/__main__.py \
    data-plane/policy/src/policy/engine.py \
    data-plane/policy/tests/test_metrics.py
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(engines): expose Prometheus /metrics + custom RED counters for correlator/anomaly/policy`

---

## Task 5: Prometheus config files

**Files:**
- Create: `data-plane/prometheus/prometheus.yml`
- Create: `data-plane/prometheus/alerts.yml`

(No service block yet — that lands in Task 8.)

- [ ] **Step 1: Write prometheus.yml**

`data-plane/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - /etc/prometheus/alerts.yml

alerting:
  alertmanagers:
    - static_configs:
        - targets: ["alertmanager:9093"]

scrape_configs:
  - job_name: "intellifim-auth-backend"
    static_configs:
      - targets: ["auth-backend:8000"]

  - job_name: "intellifim-orchestrator"
    static_configs:
      - targets: ["response-orchestrator:8200"]

  - job_name: "intellifim-reporting"
    static_configs:
      - targets: ["reporting:8300"]

  - job_name: "intellifim-correlator"
    static_configs:
      - targets: ["correlation-engine:9100"]

  - job_name: "intellifim-anomaly"
    static_configs:
      - targets: ["anomaly-detector:9101"]

  - job_name: "intellifim-policy"
    static_configs:
      - targets: ["policy-engine:9102"]
```

- [ ] **Step 2: Write alerts.yml**

`data-plane/prometheus/alerts.yml`:

```yaml
groups:
  - name: intellifim-availability
    interval: 30s
    rules:
      - alert: IntelliFIMServiceDown
        expr: up{job=~"intellifim-.+"} == 0
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "IntelliFIM service {{ $labels.job }} is down"
          description: "{{ $labels.job }} ({{ $labels.instance }}) has been unreachable for >2 minutes."
```

- [ ] **Step 3: Validate config files with `promtool` (Docker)**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker run --rm -v "$(pwd)/prometheus":/work prom/prometheus:v2.55.0 \
    promtool check config /work/prometheus.yml
docker run --rm -v "$(pwd)/prometheus":/work prom/prometheus:v2.55.0 \
    promtool check rules /work/alerts.yml
```

Expected: both commands print `SUCCESS` and exit 0.

- [ ] **Step 4: Stage**

```bash
git -C /home/aditya/Documents/IntelliFIM add \
    data-plane/prometheus/prometheus.yml \
    data-plane/prometheus/alerts.yml
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(observability): add Prometheus scrape config + IntelliFIMServiceDown alert rule`

---

## Task 6: Alertmanager config

**Files:**
- Create: `data-plane/alertmanager/alertmanager.yml`

- [ ] **Step 1: Write alertmanager.yml**

`data-plane/alertmanager/alertmanager.yml`:

```yaml
global:
  resolve_timeout: 5m

route:
  receiver: "null-receiver"
  group_by: ["alertname", "job"]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h

receivers:
  - name: "null-receiver"
    # No integrations in v1 — operator watches the Alertmanager web UI at :9093.
    # v2 will add Slack via slack_configs, email via email_configs, etc.
```

- [ ] **Step 2: Validate with `amtool` (Docker)**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker run --rm -v "$(pwd)/alertmanager":/work prom/alertmanager:v0.27.0 \
    amtool check-config /work/alertmanager.yml
```

Expected: prints `Checking '/work/alertmanager.yml'  SUCCESS` and exits 0.

- [ ] **Step 3: Stage**

```bash
git -C /home/aditya/Documents/IntelliFIM add data-plane/alertmanager/alertmanager.yml
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(observability): add Alertmanager config (null-receiver, console-only)`

---

## Task 7: Grafana provisioning + dashboards

**Files:**
- Create: `data-plane/grafana/provisioning/datasources/prometheus.yml`
- Create: `data-plane/grafana/provisioning/dashboards/dashboards.yml`
- Create: `data-plane/grafana/dashboards/pipeline-overview.json`
- Create: `data-plane/grafana/dashboards/threat-and-response.json`

- [ ] **Step 1: Write the datasource provisioning file**

`data-plane/grafana/provisioning/datasources/prometheus.yml`:

```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
```

- [ ] **Step 2: Write the dashboard provider file**

`data-plane/grafana/provisioning/dashboards/dashboards.yml`:

```yaml
apiVersion: 1
providers:
  - name: "intellifim"
    folder: "IntelliFIM"
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
```

- [ ] **Step 3: Write the "Pipeline overview" dashboard JSON**

`data-plane/grafana/dashboards/pipeline-overview.json`:

```json
{
  "uid": "intellifim-pipeline",
  "title": "IntelliFIM — Pipeline overview",
  "tags": ["intellifim"],
  "schemaVersion": 39,
  "version": 1,
  "refresh": "10s",
  "time": { "from": "now-1h", "to": "now" },
  "timepicker": {},
  "templating": { "list": [] },
  "annotations": { "list": [] },
  "panels": [
    {
      "id": 1,
      "type": "row",
      "title": "Service health (up == 1)",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 0 },
      "collapsed": false,
      "panels": []
    },
    {
      "id": 2,
      "type": "stat",
      "title": "correlation-engine",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 4, "w": 4, "x": 0, "y": 1 },
      "targets": [{ "expr": "up{job=\"intellifim-correlator\"}", "refId": "A" }],
      "fieldConfig": {
        "defaults": {
          "mappings": [
            { "type": "value", "options": { "0": { "text": "DOWN", "color": "red" }, "1": { "text": "UP", "color": "green" } } }
          ],
          "color": { "mode": "thresholds" },
          "thresholds": { "mode": "absolute", "steps": [
            { "value": null, "color": "red" },
            { "value": 1, "color": "green" }
          ]}
        }
      }
    },
    {
      "id": 3,
      "type": "stat",
      "title": "anomaly-detector",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 4, "w": 4, "x": 4, "y": 1 },
      "targets": [{ "expr": "up{job=\"intellifim-anomaly\"}", "refId": "A" }],
      "fieldConfig": { "defaults": {
        "mappings": [{ "type": "value", "options": { "0": { "text": "DOWN", "color": "red" }, "1": { "text": "UP", "color": "green" } } }],
        "color": { "mode": "thresholds" },
        "thresholds": { "mode": "absolute", "steps": [{ "value": null, "color": "red" }, { "value": 1, "color": "green" }] }
      }}
    },
    {
      "id": 4,
      "type": "stat",
      "title": "policy-engine",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 4, "w": 4, "x": 8, "y": 1 },
      "targets": [{ "expr": "up{job=\"intellifim-policy\"}", "refId": "A" }],
      "fieldConfig": { "defaults": {
        "mappings": [{ "type": "value", "options": { "0": { "text": "DOWN", "color": "red" }, "1": { "text": "UP", "color": "green" } } }],
        "color": { "mode": "thresholds" },
        "thresholds": { "mode": "absolute", "steps": [{ "value": null, "color": "red" }, { "value": 1, "color": "green" }] }
      }}
    },
    {
      "id": 5,
      "type": "stat",
      "title": "response-orchestrator",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 4, "w": 4, "x": 12, "y": 1 },
      "targets": [{ "expr": "up{job=\"intellifim-orchestrator\"}", "refId": "A" }],
      "fieldConfig": { "defaults": {
        "mappings": [{ "type": "value", "options": { "0": { "text": "DOWN", "color": "red" }, "1": { "text": "UP", "color": "green" } } }],
        "color": { "mode": "thresholds" },
        "thresholds": { "mode": "absolute", "steps": [{ "value": null, "color": "red" }, { "value": 1, "color": "green" }] }
      }}
    },
    {
      "id": 6,
      "type": "stat",
      "title": "auth-backend",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 4, "w": 4, "x": 16, "y": 1 },
      "targets": [{ "expr": "up{job=\"intellifim-auth-backend\"}", "refId": "A" }],
      "fieldConfig": { "defaults": {
        "mappings": [{ "type": "value", "options": { "0": { "text": "DOWN", "color": "red" }, "1": { "text": "UP", "color": "green" } } }],
        "color": { "mode": "thresholds" },
        "thresholds": { "mode": "absolute", "steps": [{ "value": null, "color": "red" }, { "value": 1, "color": "green" }] }
      }}
    },
    {
      "id": 7,
      "type": "stat",
      "title": "reporting",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 4, "w": 4, "x": 20, "y": 1 },
      "targets": [{ "expr": "up{job=\"intellifim-reporting\"}", "refId": "A" }],
      "fieldConfig": { "defaults": {
        "mappings": [{ "type": "value", "options": { "0": { "text": "DOWN", "color": "red" }, "1": { "text": "UP", "color": "green" } } }],
        "color": { "mode": "thresholds" },
        "thresholds": { "mode": "absolute", "steps": [{ "value": null, "color": "red" }, { "value": 1, "color": "green" }] }
      }}
    },
    {
      "id": 10,
      "type": "row",
      "title": "Throughput (msg/sec, 1m rate)",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 5 },
      "collapsed": false,
      "panels": []
    },
    {
      "id": 11,
      "type": "timeseries",
      "title": "Messages processed per service",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 8, "w": 24, "x": 0, "y": 6 },
      "targets": [
        { "expr": "rate(intellifim_messages_processed_total{service=\"correlation-engine\"}[1m])", "refId": "A", "legendFormat": "correlator" },
        { "expr": "rate(intellifim_messages_processed_total{service=\"anomaly-detector\"}[1m])",   "refId": "B", "legendFormat": "anomaly" },
        { "expr": "rate(intellifim_messages_processed_total{service=\"policy-engine\"}[1m])",     "refId": "C", "legendFormat": "policy" },
        { "expr": "rate(intellifim_messages_processed_total{service=\"response-orchestrator\"}[1m])", "refId": "D", "legendFormat": "orchestrator" },
        { "expr": "rate(intellifim_messages_processed_total{service=\"auth-backend\"}[1m])",     "refId": "E", "legendFormat": "auth-backend" },
        { "expr": "rate(intellifim_messages_processed_total{service=\"reporting\"}[1m])",        "refId": "F", "legendFormat": "reporting" }
      ],
      "fieldConfig": { "defaults": { "unit": "ops" } }
    },
    {
      "id": 12,
      "type": "row",
      "title": "Errors (errors/sec, 5m rate)",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 14 },
      "collapsed": false,
      "panels": []
    },
    {
      "id": 13,
      "type": "timeseries",
      "title": "Errors per service",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 8, "w": 24, "x": 0, "y": 15 },
      "targets": [
        { "expr": "sum(rate(intellifim_errors_total{service=\"correlation-engine\"}[5m])) by (kind)", "refId": "A", "legendFormat": "correlator/{{kind}}" },
        { "expr": "sum(rate(intellifim_errors_total{service=\"anomaly-detector\"}[5m])) by (kind)", "refId": "B", "legendFormat": "anomaly/{{kind}}" },
        { "expr": "sum(rate(intellifim_errors_total{service=\"policy-engine\"}[5m])) by (kind)", "refId": "C", "legendFormat": "policy/{{kind}}" },
        { "expr": "sum(rate(intellifim_errors_total{service=\"response-orchestrator\"}[5m])) by (kind)", "refId": "D", "legendFormat": "orchestrator/{{kind}}" },
        { "expr": "sum(rate(intellifim_errors_total{service=\"auth-backend\"}[5m])) by (kind)", "refId": "E", "legendFormat": "auth-backend/{{kind}}" },
        { "expr": "sum(rate(intellifim_errors_total{service=\"reporting\"}[5m])) by (kind)", "refId": "F", "legendFormat": "reporting/{{kind}}" }
      ],
      "fieldConfig": { "defaults": { "unit": "ops" } }
    },
    {
      "id": 20,
      "type": "row",
      "title": "p95 latency",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 23 },
      "collapsed": false,
      "panels": []
    },
    {
      "id": 21,
      "type": "timeseries",
      "title": "p95 processing latency per service",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 8, "w": 24, "x": 0, "y": 24 },
      "targets": [
        { "expr": "histogram_quantile(0.95, sum(rate(intellifim_processing_seconds_bucket{service=\"correlation-engine\"}[5m])) by (le))", "refId": "A", "legendFormat": "correlator" },
        { "expr": "histogram_quantile(0.95, sum(rate(intellifim_processing_seconds_bucket{service=\"anomaly-detector\"}[5m])) by (le))",   "refId": "B", "legendFormat": "anomaly" },
        { "expr": "histogram_quantile(0.95, sum(rate(intellifim_processing_seconds_bucket{service=\"policy-engine\"}[5m])) by (le))",     "refId": "C", "legendFormat": "policy" },
        { "expr": "histogram_quantile(0.95, sum(rate(intellifim_processing_seconds_bucket{service=\"response-orchestrator\"}[5m])) by (le))", "refId": "D", "legendFormat": "orchestrator" },
        { "expr": "histogram_quantile(0.95, sum(rate(intellifim_processing_seconds_bucket{service=\"auth-backend\"}[5m])) by (le))",     "refId": "E", "legendFormat": "auth-backend" },
        { "expr": "histogram_quantile(0.95, sum(rate(intellifim_processing_seconds_bucket{service=\"reporting\"}[5m])) by (le))",        "refId": "F", "legendFormat": "reporting" }
      ],
      "fieldConfig": { "defaults": { "unit": "s" } }
    }
  ]
}
```

- [ ] **Step 4: Write the "Threat & response health" dashboard JSON**

`data-plane/grafana/dashboards/threat-and-response.json`:

```json
{
  "uid": "intellifim-threat-response",
  "title": "IntelliFIM — Threat & response health",
  "tags": ["intellifim"],
  "schemaVersion": 39,
  "version": 1,
  "refresh": "30s",
  "time": { "from": "now-6h", "to": "now" },
  "timepicker": {},
  "templating": { "list": [] },
  "annotations": { "list": [] },
  "panels": [
    {
      "id": 1,
      "type": "row",
      "title": "Threat-score flow",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 0 },
      "collapsed": false,
      "panels": []
    },
    {
      "id": 2,
      "type": "timeseries",
      "title": "policy-engine publish rate vs reporting ingest rate",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 8, "w": 24, "x": 0, "y": 1 },
      "targets": [
        { "expr": "rate(intellifim_messages_processed_total{service=\"policy-engine\"}[1m])", "refId": "A", "legendFormat": "policy publish" },
        { "expr": "rate(intellifim_messages_processed_total{service=\"reporting\"}[1m])", "refId": "B", "legendFormat": "reporting ingest" }
      ],
      "fieldConfig": { "defaults": { "unit": "ops" } }
    },
    {
      "id": 10,
      "type": "row",
      "title": "Approvals API",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 9 },
      "collapsed": false,
      "panels": []
    },
    {
      "id": 11,
      "type": "timeseries",
      "title": "Approval API call rate (by handler)",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 8, "w": 12, "x": 0, "y": 10 },
      "targets": [
        { "expr": "sum(rate(http_requests_total{job=\"intellifim-orchestrator\", handler=~\"/approvals.*\"}[1m])) by (handler)", "refId": "A", "legendFormat": "{{handler}}" }
      ],
      "fieldConfig": { "defaults": { "unit": "ops" } }
    },
    {
      "id": 12,
      "type": "timeseries",
      "title": "Approval API 5xx errors (by status)",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 8, "w": 12, "x": 12, "y": 10 },
      "targets": [
        { "expr": "sum(rate(http_requests_total{job=\"intellifim-orchestrator\", handler=~\"/approvals.*\", status=~\"5..\"}[1m])) by (status)", "refId": "A", "legendFormat": "{{status}}" }
      ],
      "fieldConfig": { "defaults": { "unit": "ops" } }
    },
    {
      "id": 13,
      "type": "timeseries",
      "title": "Approval API p95 latency",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 8, "w": 24, "x": 0, "y": 18 },
      "targets": [
        { "expr": "histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{job=\"intellifim-orchestrator\", handler=~\"/approvals.*\"}[5m])) by (le))", "refId": "A", "legendFormat": "p95" }
      ],
      "fieldConfig": { "defaults": { "unit": "s" } }
    },
    {
      "id": 20,
      "type": "row",
      "title": "Auth + Reporting",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 26 },
      "collapsed": false,
      "panels": []
    },
    {
      "id": 21,
      "type": "timeseries",
      "title": "Auth login rate (by status)",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 8, "w": 12, "x": 0, "y": 27 },
      "targets": [
        { "expr": "sum(rate(http_requests_total{job=\"intellifim-auth-backend\", handler=\"/auth/login\"}[1m])) by (status)", "refId": "A", "legendFormat": "{{status}}" }
      ],
      "fieldConfig": { "defaults": { "unit": "ops" } }
    },
    {
      "id": 22,
      "type": "timeseries",
      "title": "Report generation success rate",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 8, "w": 12, "x": 12, "y": 27 },
      "targets": [
        { "expr": "sum(rate(http_requests_total{job=\"intellifim-reporting\", handler=\"/reports/generate\", status=\"201\"}[5m]))", "refId": "A", "legendFormat": "201s/sec" }
      ],
      "fieldConfig": { "defaults": { "unit": "ops" } }
    },
    {
      "id": 23,
      "type": "timeseries",
      "title": "Reporting service errors",
      "datasource": { "type": "prometheus", "uid": "prometheus" },
      "gridPos": { "h": 8, "w": 24, "x": 0, "y": 35 },
      "targets": [
        { "expr": "sum(rate(intellifim_errors_total{service=\"reporting\"}[5m])) by (kind)", "refId": "A", "legendFormat": "{{kind}}" }
      ],
      "fieldConfig": { "defaults": { "unit": "ops" } }
    }
  ]
}
```

- [ ] **Step 5: Validate JSON syntax**

```bash
cd /home/aditya/Documents/IntelliFIM
python3 -c "import json; json.load(open('data-plane/grafana/dashboards/pipeline-overview.json')); json.load(open('data-plane/grafana/dashboards/threat-and-response.json')); print('ok')"
```

Expected: `ok` printed (both files are valid JSON).

> Dashboard semantic validity (whether Grafana likes the JSON) is verified at DoD time when the stack comes up — Grafana logs loudly if it can't load a dashboard.

- [ ] **Step 6: Stage**

```bash
git -C /home/aditya/Documents/IntelliFIM add \
    data-plane/grafana/provisioning/datasources/prometheus.yml \
    data-plane/grafana/provisioning/dashboards/dashboards.yml \
    data-plane/grafana/dashboards/pipeline-overview.json \
    data-plane/grafana/dashboards/threat-and-response.json
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(observability): add Grafana provisioning + 2 pre-built dashboards`

---

## Task 8: docker-compose.yml integration

**Files:**
- Modify: `data-plane/docker-compose.yml` (add 3 new services, 3 new volumes, engine port mappings)

- [ ] **Step 1: Add the 3 engine port mappings + METRICS_PORT env vars**

In `data-plane/docker-compose.yml`, find each engine's service block and:

(a) `correlation-engine` block — under `environment:`, add:
```yaml
      METRICS_PORT: "9100"
```
And add a `ports:` section (or extend existing):
```yaml
    ports:
      - "127.0.0.1:9100:9100"
```

(b) `anomaly-detector` block — same shape but port `9101`.

(c) `policy-engine` block — same shape but port `9102`.

- [ ] **Step 2: Add the 3 new service blocks**

Insert these blocks at the end of the `services:` section (just before the top-level `volumes:` block):

```yaml
  prometheus:
    image: prom/prometheus:v2.55.0
    container_name: prometheus
    networks: [bus]
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./prometheus/alerts.yml:/etc/prometheus/alerts.yml:ro
      - prometheus_data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus"
      - "--storage.tsdb.retention.time=7d"
      - "--web.enable-lifecycle"
    depends_on:
      alertmanager:
        condition: service_started
    healthcheck:
      test: ["CMD", "wget", "-q", "-O", "/dev/null", "http://localhost:9090/-/healthy"]
      interval: 10s
      timeout: 5s
      retries: 5

  alertmanager:
    image: prom/alertmanager:v0.27.0
    container_name: alertmanager
    networks: [bus]
    ports:
      - "127.0.0.1:9093:9093"
    volumes:
      - ./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
      - alertmanager_data:/alertmanager
    command:
      - "--config.file=/etc/alertmanager/alertmanager.yml"
      - "--storage.path=/alertmanager"
    healthcheck:
      test: ["CMD", "wget", "-q", "-O", "/dev/null", "http://localhost:9093/-/healthy"]
      interval: 10s
      timeout: 5s
      retries: 5

  grafana:
    image: grafana/grafana:11.3.0
    container_name: grafana
    networks: [bus]
    ports:
      - "127.0.0.1:3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
      - ./grafana/dashboards:/var/lib/grafana/dashboards:ro
    environment:
      GF_SECURITY_ADMIN_USER: "admin"
      GF_SECURITY_ADMIN_PASSWORD: "admin"
      GF_USERS_ALLOW_SIGN_UP: "false"
      GF_AUTH_ANONYMOUS_ENABLED: "true"
      GF_AUTH_ANONYMOUS_ORG_ROLE: "Viewer"
    depends_on:
      prometheus:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "wget -q -O /dev/null http://localhost:3000/api/health"]
      interval: 10s
      timeout: 5s
      retries: 5
```

- [ ] **Step 3: Add the 3 new named volumes**

In the top-level `volumes:` block (at the bottom of the file), add:

```yaml
  prometheus_data:
  alertmanager_data:
  grafana_data:
```

- [ ] **Step 4: Validate compose config**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane config --services 2>&1 | grep -v "^time=" | sort | wc -l
```

Expected: `27` (24 prior + prometheus + alertmanager + grafana).

```bash
docker compose --env-file .env.dataplane --profile sim config --services 2>&1 | grep -v "^time=" | sort | wc -l
```

Expected: `28` (27 + simulator from profile).

- [ ] **Step 5: Bring up the stack + verify 27 services healthy**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
./scripts/init-secrets.sh   # idempotent; ensures JWT_SECRET is set
docker compose --env-file .env.dataplane up -d
sleep 45
docker compose ps --format "{{.Service}}\t{{.Status}}" | sort | head -30
```

Expected: 27 services listed; all the new ones (`prometheus`, `alertmanager`, `grafana`) show `Up X seconds (healthy)`. The simulator stays hidden because no `--profile sim`.

- [ ] **Step 6: Stage**

```bash
cd /home/aditya/Documents/IntelliFIM
git -C /home/aditya/Documents/IntelliFIM add data-plane/docker-compose.yml
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(observability): wire prometheus + alertmanager + grafana into Compose (24 → 27 services)`

---

## Task 9: Verification script + smoke

**Files:**
- Create: `data-plane/scripts/check-observability.sh`

- [ ] **Step 1: Write the verification script**

`data-plane/scripts/check-observability.sh`:

```bash
#!/usr/bin/env bash
# Verifies Prometheus is scraping all 6 IntelliFIM services and the
# IntelliFIMServiceDown alert rule is loaded.
set -uo pipefail
cd "$(dirname "$0")/.."

echo "=== Prometheus health ==="
curl -fsS http://127.0.0.1:9090/-/healthy && echo " OK"

echo "=== Scrape targets ==="
UP_COUNT=$(curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=up{job=~"intellifim-.%2B"}' \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sum(1 for r in d["data"]["result"] if r["value"][1]=="1"))')
echo "scrape targets up: $UP_COUNT / 6"
[ "$UP_COUNT" = "6" ] || { echo "ERROR: expected 6"; exit 2; }

echo "=== Alert rule loaded ==="
curl -fsS http://127.0.0.1:9090/api/v1/rules | python3 -c '
import sys, json
d = json.load(sys.stdin)
rules = [r for g in d["data"]["groups"] for r in g["rules"]]
names = [r["name"] for r in rules]
print("rules:", names)
assert "IntelliFIMServiceDown" in names, "missing IntelliFIMServiceDown rule"
'

echo "=== Grafana health ==="
curl -fsS http://127.0.0.1:3000/api/health | python3 -m json.tool

echo "=== Alertmanager health ==="
curl -fsS http://127.0.0.1:9093/-/healthy && echo " OK"

echo "PASS"
```

- [ ] **Step 2: Make executable + run**

```bash
chmod +x /home/aditya/Documents/IntelliFIM/data-plane/scripts/check-observability.sh
cd /home/aditya/Documents/IntelliFIM/data-plane
./scripts/check-observability.sh
echo "exit=$?"
```

Expected output ends with `PASS` and `exit=0`. If any check fails, the script prints the failing check and exits non-zero.

- [ ] **Step 3: End-to-end metrics signal (DoD #7)**

Run a scenario from sub-project #8 + verify metrics light up:

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
./scripts/run-scenario.sh data-exfil
echo "exit=$?"
```

Wait 60 seconds for processing to propagate through the pipeline. Then verify each service's messages_processed_total has incremented since stack startup:

```bash
for svc in correlation-engine anomaly-detector policy-engine response-orchestrator reporting; do
  count=$(curl -fsS "http://127.0.0.1:9090/api/v1/query?query=intellifim_messages_processed_total%7Bservice%3D%22${svc}%22%7D" \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sum(float(r["value"][1]) for r in d["data"]["result"]))')
  echo "${svc}: ${count}"
done
```

Expected: every service shows a non-zero count after running scenarios. (auth-backend may show 0 if no login has happened recently — that's fine; the scenarios don't exercise the login path.)

- [ ] **Step 4: End-to-end alert firing (DoD #8)**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose stop policy-engine
echo "stopped policy-engine; waiting 3 minutes for alert to fire..."
sleep 180
curl -fsS http://127.0.0.1:9093/api/v2/alerts | python3 -c '
import sys, json
alerts = json.load(sys.stdin)
firing = [a for a in alerts if a.get("status", {}).get("state") == "active"]
print("firing alerts:", [a["labels"]["alertname"] for a in firing])
assert any(a["labels"].get("alertname") == "IntelliFIMServiceDown" and a["labels"].get("job") == "intellifim-policy" for a in firing), "expected IntelliFIMServiceDown for intellifim-policy"
'
# Restart
docker compose start policy-engine
echo "restarted policy-engine; waiting 60s for alert to resolve..."
sleep 60
curl -fsS http://127.0.0.1:9093/api/v2/alerts | python3 -c '
import sys, json
alerts = json.load(sys.stdin)
firing = [a for a in alerts if a.get("status", {}).get("state") == "active" and a["labels"].get("job") == "intellifim-policy"]
print("policy-engine firing alerts after restart:", firing)
assert not firing, "policy-engine alert should have resolved"
'
```

Expected:
- After stop + 3-min wait: `firing alerts: ['IntelliFIMServiceDown']`
- After restart + 1-min wait: `policy-engine firing alerts after restart: []`

- [ ] **Step 5: Promtool config validation (DoD #9)**

```bash
docker exec prometheus promtool check config /etc/prometheus/prometheus.yml
docker exec prometheus promtool check rules /etc/prometheus/alerts.yml
```

Expected: both print `SUCCESS`.

- [ ] **Step 6: No regression on prior DoD (DoD #10)**

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
./scripts/run-all-scenarios.sh
```

Expected: `PASS (5/5)` from sub-project #8. Reporting + admin console still work; verify by hand or with the reporting smoke:

```bash
export ADMIN_EMAIL=$(grep ^ADMIN_EMAIL= .env.dataplane | cut -d= -f2-)
export ADMIN_PASSWORD=$(grep ^ADMIN_PASSWORD= .env.dataplane | cut -d= -f2-)
./scripts/generate-report.py
```

Expected: `exit=0`, PDF written to `/tmp/`.

- [ ] **Step 7: Stage**

```bash
cd /home/aditya/Documents/IntelliFIM
git -C /home/aditya/Documents/IntelliFIM add data-plane/scripts/check-observability.sh
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `feat(observability): add check-observability.sh verification script`

---

## Task 10: README updates

**Files:**
- Modify: `data-plane/README.md` (add observability section)

- [ ] **Step 1: Update services list in README**

Find the "What's in the box" section in `data-plane/README.md`. Update the count `24 services` → `27 services` and add a new bullet point AFTER the existing `Dev tooling:` / `Simulation lab:` bullets:

```markdown
- **Observability:** `prometheus` (port 9090), `grafana` (port 3000), `alertmanager` (port 9093) — scrapes the 6 in-house Python services every 15s, auto-provisions 2 dashboards (Pipeline overview + Threat & response health), routes 1 example alert rule (IntelliFIMServiceDown) to Alertmanager's console UI. See [prometheus/](prometheus/), [grafana/](grafana/), [alertmanager/](alertmanager/).
```

- [ ] **Step 2: Add a new "Observability" section near the end of the README**

Insert just before the `## Tear down` section:

```markdown
## Observability

Sub-project #9 (the final v1 sub-project) adds Prometheus metrics scraping, Grafana dashboards, and Alertmanager. All 6 in-house Python services (auth-backend, response-orchestrator, reporting, correlation-engine, anomaly-detector, policy-engine) expose `/metrics` endpoints; Prometheus scrapes them every 15s.

```bash
# From data-plane/:
./scripts/check-observability.sh           # verify everything is healthy
```

URLs (all bound to `127.0.0.1`):
- **Prometheus UI:** http://localhost:9090
- **Grafana:** http://localhost:3000  (anonymous viewer; `admin/admin` for editing)
- **Alertmanager:** http://localhost:9093

Two pre-built Grafana dashboards (in the "IntelliFIM" folder):
1. **Pipeline overview** — `up` indicator per service, throughput / errors / p95 latency time-series for all 6 services.
2. **Threat & response health** — policy-engine publish rate vs reporting ingest rate, approval API call rate + 5xx + p95 latency, auth login rate, report generation success rate.

One example alert rule (`IntelliFIMServiceDown`) fires when any of the 6 services is unreachable for >2min. View firing alerts in the Alertmanager web UI.

**v1 limitations** (deferred to v2):
- No outbound notifications (no Slack/email/PagerDuty) — operator watches Alertmanager UI manually.
- No log aggregation (Loki) — use `docker compose logs` for now.
- No distributed traces (Jaeger) — v2.
- No Kafka exporter — `up` is the only Kafka health signal in v1.
- Grafana admin password is `admin/admin` for dev. v2 hardens.
- No Helm chart — Docker Compose only. v2 deferral.

See [`data-plane/scripts/check-observability.sh`](scripts/check-observability.sh) for the verification smoke.
```

- [ ] **Step 3: DoD walk-through summary (this is verification, not file changes)**

DoD items from the spec §12.4:

1. ✅ `pytest` green — total 273 Python + 5 Rego = 278 (verified by running each service's suite).
2. ✅ `docker compose up -d` brings up 27 services healthy (verified in Task 8 Step 5).
3. ✅ Prometheus healthy — `curl http://127.0.0.1:9090/-/healthy` returns 200 (verified by check-observability.sh).
4. ✅ All 6 scrape targets UP — query returns 6 results all `"1"` (verified by check-observability.sh).
5. ✅ Grafana healthy + dashboards loaded — `curl http://127.0.0.1:3000/api/health` returns 200; open `http://127.0.0.1:3000` → "IntelliFIM" folder → both dashboards render.
6. ✅ Alertmanager healthy — `curl http://127.0.0.1:9093/-/healthy` returns 200.
7. ✅ End-to-end metrics signal — verified in Task 9 Step 3.
8. ✅ End-to-end alert firing + resolution — verified in Task 9 Step 4.
9. ✅ Config validation — verified in Task 9 Step 5.
10. ✅ No breakage of prior DoD — verified in Task 9 Step 6.

- [ ] **Step 4: Stage README + ask user to commit**

```bash
git -C /home/aditya/Documents/IntelliFIM add data-plane/README.md
git -C /home/aditya/Documents/IntelliFIM status --short
```

Suggested commit message: `docs(observability): document observability stack in data-plane README`

---

## Post-merge checklist (after PR merges to main)

1. Sync local `main`:
   ```bash
   git checkout main && git pull --ff-only
   ```
2. Update memory files:
   - `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/MEMORY.md`:
     - Update count to **9/9 SHIPPED — v1 walking-skeleton complete!**
     - Remove "next up" pointer (next is v2 cross-cutting passes).
     - Add a line for the new shipped sub-project.
   - `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/project_intellifim_roadmap.md`:
     - Mark row 9 ✅ SHIPPED `YYYY-MM-DD` PR #N squash `<sha>`.
     - Add a v1-complete banner at the top.
     - Append "From #9" v2 deferral block.
     - Append new patterns to the "Critical patterns" section.
   - Create `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/project_intellifim_observability_shipped.md` as the frozen snapshot.
   - Update `project_intellifim_v1_shipped.md`: service count 24 → 27, test total 261 → 273, mark v1 walking-skeleton phase as COMPLETE.

---

## Plan self-review

### Spec coverage

| Spec section | Implemented in |
|---|---|
| §1 Goal | Tasks 1–10 (end-to-end) |
| §2 Architecture — 3 new services + 6 instrumented | Tasks 5+6+7+8 (services), Tasks 1+2+3+4 (instrumentation) |
| §3 Scope (in/out) | Whole plan respects scope; §13 deferrals not implemented |
| §4.1–§4.3 RED metrics + integration points | Tasks 1+2+3+4 (per service) |
| §4.4 Per-service Compose env additions | Task 8 Step 1 |
| §4.5 prometheus-client deps | Tasks 1+2+3+4 Step 2 (per service) |
| §5 Prometheus (service + config + alert rule) | Tasks 5 + 8 |
| §6 Alertmanager (service + config) | Tasks 6 + 8 |
| §7 Grafana (service + provisioning + 2 dashboards) | Tasks 7 + 8 |
| §8 HTTP surface table | Tasks 1+2+3+4 (`/metrics` routes), Task 8 (UI ports) |
| §9 Storage (3 named volumes) | Task 8 Step 3 |
| §10 Service composition (stack count, no schema bump) | Tasks 1–10 (additive only) |
| §11 Repo layout | Tasks 1–10 (each file maps) |
| §12.1 Unit tests (12 new) | Tasks 1–4 (2 per service) |
| §12.4 DoD (10 items) | Task 9 + Task 10 Step 3 |
| §12.5 Smoke script | Task 9 Step 1 |
| §13 v2 deferrals | Not implemented (documented in spec) |

No gaps.

### Placeholder scan
- No "TBD" / "TODO" / "implement later" / "fill in" in the plan body.
- Every test step shows full code or explicit pattern to follow.
- Every implementation step shows full code.
- Every command is exact.
- Where existing-fixture names are referenced (`deps`, `engine`, `pending_approval_id`), the plan flags this and tells the engineer to adapt to whatever exists.

### Type / method-name consistency
- `SERVICE_LABEL` is a module-level constant set per service (different value per service, same identifier).
- `messages_processed_total` / `errors_total` / `processing_seconds` — identical metric names + labels across all 6 services (this is the point of uniform RED).
- `start_http_server(int(os.environ.get("METRICS_PORT", "<default>")))` — identical pattern in 3 engines, only default port differs (9100/9101/9102).
- `Instrumentator().instrument(app).expose(app)` — identical in 2 FastAPI services.
- aiohttp `/metrics` route handler shape — only in orchestrator (Task 3).
- Job names in `prometheus.yml` match dashboard panel queries (`intellifim-correlator`, `intellifim-anomaly`, etc.).
- Alert rule selector `up{job=~"intellifim-.+"}` matches all 6 job names.
- Compose service names match scrape targets (`auth-backend:8000`, `response-orchestrator:8200`, etc.).

All consistent.

---

**Plan ready for execution.**
