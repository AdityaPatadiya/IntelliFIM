# Reporting subsystem v1 — design

**Sub-project #7 of 9** in the IntelliFIM v1 walking-skeleton. Builds on top of #1 (data plane), #4 (policy engine — `threat.scores` topic), #5 (response orchestrator — `/approvals` API), and #6 (admin console + auth-backend).

**Date:** 2026-05-20
**Author:** IntelliFIM team
**Status:** Approved — ready for implementation plan.

---

## 1. Goal

Ship a `reporting` service that:
1. Continuously consumes `threat.scores` Kafka topic into local storage.
2. On request, generates a "Security Summary" PDF that combines approvals (from orchestrator API) + threat scores (from local store) for a date range.
3. Persists generated PDFs and exposes them through a list/download API consumed by the React Reports page.

The master tech-stack document (`docs/superpowers/specs/2026-05-04-intellifim-tech-stack-design.md` §4.10) calls for **WeasyPrint + Jinja2** for PDF generation. This sub-project implements the v1 walking-skeleton of that subsystem. Celery / Celery Beat scheduling, compliance-template variants (PCI-DSS, HIPAA, GDPR, ISO 27001, NIST 800-53), and MinIO/S3 storage are explicit v2 deferrals — see §13.

## 2. Architecture

New service `reporting` (the 24th service in the data-plane Compose stack). Stack:

- **FastAPI** + **uvicorn** — HTTP API. FastAPI factory pattern matches `auth-backend` (sub-project #6).
- **aiokafka** — background consumer of `threat.scores` topic.
- **aiosqlite** — local persistence (`threat_scores` + `reports` tables) in a single SQLite file.
- **Jinja2** + **WeasyPrint** — HTML template → PDF.
- **matplotlib** (Agg backend) — server-side chart rendering to inline SVG (WeasyPrint does not execute JavaScript, so Recharts-style client charts are not an option).
- **httpx** — outbound calls to the orchestrator's `/approvals` API.
- **python-jose** — JWT validation (shared HS256 secret with auth-backend + orchestrator).

The service runs two concurrent jobs in one event loop, using the same aiohttp+aiokafka co-resident pattern established by the response-orchestrator in #5 (substitute `aiohttp` with `FastAPI`/uvicorn — uvicorn's `Server.serve()` is awaitable):

- **Foreground:** uvicorn HTTP server (handles all `/reports/*` and `/healthz` traffic).
- **Background:** aiokafka consumer task (drains `threat.scores`, writes into `threat_scores` table).

A startup hook spawns the consumer task; a shutdown hook cancels it cleanly. The whole entry point uses nested try/finally to guarantee `aclose()` discipline on httpx, aiokafka, and aiosqlite clients (pattern established in #4 — see roadmap memory).

## 3. Scope (in / out)

### In v1
- Single hard-coded report template: **Security Summary** (header, executive summary stats, threat-score bar chart, approvals table).
- Per-request PDF generation (synchronous; the API blocks until the PDF is rendered).
- Persistent local store for generated PDFs.
- JWT-authenticated API. Role gates: admin|analyst can generate + delete; any logged-in user can list + download.
- React Reports page (`chronos-ai-guard/src/pages/Reports.tsx`) rewritten to live data.

### Out of v1 (deferred to v2 — see §13)
- Celery / Celery Beat scheduled reports.
- Compliance template variants.
- MinIO / S3 storage.
- CSV export.
- Notifications (email / Slack).
- Multi-format export (HTML, JSON).
- Retention / pruning of `threat_scores` rows.
- The 7 other "Mock data — v2" pages (Dashboard, FileIntegrity, NetworkMonitoring, AIAnomaly, EmployeeManagement, SystemConfig, AuditLogs) — stay mock.

## 4. Data Sources

### 4.1 Threat scores — local SQLite, populated by Kafka consumer
The reporting service subscribes to `threat.scores` using `consumer_group="intellifim-reporting"` and `auto_offset_reset="latest"` (consistent with the same setting in correlation-engine, anomaly-detector, and policy-engine — all four are flagged in the v2 deferral list for the same `latest` → `earliest` rethink).

Messages are decoded as `intellifim_schemas.ThreatScoreUpdate` (Pydantic v2 `BaseModel` with `extra="forbid"`, available since intellifim-schemas 0.4.0 from #4). Successful decodes are inserted into the `threat_scores` table:

| Column | Type | Source |
|---|---|---|
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | local |
| `host_id` | TEXT NOT NULL | `ThreatScoreUpdate.host_id` |
| `score` | REAL NOT NULL | `ThreatScoreUpdate.score` |
| `reason` | TEXT NOT NULL | `ThreatScoreUpdate.reason` |
| `ts` | TEXT NOT NULL (ISO-8601 UTC) | `ThreatScoreUpdate.ts.isoformat()` |

Indexes: `(ts)` and `(host_id, ts)`. Insert-only — no updates, no v1 retention.

Malformed JSON / Pydantic ValidationError is logged at WARN and skipped (does not stall the partition — same `_extract_event` discipline from #3/#4/#5).

### 4.2 Approvals — HTTP call to orchestrator
The reporting service does NOT mirror approvals locally. On each report generation, it issues:

```
GET http://response-orchestrator:8200/approvals
Authorization: Bearer <forwarded user JWT>
```

The user's JWT is extracted from the inbound `/reports/generate` request's `Authorization` header and forwarded verbatim. This means the orchestrator's existing JWT middleware + RBAC sees the actual requesting user — no service-account magic.

The response is parsed as a list of approval objects. The reporting service filters by `created_at ∈ [range_start, range_end]` client-side (the orchestrator's API does not accept a date filter in v1; approvals volume is low — a handful per day — so client-side filtering is fine).

If the orchestrator is unreachable (connection refused, timeout, 5xx), the reporting service returns HTTP 502 with `{"error": "could not reach response-orchestrator"}`. The service deliberately does NOT produce a "0 approvals" report on orchestrator failure — that would lie to the operator.

## 5. HTTP API

Base URL: `http://reporting:8300` (inside Compose), `http://127.0.0.1:8300` (host).

### 5.1 Endpoints

| Method | Path | Auth | Roles | Purpose |
|---|---|---|---|---|
| GET | `/healthz` | None | — | Liveness probe. Returns `{"status": "ok"}` 200. |
| POST | `/reports/generate` | JWT | admin \| analyst | Generate a new report. Returns `ReportMetadata`. |
| GET | `/reports` | JWT | admin \| analyst \| viewer | Paginated list, newest first. Query params: `limit` (default 50, max 200), `offset` (default 0). |
| GET | `/reports/{id}` | JWT | admin \| analyst \| viewer | Single report metadata. 404 if not found. |
| GET | `/reports/{id}/download` | JWT | admin \| analyst \| viewer | Stream PDF bytes. `Content-Type: application/pdf`. `Content-Disposition: attachment; filename="..."`. |
| DELETE | `/reports/{id}` | JWT | admin | Remove DB row + delete PDF file. Idempotent (delete-nonexistent returns 404, not 500). |

### 5.2 Request / response models

```python
class GenerateReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    range_start: AwareDatetime   # UTC, inclusive
    range_end: AwareDatetime     # UTC, exclusive

    # Pydantic model_validator:
    # - range_end > range_start
    # - (range_end - range_start) <= timedelta(days=90)
```

```python
class ReportMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    name: str
    range_start: AwareDatetime
    range_end: AwareDatetime
    generated_at: AwareDatetime
    generated_by: str            # principal.username from JWT
    size_bytes: NonNegativeInt
    approvals_count: NonNegativeInt
    scores_count: NonNegativeInt
```

```python
class ReportListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reports: list[ReportMetadata]
    total: NonNegativeInt
```

### 5.3 Error envelope

Uniform across all endpoints. FastAPI's default `{"detail": "..."}` is remapped to `{"error": "..."}` via `@app.exception_handler(...)` — same pattern as `auth-backend/api.py`:

| Status | When |
|---|---|
| 400 | Invalid request body. Examples: `range_end <= range_start`, range > 90 days, name empty, bad date format. |
| 401 | Missing / malformed / expired JWT. |
| 403 | Viewer hitting POST `/reports/generate` or DELETE `/reports/{id}`; analyst hitting DELETE. |
| 404 | `GET /reports/{id}` or `DELETE /reports/{id}` for unknown id. |
| 502 | Orchestrator unreachable during generate. |
| 500 | WeasyPrint render exception, matplotlib chart exception, unexpected store error. (Logged with stack trace; client sees `{"error": "internal server error"}`.) |

### 5.4 JWT validation

Reuses the HS256 + shared `JWT_SECRET` pattern from #6. The `Principal` dataclass + `decode_token()` helper from `data-plane/orchestrator/src/orchestrator/auth.py` are conceptually copied into `data-plane/reporting/src/reporting/auth.py`, but adapted to FastAPI's `Depends` style (matches `auth-backend`'s `_current_user`). This keeps the auth contract identical across the three backend services without forcing reporting to host aiohttp middleware.

`now: Callable[[], datetime]` is threaded through `build_app(...)` into the JWT decoder so tests can forge tokens against a fixed `_T0` clock (the lesson from #6 Task 8 — clock-injection must reach every place `now()` is called).

## 6. PDF Generation Pipeline

End-to-end flow for `POST /reports/generate`:

1. **Validate** request body via Pydantic. Bad body → 400.
2. **Query local scores:** `SELECT host_id, score, reason, ts FROM threat_scores WHERE ts BETWEEN ? AND ? ORDER BY ts`.
3. **Fetch approvals** via authenticated httpx call. Orchestrator unreachable → 502. Filter by date range client-side.
4. **Compute summary stats:**
   - total approvals
   - approvals by state (PENDING / APPROVED / EXECUTED / REJECTED / FAILED)
   - approvals by priority (HIGH / LOW)
   - total threat-score samples
   - unique hosts seen
   - top 10 hosts by max score in range (used in chart)
5. **Render chart:** matplotlib bar chart, x = top 10 hosts, y = max score. Figure size 8x4 in at 100 DPI. Save to `io.BytesIO()` as SVG, base64-encode, embed as `<img src="data:image/svg+xml;base64,...">`. Empty data → render the chart anyway with a "No data in range" annotation (don't omit the chart — keeps template stable).
6. **Render Jinja2 template** `security_summary.html.j2` with the data dict.
7. **WeasyPrint** converts HTML → PDF bytes: `weasyprint.HTML(string=html).write_pdf()`.
8. **Persist:**
   - Write bytes to `/data/reports/{generated_at YYYY-MM-DD}-{uuid}.pdf`.
   - Insert row into `reports` table.
9. **Respond** with `ReportMetadata` (no PDF bytes in the response; client follows up with `/download`).

A single `/reports/generate` request is expected to complete in 1–5 seconds depending on row counts. v1 does this synchronously — no background job queue. v2 may move long-running generations to Celery.

## 7. Frontend Wiring

File: `chronos-ai-guard/src/pages/Reports.tsx` — rewritten.

### 7.1 Page layout
1. **Header:** "Reports" + "Generate and download Security Summary PDFs" subtitle.
2. **Generate form** (visible only to `admin` or `analyst` per `useAuth()`):
   - name (text input)
   - range_start (datetime picker)
   - range_end (datetime picker)
   - "Generate PDF" button → `useMutation` → `POST /reports/generate` via `apiClient.ts`
   - On success: invalidate the report-list query so the new row appears at the top of the table. Toast "Report generated."
   - On error: toast with the error message.
3. **Reports table** (visible to all roles):
   - `useQuery({ queryKey: ["reports"], queryFn: () => apiFetch(REPORTING_API_URL + "/reports?limit=50") })`
   - No polling — reports are user-triggered.
   - Columns: Name, Date Range, Generated By, Generated At, Size, Download.
   - Download action: `apiFetch(.../download)` → `response.blob()` → `URL.createObjectURL(blob)` → trigger click on a hidden `<a download="name.pdf" href={url}>` element → `URL.revokeObjectURL(url)`. This is the only way to download an auth-gated file via the browser's `Authorization: Bearer` header without leaking the JWT in URLs.

### 7.2 Stripped from current page
- All `mockChartData` imports and Recharts components (`BarChart`, `LineChart`, etc.) — gone.
- The "Mock data — v2" badge — gone (page is live).

### 7.3 Kept but disabled
- "Export CSV" button — stays in the layout as a disabled button with a tooltip "CSV export — v2".

### 7.4 `apiClient.ts` changes
Add one export:
```ts
export const REPORTING_API_URL =
  import.meta.env.VITE_REPORTING_API_URL ?? "http://localhost:8300";
```
`apiFetch()` itself does not change — same Bearer-token injection + 401-handling works.

### 7.5 Vite env
Add `VITE_REPORTING_API_URL=http://localhost:8300` to `chronos-ai-guard/.env.development` (or whichever env file the Compose admin-console mount uses). Compose `environment:` on admin-console also sets it, so dev + Compose stay in sync.

### 7.6 Frontend tests
Zero new JS unit tests in v1 (vitest setup still deferred — explicitly carried forward from #6's v2 deferral list). DoD #10 validates the page end-to-end in a real browser.

## 8. Schemas & Storage

### 8.1 SQLite tables

```sql
CREATE TABLE IF NOT EXISTS threat_scores (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id TEXT NOT NULL,
    score   REAL NOT NULL,
    reason  TEXT NOT NULL,
    ts      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threat_scores_ts ON threat_scores(ts);
CREATE INDEX IF NOT EXISTS idx_threat_scores_host_ts ON threat_scores(host_id, ts);

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
CREATE INDEX IF NOT EXISTS idx_reports_generated_at ON reports(generated_at DESC);
```

### 8.2 `ReportingStore` class
Single class wrapping aiosqlite. Pattern matches #5's `ApprovalStore` and #6's `UsersStore`:

- One `aiosqlite.Connection` per instance.
- `row_factory = aiosqlite.Row`.
- All writes serialized via a single `asyncio.Lock` (single-writer SQLite).
- Reads concurrent (no lock).
- `init_schema()` idempotent — returns immediately if already initialized.

Methods:
- `insert_score(host_id, score, reason, ts)`
- `query_scores(start, end, host_id=None) -> list[ScoreRow]`
- `top_hosts_by_max_score(start, end, limit=10) -> list[tuple[host_id, max_score]]`
- `insert_report(metadata, pdf_path) -> ReportMetadata`
- `list_reports(limit, offset) -> tuple[list[ReportMetadata], total_count]`
- `get_report(id) -> ReportMetadata | None`
- `delete_report(id) -> bool`  (returns True if row existed)

### 8.3 PDF filesystem layout
```
/data/                              ← reporting_data volume
├── reporting.db                    ← SQLite
└── reports/
    ├── 2026-05-20-<uuid>.pdf
    ├── 2026-05-21-<uuid>.pdf
    └── ...
```
- Flat directory. No date partitioning in v1.
- Filenames: `{generated_at YYYY-MM-DD}-{uuid}.pdf` (sortable + globally unique).
- `reports/` directory created during `init_schema()` if missing.
- On `DELETE /reports/{id}`: SQL DELETE first, then `os.unlink(pdf_path)`. If unlink raises FileNotFoundError, log WARN and continue — keeps endpoint idempotent against a partially-deleted-prior state.

### 8.4 Internal models
Defined in `data-plane/reporting/src/reporting/models.py` (NOT added to `intellifim-schemas` — these are not on any Kafka topic; intellifim-schemas stays at 0.4.x):
- `GenerateReportRequest`
- `ReportMetadata`
- `ReportListResponse`
- `Principal` (frozen dataclass: `user_id: UUID`, `username: str`, `role: Literal["admin","analyst","viewer"]` — field shape matches `data-plane/orchestrator/src/orchestrator/auth.py`'s `Principal` so a single JWT contract holds across the two backend services; `Role` is tightened to the Literal here vs. orchestrator's loose `str`)

### 8.5 Jinja2 template
Single file at `data-plane/reporting/src/reporting/templates/security_summary.html.j2`. All CSS is inlined in a `<style>` block (WeasyPrint does not follow `<link>` to external stylesheets unless given a `base_url`; one-file template keeps things portable).

Template sections in order:
1. **Cover** — title, date range (formatted), generated_by, generated_at.
2. **Executive summary** — stat cards (total approvals, by-state, by-priority, total scores, unique hosts).
3. **Threat scores** — inline matplotlib SVG chart (top 10 hosts by max score).
4. **Approvals** — table sorted by `created_at`.

A4 page size. Helvetica fallback (DejaVu Sans is shipped via apt; matplotlib auto-falls-back).

## 9. Service Composition

### 9.1 New service block (in `data-plane/docker-compose.yml`)
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
    volumes:
      - reporting_data:/data
    ports:
      - "127.0.0.1:8300:8300"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8300/healthz').read()"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  # ... existing volumes ...
  reporting_data:
```

### 9.2 Modified service: `admin-console`
- Add `reporting: { condition: service_healthy }` to `depends_on`.
- Add `VITE_REPORTING_API_URL: "http://localhost:8300"` to `environment`.

### 9.3 Stack count
21 (after #4) → 23 (after #6) → **24 (after #7)**.

### 9.4 No new Kafka topics
Reporting consumes existing `threat.scores` only. No producer side.

### 9.5 No schema-package bump
intellifim-schemas stays at 0.4.x. Reporting is consumer-only.

## 10. Repo Layout

New directory `data-plane/reporting/`:
```
data-plane/reporting/
├── .dockerignore
├── Dockerfile
├── README.md
├── pyproject.toml
├── src/reporting/
│   ├── __init__.py
│   ├── __main__.py
│   ├── api.py
│   ├── auth.py
│   ├── config.py
│   ├── consumer.py
│   ├── models.py
│   ├── orchestrator_client.py
│   ├── renderer.py
│   ├── store.py
│   └── templates/
│       └── security_summary.html.j2
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── test_api.py
    ├── test_config.py
    ├── test_consumer.py
    ├── test_orchestrator_client.py
    ├── test_renderer.py
    └── test_store.py
```

### Dockerfile
Follows the same context-at-`data-plane/` pattern as the orchestrator's Dockerfile (build context is one level above the service so `COPY schemas` works):

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

- System deps from WeasyPrint upstream docs.
- `fonts-dejavu-core` for matplotlib (slim image has no system fonts).
- Same two-stage `COPY + pip install` pattern as `data-plane/orchestrator/Dockerfile` — keeps the schemas install layer cacheable across service rebuilds.
- `intellifim-reporting` is a `console_scripts` entry point in `pyproject.toml` that calls `reporting.__main__:main` (same pattern as `intellifim-orchestrator`, `intellifim-auth-backend`).

### pyproject.toml (key dep ranges, NOT equality pins)
```toml
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
```

### Branch
`feat/reporting-v1` off main.

## 11. Testing

### 11.1 Unit tests (~25 new; total moves from 210 → ~235 Python + 5 Rego)

| Module | Count | Coverage |
|---|---|---|
| `tests/test_config.py` | ~4 | env-var parsing; required fields fail-fast (JWT_SECRET, KAFKA_BOOTSTRAP, ORCHESTRATOR_URL); defaults for ports/paths; bad URL rejected. |
| `tests/test_store.py` | ~6 | aiosqlite + asyncio.Lock store; insert/query threat_scores by date range; insert/list/get/delete reports; idempotent init_schema; concurrent reads. |
| `tests/test_consumer.py` | ~3 | dual-mode `_extract_score` (typed instance fast-path + bytes-via-FakeMessage); malformed JSON skipped without stalling; valid ThreatScoreUpdate inserted. |
| `tests/test_renderer.py` | ~4 | Jinja2 template renders empty + populated data; WeasyPrint produces non-empty PDF bytes starting with `%PDF`; matplotlib chart helper returns valid SVG. |
| `tests/test_orchestrator_client.py` | ~3 | httpx + respx; forwards Bearer token; raises on 502/timeout; parses approval JSON list. |
| `tests/test_api.py` | ~7 | FastAPI factory + TestClient; `/healthz` 200; `/reports/generate` admin\|analyst gate (viewer → 403); `/reports` newest-first; `/reports/{id}/download` streams PDF bytes; DELETE admin-only + idempotent; missing JWT → 401; range > 90 days → 400. |

### 11.2 Test infrastructure to repeat
- `now: Callable[[], datetime]` injection in store + API + JWT decoder.
- `_T0` fixed test clock + `_make_token(...)` helper for JWT forging (copied from orchestrator tests, threaded through `build_app(now=...)` so the auth path shares the mock clock — the lesson from #6 Task 8).
- `respx` for mocking orchestrator `/approvals` responses.
- `pytest-asyncio` (already standard).
- `aiosqlite` against in-memory `":memory:"` DB.

### 11.3 Definition of Done (10 items)

1. **`pytest` green** — full suite stays green: ~235 Python + 5 Rego.
2. **`docker compose up -d`** on a fresh checkout brings up **24 services** healthy within 60s. `init-secrets.sh` runs first if no JWT_SECRET yet.
3. **Healthcheck** — `curl http://127.0.0.1:8300/healthz` returns `{"status": "ok"}`.
4. **Background consumer working** — within 30s of `docker compose up`, `threat_scores` table has ≥ 1 row. Verified via `docker exec reporting sqlite3 /data/reporting.db "SELECT count(*) FROM threat_scores"`.
5. **JWT-auth wall** — `curl -X POST /reports/generate` without token → 401. With viewer token → 403.
6. **End-to-end generate via curl** — log in via auth-backend → POST `/reports/generate` with 24h range → response has non-zero `size_bytes`. `GET /reports/{id}/download` returns bytes starting with `%PDF-`.
7. **Persistence across restart** — after `docker compose restart reporting`, generated report still listed in `GET /reports` and still downloadable.
8. **Orchestrator unreachable → 502** — stop orchestrator container, attempt to generate → reporting returns 502 with `{"error": ...}` (not 500; no corrupt report row).
9. **PDF well-formed** — open in PDF viewer (or `pdfinfo`); page count ≥ 1; contains date range, summary stats, matplotlib chart, approvals table.
10. **Browser end-to-end** — log into admin console at `http://localhost:5173` as `admin` → navigate to `/reports` → fill form → click "Generate PDF" → see new row appear → click "Download" → browser downloads valid PDF.

### 11.4 Smoke script
`data-plane/scripts/generate-report.py` — equivalent of `approve-pending.py` for #5. Logs in as admin via auth-backend, POSTs `/reports/generate` with a fixed 24h range, downloads the result to `/tmp/`. Exit codes:
- 0 — success
- 1 — login failed
- 2 — generate failed
- 3 — download failed
- 4 — missing creds env
- 5 — reporting unreachable

## 12. Error Handling & Edge Cases

| Scenario | Behavior |
|---|---|
| Malformed Kafka message | Logged WARN, skipped. Partition not stalled. |
| Pydantic ValidationError on `ThreatScoreUpdate` decode | Same as malformed — logged + skipped. |
| Empty `threat_scores` for a range | Report still renders; chart shows "No data in range" annotation; summary stats show zeros. Not an error. |
| Empty `approvals` for a range | Report still renders; table shows "No approvals in range". Not an error. |
| Orchestrator returns 5xx during generate | Reporting returns 502 with explanatory error. Generate is not partially-persisted (failed before INSERT). |
| Orchestrator returns 401 (forwarded JWT expired between request hop and outbound call) | Reporting returns 401, propagating the upstream signal. |
| WeasyPrint render exception | 500 + log full stack trace. No partial PDF written; no DB row inserted. |
| matplotlib chart helper raises | Same as WeasyPrint — 500 with stack trace logged; nothing persisted. |
| `os.unlink(pdf_path)` raises FileNotFoundError on DELETE | Log WARN, return 200 (idempotent). |
| Disk full during PDF write | 500. DB row insert is AFTER successful file write, so no orphan DB rows. (Orphan PDF files possible if process crashes between write + insert; tolerated as a known v1 limitation — explicit in §13.) |
| Date range > 90 days | 400 at request validation. |
| Date `range_end <= range_start` | 400. |
| `name` empty or >200 chars | 400. |

## 13. Known v2 Follow-ups

Carried forward from v1's deliberate scope reductions. These will appear in a "From #7" block in the roadmap memory after merge.

- **Celery + Celery Beat scheduled reports** (master spec target). Daily 09:00 UTC summary, weekly Monday digest, ad-hoc cron.
- **Compliance template variants:** PCI-DSS, HIPAA, GDPR, ISO 27001, NIST 800-53. Each is a Jinja2 template variant + an explicit `kind` enum on `GenerateReportRequest`.
- **MinIO / S3 storage** (master spec target). Replaces filesystem-on-volume.
- **CSV export.** Wire the (currently disabled) Reports.tsx button to a `GET /reports/{id}/export.csv` endpoint that streams CSV of the approvals + scores from the same time range.
- **Email / Slack / webhook notifications** on generation completion.
- **Retention / pruning** of `threat_scores` rows (matches Kafka's 14-day retention; nightly cron).
- **Healthcheck + resource limits** on `reporting` service (request limits, memory caps).
- **CORS hardening** — replace `localhost:5173` allowlist with real production origin (parallel to #6's deferral).
- **Background job queue** for long-running generations (move synchronous render off the request thread; pair with Celery).
- **Orphan-PDF cleanup task** — sweep `/data/reports/` for files with no matching `reports` row.
- **`reports.kind` column + multi-template support** (paired with compliance templates).
- **Per-host detail report kind** — supplements the global summary.
- **Live tail of `events.scored` / `events.correlated` into the report** for forensic depth.
- **JS test setup** (vitest + react-testing-library) so Reports.tsx gets unit tests (parallel to #6's deferral).
- **Auth-backend `/auth/me`-cached `Principal` lookup** instead of decoding JWT on every endpoint hit.
- **`reporting` service Postgres migration** (paired with the orchestrator + auth-backend's planned migrations).
- **Refresh tokens** — same v2 wave as #6 (currently long-lived 8h JWTs leak into the orchestrator's hop and into reporting's outbound call).
- **`auto_offset_reset="latest"` → `"earliest"`** rethink — same item as #2/#3/#4 (consistent across all consumers).
- **WeasyPrint font configuration** — proper Helvetica via msttcorefonts or embedded TTF; ditch DejaVu fallback.
- **Per-report download permissions** — currently any logged-in user can download any report; v2 adds report-owner-or-admin gating.
- **README curl-example** for `generate-report.py` doesn't warn that JWTs expire after 8h (parallel to #6's deferral).

## 14. References

- Master tech-stack design: `docs/superpowers/specs/2026-05-04-intellifim-tech-stack-design.md` (§4.10 Reporting)
- Sub-project #1: data plane — `docs/superpowers/specs/2026-05-04-data-plane-v1-design.md`
- Sub-project #4: policy engine (produces `threat.scores`) — `docs/superpowers/specs/2026-05-18-policy-engine-v1-design.md`
- Sub-project #5: response orchestrator (provides `/approvals` API) — `docs/superpowers/specs/2026-05-19-response-orchestrator-v1-design.md`
- Sub-project #6: admin console + auth-backend (shared JWT contract) — `docs/superpowers/specs/2026-05-20-admin-console-v1-design.md`
- Roadmap memory (canonical sub-project status): `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/project_intellifim_roadmap.md`
