# Admin Console v1 — Design Spec

**Status:** Approved 2026-05-20, ready for implementation planning
**Sub-project:** #6 of 9 in the IntelliFIM v1 walking-skeleton roadmap
**Depends on:** sub-project #5 (response orchestrator v1 — REST API at `:8200`)
**Reference:** `docs/superpowers/specs/2026-05-04-intellifim-tech-stack-design.md` §§ "Approval workflow", "Framework / UI components"

## 1. Purpose

Wire the existing `chronos-ai-guard/` React frontend (Vite + shadcn/ui +
react-router + react-query, fully shelled with 10 mock pages today) into the
data-plane stack as the FIRST live admin surface: an authenticated console
where an analyst or admin can review PENDING approval requests produced by
the response-orchestrator (#5) and click Approve or Reject. To do that
honestly, this sub-project also ships a tiny `auth-backend` service (since
none exists today and the existing AuthContext expects one at `:8000`) and
extends the orchestrator with JWT validation + role-based access control.

This is the first sub-project that:
- Touches the React frontend (all prior work has been backend-only).
- Introduces a Python service that's NOT aiohttp (auth-backend uses FastAPI).
- Adds an aiohttp middleware to the orchestrator.
- Establishes a shared secret across data-plane services (`JWT_SECRET`).
- Exposes a browser-facing port from Compose.

## 2. Scope (walking-skeleton + real auth)

In scope for v1:

- New Python service `auth-backend` at `data-plane/auth_backend/` —
  FastAPI on port 8000. SQLite-backed user store. HS256 JWT signing.
  Endpoints: `POST /auth/login`, `POST /auth/register`, `GET /auth/me`,
  `GET /healthz`. Seeds one admin from env on first start.
- New Compose service `admin-console` — the existing `chronos-ai-guard/`
  frontend, built from its existing dev-target Dockerfile, bind-mounted
  source for hot reload. Container port 8080 published to host port 5173
  (kafka-ui keeps host 8080).
- Modifications to `response-orchestrator` (#5):
  - Aiohttp middleware that validates `Authorization: Bearer <jwt>` on every
    request except `/healthz`. Returns 401 on missing/invalid token.
  - Per-route role guard: `POST /approvals/{id}/approve` and `POST
    /approvals/{id}/reject` require `role in {admin, analyst}`; `viewer`
    gets 403. GET endpoints accept any valid token.
  - New `OrchestratorConfig.jwt_secret` field (required env var,
    fails fast at startup).
  - New `/healthz`-backed Compose healthcheck so `admin-console`'s
    `depends_on` can wait for it cleanly.
- Modifications to `chronos-ai-guard/`:
  - `AuthContext.tsx` wired to the new auth-backend (the shape already
    matches; just point it at real endpoints and store the JWT).
  - New `src/lib/apiClient.ts` — small fetch wrapper that injects
    `Authorization: Bearer <token>` and handles 401 by logging out +
    redirecting to `/auth`. Reads `VITE_AUTH_API_URL` and
    `VITE_ORCHESTRATOR_API_URL` from env.
  - `IncidentManagement.tsx` — replace `mockIncidents` with a
    react-query `useQuery` that polls `/approvals` every 3 seconds; render
    rows as `ApprovalRow` shape; add Approve + Reject buttons that POST via
    `useMutation`. Buttons disabled for `viewer` role with a tooltip.
    Header text updated to "Response Approvals".
  - Other 8 pages get a one-line "Mock data — v2" badge in their header
    so the user can tell what's wired vs not. Internals unchanged.
- New `scripts/init-secrets.sh` helper that generates `JWT_SECRET` and
  writes it into `.env.dataplane` on first stack-up (no-op if already set).
- Update `approve-pending.py` to call `/auth/login` first and forward the
  token on all subsequent orchestrator calls.

Stack grows from 21 → 23 services (`auth-backend` + `admin-console`).

## 3. Out of scope (deferred to v2 / later sub-projects)

- Postgres-backed user store (master spec target; v1 sticks to SQLite for
  walking-skeleton consistency with the orchestrator).
- Refresh tokens, password reset, email verification, account lockout.
- Rate limiting on `/auth/login`.
- Audit log of login / approve / reject events to Kafka (couples with
  sub-project #5's deferred `response.events` topic).
- RS256 + key rotation (v1 uses HS256 shared secret).
- httpOnly cookie token storage + CSRF protection (v1 uses localStorage —
  already what the existing AuthContext does).
- OIDC / Keycloak integration (replaces the in-house auth-backend entirely
  in v2; master spec calls this out).
- Admin-only `/auth/register` (v1 has open registration; role is selectable
  in the request body — acceptable for dev).
- Per-page wiring for the other 8 mock pages (Dashboard, FileIntegrity,
  NetworkMonitoring, AIAnomaly, EmployeeManagement, SystemConfig, Reports,
  AuditLogs). Most depend on services that don't exist yet (Reports →
  sub-project #7, AuditLogs → response.events topic, Dashboard live tail →
  Kafka→SSE bridge).
- JS test setup (vitest + react-testing-library). The existing
  `chronos-ai-guard/package.json` has no test runner; introducing one is
  a meaningful side-project. v1 covers the auth contract via Python tests
  (auth-backend + orchestrator JWT/RBAC) + a manual UX smoke (DoD #10).
- Frontend prod build wired into Compose (the existing
  `chronos-ai-guard/Dockerfile` has a `prod` nginx target; v1 uses `dev`
  for hot reload).
- WebSocket / SSE push from orchestrator → admin-console (v1 polls every
  3 s — same UX feel for low-volume v1 traffic).
- Live tail of Kafka topics in the console (needs a Kafka→SSE bridge service).
- Per-user theme + i18n persistence (currently localStorage only;
  per-user persistence requires storing prefs in users.db, deferred).
- Role enforcement on SYSTEM-LEVEL settings UI (v1 only enforces approve/
  reject; viewer can see every page in the existing UI).

## 4. Architecture overview

Two new services plus one extended; one frontend container.

```
              ┌──────────────────────────────────┐
              │ Browser                          │
              │ chronos-ai-guard                 │
              │ (React/Vite/shadcn)              │
              │   AuthContext (localStorage)     │
              │   apiClient.ts                   │
              │   IncidentManagement (LIVE)      │
              │   Other 8 pages (mock+badge)     │
              └────────┬──────────────────┬──────┘
                       │                  │
       /auth/login,    │                  │  GET /approvals
       /register, /me  │                  │  POST .../approve|reject
       (Bearer)        │                  │  (Bearer)
                       ▼                  ▼
       ┌────────────────────┐    ┌─────────────────────────┐
       │ auth-backend        │   │ response-orchestrator    │
       │ (FastAPI)           │   │  + NEW JWT middleware    │
       │  SQLite users.db    │   │  + role guards           │
       │  HS256 JWT signer   │   │  + /healthz              │
       │  Seeds admin on     │   │  (existing approvals     │
       │   first start       │   │   logic unchanged)       │
       └────────────────────┘    └─────────────────────────┘
                       ▲                  ▲
                       │ JWT_SECRET shared (HS256)
                       │ via .env.dataplane
                       │
                  ┌────┴───┐
                  │ secret │
                  └────────┘
```

**Port allocation:**

| Service               | Container port | Host port           | Notes                             |
| --------------------- | -------------- | ------------------- | --------------------------------- |
| auth-backend          | 8000           | 127.0.0.1:8000      | matches AuthContext default       |
| response-orchestrator | 8200           | 127.0.0.1:8200      | unchanged                         |
| admin-console (Vite)  | 8080           | 127.0.0.1:5173      | kafka-ui keeps 8080 → host 8080   |

`JWT_SECRET` is single-source-of-truth in `data-plane/.env.dataplane`, read
by both `auth-backend` and `response-orchestrator` via Compose
`environment:` blocks. `scripts/init-secrets.sh` generates one on first
start if missing.

CORS on both backends defaults to
`http://localhost:5173,http://127.0.0.1:5173` (env-overridable). No
credentials/cookies in v1.

## 5. `auth-backend` service

### 5.1 Tech stack

| Concern         | Choice                                                |
| --------------- | ----------------------------------------------------- |
| Web framework   | **FastAPI** (~0.115)                                  |
| Server          | **uvicorn** (standard worker)                         |
| Storage         | **SQLite** via `aiosqlite>=0.20,<0.22`                |
| Password hash   | **passlib[bcrypt]** `>=1.7,<2`                        |
| JWT             | **python-jose[cryptography]** `>=3.3,<4`              |
| Validation      | **Pydantic v2** (`>=2.7,<3`)                          |
| Python          | 3.12 (same as all data-plane services)                |

FastAPI chosen over the existing aiohttp pattern because (a) it bundles
OpenAPI/Swagger at `/docs` — useful for a small auth service that admins
poke at via curl, (b) `python-jose` and `passlib` integrate cleanly via
FastAPI's dependency-injection idiom, (c) it's an industry default for
auth APIs and signals intent. Adds one new framework to the codebase;
worth it for the focused use-case.

### 5.2 SQLite schema

```sql
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,           -- UUID
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,               -- bcrypt
    role          TEXT NOT NULL,               -- 'admin' | 'analyst' | 'viewer'
    created_at    TEXT NOT NULL                -- ISO 8601 UTC
);
```

DB at `/data/users.db` (Compose volume `auth_backend_data`).
`init_schema()` idempotent via `CREATE TABLE IF NOT EXISTS`.

### 5.3 Bootstrap admin

At startup, if no user with `role='admin'` exists, INSERT one from env
vars `ADMIN_USERNAME` (default `admin`), `ADMIN_EMAIL` (required),
`ADMIN_PASSWORD` (required). All required env vars missing → fail fast.
Idempotent on restart. Logged at INFO: `seeded admin user
<username>` or `admin user already exists, skipping seed`.

### 5.4 JWT shape

HS256, default 8-hour TTL (`JWT_TTL_SECONDS=28800` env-overridable):

```json
{
  "sub": "4fd43623-78cc-4f94-a365-c8a4ddfe0b8f",
  "username": "alice",
  "email": "alice@example.com",
  "role": "admin",
  "iat": 1747767000,
  "exp": 1747795800
}
```

### 5.5 Endpoints

```
POST /auth/register
   Body: {"username":"...", "email":"...", "password":"...", "role":"admin|analyst|viewer"}
   → 201 {"id":"...", "username":"...", "email":"...", "role":"..."}
   → 409 {"error":"username or email already exists"}
   → 422 {"error":"validation failed", "details":[...]}

POST /auth/login
   Body: {"email":"...", "password":"..."}
   → 200 {"access_token":"<jwt>", "token_type":"bearer",
          "user":{"id":"...","username":"...","email":"...","role":"..."}}
   → 401 {"error":"invalid credentials"}

GET /auth/me
   Header: Authorization: Bearer <jwt>
   → 200 {"id":"...","username":"...","email":"...","role":"..."}
   → 401 {"error":"unauthorized"}

GET /healthz
   → 200 {"status":"ok"}
```

Password never round-trips back through any response. `/auth/register`
hashes via `passlib.hash.bcrypt`; `/auth/login` verifies via the same.

### 5.6 Env vars

| Var               | Required | Default                                            |
| ----------------- | -------- | -------------------------------------------------- |
| `DB_PATH`         | no       | `/data/users.db`                                   |
| `API_HOST`        | no       | `0.0.0.0`                                          |
| `API_PORT`        | no       | `8000`                                             |
| `JWT_SECRET`      | **yes**  | — (fails fast)                                     |
| `JWT_TTL_SECONDS` | no       | `28800` (8h)                                       |
| `CORS_ORIGINS`    | no       | `http://localhost:5173,http://127.0.0.1:5173`      |
| `ADMIN_USERNAME`  | no       | `admin`                                            |
| `ADMIN_EMAIL`     | **yes**  | — (fails fast)                                     |
| `ADMIN_PASSWORD`  | **yes**  | — (fails fast)                                     |

### 5.7 Lifecycle

Nested try/finally in `__main__.py` (matches orchestrator pattern):
load config → open SQLite store → init_schema → seed admin → start uvicorn
inside a try → cleanup store. `KeyboardInterrupt` → INFO log + clean exit.

### 5.8 Tests (~19)

- `test_config.py` (~4): defaults, overrides, missing `JWT_SECRET` raises,
  missing `ADMIN_EMAIL`/`ADMIN_PASSWORD` raises.
- `test_users_store.py` (~5): create user; duplicate username raises;
  duplicate email raises; `get_by_email` returns user or None;
  `password_hash` is bcrypt (not plaintext); seed_admin idempotent.
- `test_jwt.py` (~3): encode produces a 3-segment string; decode round-
  trips claims; expired token raises.
- `test_api.py` (~7): `/healthz`; `/register` happy path; `/register`
  duplicate → 409; `/login` happy → token; `/login` wrong password → 401;
  `/me` with token → user; `/me` without token → 401.

Uses FastAPI's `TestClient` (sync, backed by httpx). Temp-file SQLite via
`tempfile.mkstemp` per test (mirrors orchestrator's `ApprovalStore` tests).

## 6. `response-orchestrator` modifications

### 6.1 New file `data-plane/orchestrator/src/orchestrator/auth.py`

```python
class AuthError(Exception):
    def __init__(self, status: int, message: str): ...

@dataclass(frozen=True)
class Principal:
    user_id: UUID
    username: str
    role: str   # 'admin' | 'analyst' | 'viewer'

def decode_token(token: str, secret: str) -> Principal:
    # python-jose HS256 verify. Raises AuthError on:
    #  - malformed Bearer header (handled by middleware)
    #  - invalid signature
    #  - expired token
    #  - missing required claims
    ...

@web.middleware
async def auth_middleware(request, handler):
    # Skip /healthz.
    # Parse `Authorization: Bearer <jwt>`. Missing/malformed → 401.
    # decode_token → store on request['principal'].
    # Role guard: /approve and /reject require admin or analyst.
    # Catch AuthError; return uniform JSON.
    ...
```

### 6.2 `api.py` changes

- `build_api()` signature gains `jwt_secret: str`.
- `web.Application(middlewares=[functools.partial(auth_middleware, secret=jwt_secret)])`.
- New 401 response shape: `{"error":"unauthorized"}`.
- New 403 response shape:
  `{"error":"forbidden", "required_role":"admin|analyst", "actual_role":"viewer"}`.
- `/healthz` (already exists) is the only unauthenticated route.

### 6.3 `config.py` changes

- `OrchestratorConfig.jwt_secret: str` — required env (`JWT_SECRET`),
  fails fast at startup.
- Update `test_config.py` `test_from_env_with_defaults` to set
  `JWT_SECRET` via the monkeypatch (otherwise the test now fails to
  construct config — small migration nit).

### 6.4 New tests (~5)

- `test_auth.py` (~3):
  - `decode_token` rejects invalid signature
  - `decode_token` rejects expired token
  - `decode_token` rejects token missing required claims (sub, role)
- `test_api.py` (~2 new):
  - `test_unauthenticated_returns_401` (request without Authorization header)
  - `test_viewer_cannot_approve_returns_403` (token signed with role=viewer)
- Existing 7 `test_api.py` tests now set `Authorization: Bearer <test_token>`
  generated by a new `_make_token(role, secret)` helper.

Brings orchestrator total to **43 unit tests** (was 38 in #5) + 2 shell.

### 6.5 `__main__.py` change

`build_api(store=store, wazuh=wazuh, jwt_secret=cfg.jwt_secret)` — single
new keyword arg.

### 6.6 Compose `healthcheck` for orchestrator

Add a healthcheck to the existing `response-orchestrator` service block so
`admin-console`'s `depends_on: response-orchestrator: { condition: service_healthy }`
can wait correctly:

```yaml
healthcheck:
  test: ["CMD", "wget", "-q", "-O", "/dev/null", "http://localhost:8200/healthz"]
  interval: 5s
  timeout: 2s
  retries: 6
```

(Same shape as the opa healthcheck from sub-project #4; uses `wget` since
that exists in `python:3.12-slim`.) Verify by reading
`docker exec response-orchestrator which wget` before locking in — fall
back to `python -c "import urllib.request; urllib.request.urlopen('http://localhost:8200/healthz')"`
if not present.

## 7. `chronos-ai-guard/` frontend modifications

### 7.1 `src/lib/apiClient.ts` (NEW, ~40 lines)

```ts
type ApiOptions = RequestInit & { authBaseUrl?: string; apiBaseUrl?: string };

export const AUTH_API_URL =
  import.meta.env.VITE_AUTH_API_URL ?? "http://localhost:8000";
export const ORCH_API_URL =
  import.meta.env.VITE_ORCHESTRATOR_API_URL ?? "http://localhost:8200";

export function getToken(): string | null { return localStorage.getItem("access_token"); }

export async function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(url, { ...init, headers });
  if (response.status === 401) {
    localStorage.removeItem("access_token");
    localStorage.removeItem("aifim_user");
    window.location.href = "/auth";   // hard redirect; AuthContext re-initializes on load
  }
  return response;
}
```

### 7.2 `src/contexts/AuthContext.tsx` changes

Replace the current `fetchCurrentUser` and `login`/`register` stubs with
real calls to `auth-backend`:

- `login(email, password)` → `POST AUTH_API_URL/auth/login` → store
  `access_token` + `aifim_user` in localStorage → setUser.
- `register(username, email, password, role)` → `POST AUTH_API_URL/auth/register`
  (NB: existing AuthContext `register` returns void; v1 only creates the
  user, does NOT auto-login — caller redirects to login).
- `useEffect` on init: if token in localStorage, `GET /auth/me` to validate;
  on 401 clear localStorage. (apiClient's 401 handler covers this too.)
- `logout()` clears localStorage + setUser(null).

### 7.3 `src/pages/IncidentManagement.tsx` rewrite (~80 lines diff)

Replace `mockIncidents` import and the table-row mapping. New imports:

```tsx
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch, ORCH_API_URL } from "@/lib/apiClient";
import { useAuth } from "@/contexts/AuthContext";
```

Hooks:

```tsx
const { user } = useAuth();
const canDecide = user?.role === "admin" || user?.role === "analyst";
const qc = useQueryClient();

const { data: rows, isLoading } = useQuery({
  queryKey: ["approvals"],
  queryFn: async () => {
    const r = await apiFetch(`${ORCH_API_URL}/approvals?state=PENDING`);
    return (await r.json()).approvals as ApprovalRow[];
  },
  refetchInterval: 3000,
});

const approve = useMutation({
  mutationFn: async (id: string) => {
    const r = await apiFetch(`${ORCH_API_URL}/approvals/${id}/approve`, { method: "POST" });
    if (!r.ok) throw new Error(await r.text());
  },
  onSuccess: () => qc.invalidateQueries({ queryKey: ["approvals"] }),
});

const reject = useMutation({ /* same shape, POST /reject */ });
```

Table rendering: 7 columns matching `ApprovalRow` — `created_at` (formatted),
`host_id`, `priority` (color-coded badge), `score`, `last_reason`, `state`
(color-coded badge), Actions (two buttons, disabled when `!canDecide`, with
a `Tooltip` saying "Requires analyst or admin role").

Header text changes:
- H1: `"Response Approvals"` (was `"Incident Management (Row Data Displayed) Dynamic feature comming soon..."`)
- Subhead: `"Review threat-score updates and approve enforcement actions."`

### 7.4 "Mock data — v2" badge on the other 8 pages

Single one-line addition under each page's H1 — a `<Badge variant="outline">Mock data — v2</Badge>`. Files touched: `Dashboard.tsx`, `FileIntegrity.tsx`, `NetworkMonitoring.tsx`, `AIAnomaly.tsx`, `EmployeeManagement.tsx`, `SystemConfig.tsx`, `Reports.tsx`, `AuditLogs.tsx`. No other changes — they keep rendering mock data.

### 7.5 `vite.config.ts` — env injection

Vite picks up `VITE_*` env vars automatically; no config change needed
beyond setting them in Compose. The `apiClient.ts` `import.meta.env.VITE_AUTH_API_URL` access works out of the box.

### 7.6 No JS test setup in v1

The existing `chronos-ai-guard/package.json` has no test runner.
Introducing vitest + react-testing-library is meaningful side-work
deferred to v2. The auth contract is covered by Python tests in
auth-backend + orchestrator. The frontend is covered by DoD #10 (manual
UX smoke).

### 7.7 Compose service block

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
    environment:
      VITE_AUTH_API_URL: "http://localhost:8000"
      VITE_ORCHESTRATOR_API_URL: "http://localhost:8200"
```

`../chronos-ai-guard` because the frontend lives at the repo root, NOT
inside `data-plane/`. Bind-mounts give hot reload in dev (compose `up`
picks up source edits without rebuild). NOTE: the frontend NEVER speaks
the Compose internal hostnames — those URLs are resolved IN THE BROWSER
on the developer's host, so `localhost:8000` is correct (not `auth-backend:8000`).

## 8. `JWT_SECRET` management

`scripts/init-secrets.sh` (NEW, ~20 lines):

```bash
#!/usr/bin/env bash
# data-plane/scripts/init-secrets.sh
# Generates JWT_SECRET in .env.dataplane on first stack-up (idempotent).
set -euo pipefail

ENV_FILE="$(dirname "$0")/../.env.dataplane"
if grep -q '^JWT_SECRET=.\+' "$ENV_FILE" 2>/dev/null; then
    echo "JWT_SECRET already set in ${ENV_FILE}; skipping."
    exit 0
fi
SECRET=$(openssl rand -base64 48)
echo "JWT_SECRET=${SECRET}" >> "$ENV_FILE"
echo "JWT_SECRET written to ${ENV_FILE}"
```

`.env.dataplane.example` gains a placeholder `JWT_SECRET=` (empty), plus
`ADMIN_EMAIL=admin@intellifim.local` and `ADMIN_PASSWORD=changeme`.

README's "Bring up the stack" gains a single step before `docker compose
up -d`: `./scripts/init-secrets.sh` (idempotent, safe to re-run).

## 9. `scripts/approve-pending.py` modification

The existing script (added in #5) becomes auth-aware. Changes:

- New env vars / CLI args: `AUTH_BACKEND_URL` (default
  `http://127.0.0.1:8000`), `ADMIN_EMAIL`, `ADMIN_PASSWORD` (required).
- At startup: `POST {AUTH_BACKEND_URL}/auth/login` with the admin creds;
  capture the `access_token`.
- All subsequent calls to the orchestrator carry `Authorization: Bearer
  <token>`.
- Failure modes: auth-backend unreachable → exit 3; login 401 → exit 4.

DoD #9 from sub-project #5 continues to pass with this updated helper.

## 10. Definition of Done

Extends sub-project #5's 9 items with one more:

```
10. After bringing the stack up fresh and seeding traffic:
    a. POST /auth/login at http://localhost:8000 with the admin credentials
       returns a JWT access_token.
    b. Opening http://localhost:5173/auth in a browser and logging in
       redirects to the IncidentManagement (now "Response Approvals") page.
    c. The page lists at least one PENDING approval row (sourced from
       GET /approvals via the JWT).
    d. Clicking "Approve" on a PENDING row causes the row state to
       transition to EXECUTED within 3 seconds (the polling interval).
    e. The Wazuh manager's api.log shows the corresponding
       PUT /active-response call returning HTTP 200 (orchestrator dispatch
       contract honored — same v1 limitation as DoD #9 re: marker file
       landing on the agent).
```

All 10 DoD items must pass on a fresh checkout.

## 11. Test budget

| Surface                       | Existing | Added by #6 | Total after #6 |
| ----------------------------- | -------- | ----------- | -------------- |
| schemas + normalizers         | 70       |  0          | 70             |
| correlator                    | 20       |  0          | 20             |
| anomaly                       | 24       |  0          | 24             |
| policy                        | 26       |  0          | 26             |
| orchestrator                  | 38       |  5          | 43             |
| auth-backend                  |  0       | 19          | 19             |
| **Python total**              | 178      | **24**      | **202**        |
| Rego                          | 5        |  0          | 5              |
| Shell (quarantine.sh)         | 2        |  0          | 2              |
| **Grand total**               | 185      | **24**      | **209**        |

No new JS unit tests. DoD #10 covers the frontend end-to-end manually.

## 12. Patterns reused from sub-projects #1–#5

- Range-pinned cross-package deps (`fastapi>=0.115,<0.116`,
  `passlib[bcrypt]>=1.7,<2`, `python-jose[cryptography]>=3.3,<4`).
- `now: Callable[[], datetime]` injection for JWT TTL tests.
- Nested try/finally lifecycle in `__main__.py`.
- Single Docker image per Python service-family.
- `extra="forbid"` on every Pydantic request/response model.
- `AwareDatetime` for datetime fields.
- `# noqa: BLE001` only at intentional broad-except boundaries (auth
  middleware's catch-AuthError + the existing `_safe_publish` in #5).
- Two-stage subagent review per task.
- Plan-as-immutable-contract; mid-execution amendments folded back.
- Range pins, not equality (e.g. `intellifim-schemas>=0.4,<1.0` if needed —
  auth-backend doesn't need it in v1).

## 13. New patterns introduced in this sub-project

- **First non-aiohttp Python service** in the data-plane (FastAPI for
  auth-backend) — establishes the FastAPI + uvicorn + pytest-with-TestClient
  template for future services that need OpenAPI.
- **First shared secret across data-plane services** (`JWT_SECRET` consumed
  by both auth-backend and orchestrator). `scripts/init-secrets.sh` pattern
  for first-run secret generation.
- **First aiohttp middleware** in the orchestrator — establishes the
  per-request `Principal` injection pattern that v2 RBAC for other services
  can copy.
- **First Compose service exposing a browser-facing port** with bind-mounted
  source for hot reload. Sets the pattern for the prod-nginx build in v2.
- **First sub-project that touches the React frontend** — establishes the
  `apiClient.ts` + `useQuery`-driven polling pattern for future page wiring.
- **First sub-project that depends on cross-process secrets via env-file**
  (`.env.dataplane`) — `init-secrets.sh` is the bootstrap.

## 14. v2 / v3 follow-ups (deferrals enumerated so future-us doesn't re-litigate)

Already enumerated in §3. Listed here for sub-project-scoped checklist:

- Postgres-backed user store (replaces SQLite)
- Refresh tokens + short access-token TTL
- Password reset, email verification, account lockout
- Rate limiting on `/auth/login`
- Audit log of login / approve / reject events (couples with the
  `response.events` Kafka topic from sub-project #5 v2)
- RS256 + key rotation (replaces HS256 shared secret)
- httpOnly cookie token storage + CSRF protection
- OIDC / Keycloak (replaces in-house auth-backend entirely)
- Admin-only `/auth/register` (v1 has open registration)
- Per-page wiring for the other 8 mock pages
- vitest + react-testing-library + a few component / integration tests
- CORS hardening (replace permissive `localhost:5173` allowlist with the
  real production origin + credentials handling)
- Frontend prod build wired into Compose (Dockerfile already has a `prod`
  nginx target; v1 uses `dev`)
- WebSocket / SSE push from orchestrator → admin-console (currently polled
  every 3s)
- Live tail of Kafka topics in the console (needs a Kafka→SSE bridge)
- Per-user theme + i18n persistence (server-side in users.db)
- Role enforcement on SYSTEM-LEVEL settings UI (v1 only enforces approve/
  reject; viewer can see every page in the existing UI)
- Healthcheck + resource limits on `auth-backend` and `admin-console`
- Multi-replica auth-backend + Postgres-backed session store
