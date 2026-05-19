# Response Orchestrator v1 — Design Spec

**Status:** Approved 2026-05-19, ready for implementation planning
**Sub-project:** #5 of 9 in the IntelliFIM v1 walking-skeleton roadmap
**Depends on:** sub-project #4 (policy engine v1 — `threat.scores` topic + `ThreatScoreUpdate` schema)
**Reference:** `docs/superpowers/specs/2026-05-04-intellifim-tech-stack-design.md` §§ "Action dispatch", "Approval workflow"

## 1. Purpose

Consume the `threat.scores` Kafka topic produced by sub-project #4, classify each
`ThreatScoreUpdate` into a response tier, persist tier-2/tier-3 events as
approval requests in a small SQLite-backed store, expose a minimal HTTP API
for admin approve/reject, and on approval dispatch a single Wazuh Active
Response action (`quarantine.sh`) to the target agent.

The novel contribution of IntelliFIM lives in the AI/policy/response layers.
The data plane (#1), correlation (#2), ML (#3), and dynamic threat scoring (#4)
have already shipped; #5 closes the response leg of the walking skeleton —
the system can now act (with admin sign-off) on what it detects.

## 2. Scope (walking-skeleton minimum)

In scope for v1:

- One new Python service `response-orchestrator` at `data-plane/orchestrator/`.
- Consumes one Kafka topic (`threat.scores`); produces NO Kafka output.
- Three-tier classifier: IGNORE (score < 30), LOW_URGENCY (30 ≤ score < 70),
  HIGH_URGENCY (score ≥ 70). Both upper tiers do the same thing on approval;
  priority is metadata for v2 sorting / notification routing.
- Per-host dedupe: at most ONE PENDING approval request per `host_id` at a time.
  New `ThreatScoreUpdate` events for hosts already PENDING are dropped (logged).
- SQLite persistence at `/data/approvals.db` inside the orchestrator container,
  on a named Docker volume (`orchestrator_data`). No Postgres in v1.
- aiohttp REST API on port 8200 (host-published 127.0.0.1:8200): list, get,
  approve, reject. Synchronous approve path — dispatches Wazuh AR and returns
  the terminal state in the response.
- Wazuh Active Response integration: one custom script `quarantine.sh` that
  touches `/tmp/intellifim-quarantine-<update_id>.flag` on the agent. Dispatched
  via Wazuh Manager's REST API (`PUT /active-response`) over HTTPS with
  `verify=False` and stock dev credentials (`wazuh:wazuh`).
- No auth on the orchestrator API (bus-network only).
- No notifications (email/Slack/webhook) — admin polls `GET /approvals` or
  watches container logs.

Stack grows from 20 → 21 services (one new container: `response-orchestrator`).
No new Kafka topics, no new schema package additions, no infra additions
beyond the orchestrator itself.

## 3. Out of scope (deferred to v2 / later sub-projects)

- Postgres-backed approval store (master spec says Postgres; v1 sticks to
  SQLite because schema is trivial and admin-scale volume doesn't justify the
  4th infra container yet). Will revisit when sub-project #6 admin-console
  user accounts arrive.
- API authentication (JWT / OIDC via Keycloak — coupled to the same v2 wave).
- TLS to Wazuh Manager (drop `verify=False`).
- Email / Slack / webhook notifications on new approval requests.
- Audit topic `response.events` to Kafka for compliance / forensics.
- Auto-expire PENDING requests (TTL → auto-reject).
- Auto-execute tier (admin sign-off is required for ALL upper-tier actions
  in v1; auto-execute is a v2 trust-building feature once scoring is calibrated).
- Tier promotion (e.g. LOW PENDING + new HIGH update → promote in place).
  v1 strictly ignores new updates while a host has a PENDING row.
- Real enforcement library (`firewall-drop`, `disable-account`,
  `host-isolation`). v1 only ships `quarantine.sh` marker file.
- Wazuh-side AR pipeline investigation: in our dev compose stack, `PUT
  /active-response` returns 200 (manager accepts the dispatch) but the
  agent's `wazuh-execd` never receives or runs the AR command. Reproduces
  with manual `agent_control -b 1.2.3.4 -f quarantine0 -u 001`. The
  orchestrator's contract is honored; the agent-side AR queue propagation
  needs deeper Wazuh-internal wiring that's out of walking-skeleton scope.
- Idempotency on Wazuh AR retry — currently a manual re-POST creates a second
  marker file with the same update_id, which is OK because `touch` is
  idempotent, but real future actions like `iptables -A` would not be.
- Healthcheck + resource limits on the `response-orchestrator` service
  (siblings have the same gap).
- API request-body validation with Pydantic (currently hand-rolled `try/except KeyError`).
- Multi-replica orchestrator. v1 is single-writer; SQLite + `asyncio.Lock` cannot
  scale horizontally.
- Windows enforcement via PowerShell (master spec) — v3 with multi-agent.
- Admin console UI (sub-project #6).

## 4. Architecture overview

One new container plus a small shell script that runs inside the existing
wazuh-agent container.

```
threat.scores (existing)
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│ response-orchestrator                                   │
│  ┌─────────────┐    ┌──────────────────┐    ┌─────────┐ │
│  │ Kafka       │ →  │ Tier classifier  │ →  │ SQLite  │ │
│  │ consumer    │    │ + dedupe         │    │approvals│ │
│  │ (aiokafka)  │    │ (OrchestratorEngine)  │ store   │ │
│  └─────────────┘    └──────────────────┘    └─────────┘ │
│                                                  ▲      │
│  ┌─────────────────────────────────┐             │      │
│  │ aiohttp REST API (port 8200)    │ ────────────┘      │
│  │  GET  /healthz                  │                    │
│  │  GET  /approvals?state=PENDING  │                    │
│  │  GET  /approvals/{id}           │                    │
│  │  POST /approvals/{id}/approve   │ ───┐               │
│  │  POST /approvals/{id}/reject    │    │               │
│  └─────────────────────────────────┘    │               │
│                                          ▼              │
│  ┌──────────────────────────────────────────────────────┐│
│  │ WazuhClient (httpx)                                  ││
│  │ PUT https://wazuh-manager:55000/active-response      ││
│  └──────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
                                          │
                                          ▼
                              ┌──────────────────────────┐
                              │ wazuh-manager → wazuh-agent│
                              │ executes                  │
                              │ /var/ossec/active-response/│
                              │  bin/quarantine.sh         │
                              │ → touches /tmp/intellifim- │
                              │   quarantine-<id>.flag     │
                              └──────────────────────────┘
```

## 5. Tier classifier

Three tiers, thresholds env-tunable:

| Tier             | Default range          | Behavior                                              |
| ---------------- | ---------------------- | ----------------------------------------------------- |
| `IGNORE`         | score < 30             | log at INFO, no DB write                              |
| `LOW_URGENCY`    | 30 ≤ score < 70        | INSERT approval row with `priority='low'`             |
| `HIGH_URGENCY`   | score ≥ 70             | INSERT approval row with `priority='high'`            |

Env vars:
- `TIER_LOW_THRESHOLD` (default `30`, must be > 0 and < `TIER_HIGH_THRESHOLD`)
- `TIER_HIGH_THRESHOLD` (default `70`, must be ≤ 100 and > `TIER_LOW_THRESHOLD`)

Both upper tiers do the same thing on approval (`quarantine.sh` against the
host's agent). Priority is pure metadata in v1 — captured on the row so sub-project
#6 (admin console) can sort/filter, but the orchestrator itself does not branch
on it.

### Dedupe rule

Per-host singleton: each `host_id` has at most one row in state `PENDING` at any
time. While a host has a `PENDING` row, all new `ThreatScoreUpdate` events for
that host are dropped (logged at INFO). Once the row reaches any terminal state
(`APPROVED+EXECUTED`, `REJECTED`, or `FAILED`), the host is "clean" — the next
qualifying update creates a new row. **No tier promotion in v1.** If a LOW
PENDING row is open and a new HIGH update arrives, the HIGH update is dropped.

### Idempotency

The orchestrator stores `id = ThreatScoreUpdate.update_id`. If Kafka redelivers
the same update, an `INSERT OR IGNORE` on the PRIMARY KEY keeps things clean —
no duplicate rows, no second action.

## 6. Approval state machine

```
                     PENDING
                    /        \
                   ▼          ▼
              APPROVED      REJECTED  (terminal)
                  │
                  ▼  (auto, in same /approve handler)
              EXECUTED      (terminal — agent confirmed via AR)
                  │
                  ▼  (only if WazuhClient raised)
              FAILED        (terminal)
```

`EXECUTED` and `FAILED` are both terminal AND both make the host "clean" for
the dedupe rule. `FAILED` on purpose — we do not want a permanently stuck host
because the Wazuh manager was briefly unreachable.

## 7. SQLite schema

One table created at startup if missing:

```sql
CREATE TABLE IF NOT EXISTS approvals (
    id            TEXT PRIMARY KEY,         -- UUID, matches ThreatScoreUpdate.update_id
    host_id       TEXT NOT NULL,
    priority      TEXT NOT NULL,            -- 'low' | 'high'
    score         REAL NOT NULL,            -- snapshotted at request time
    last_reason   TEXT NOT NULL,
    state         TEXT NOT NULL,            -- PENDING|APPROVED|REJECTED|EXECUTED|FAILED
    created_at    TEXT NOT NULL,            -- ISO 8601 UTC
    decided_at    TEXT,                     -- nullable
    executed_at   TEXT,                     -- nullable
    decided_by    TEXT,                     -- nullable; v1 always 'curl' (no auth)
    error_message TEXT                      -- nullable; populated on FAILED
);

CREATE INDEX IF NOT EXISTS idx_approvals_host_pending
    ON approvals(host_id) WHERE state = 'PENDING';
```

The partial index makes the per-host dedupe lookup O(log n) without scanning
the EXECUTED/REJECTED/FAILED history.

DB file lives at `/data/approvals.db` inside the container, on a named volume
`orchestrator_data` declared in `docker-compose.yml`. Volume survives `docker
compose down` and is wiped only by `docker compose down -v`.

## 8. REST API surface

aiohttp server on `0.0.0.0:8200` inside the container; published to
`127.0.0.1:8200` on the host.

```
GET  /healthz
     → 200 {"status":"ok"}

GET  /approvals?state=PENDING                (state filter optional, default PENDING)
     → 200 {"approvals": [<row>, ...]}        ordered by created_at desc

GET  /approvals/{id}
     → 200 <row>
     → 404 {"error":"not found"}

POST /approvals/{id}/approve
     Body: {}  (v1 does not capture reviewer notes)
     → 200 {"id":"...", "state":"EXECUTED"}    on dispatcher success
     → 200 {"id":"...", "state":"FAILED",
            "error_message":"..."}             if WazuhClient raised
     → 404 {"error":"not found"}
     → 409 {"error":"not in PENDING state","current_state":"..."}

POST /approvals/{id}/reject
     Body: {}
     → 200 {"id":"...", "state":"REJECTED"}
     → 404, 409 as above
```

### Row JSON shape (used by every GET/POST response)

```json
{
  "id": "4fd43623-78cc-4f94-a365-c8a4ddfe0b8f",
  "host_id": "001",
  "priority": "high",
  "score": 75.0,
  "last_reason": "moderate anomaly",
  "state": "PENDING",
  "created_at": "2026-05-19T10:00:00Z",
  "decided_at": null,
  "executed_at": null,
  "decided_by": null,
  "error_message": null
}
```

### Synchronous approve path

The `/approve` handler does, in one async function:

1. `await store.get(id)`; 404 if None.
2. Verify `row.state == 'PENDING'`; 409 with `current_state` otherwise.
3. `await store.transition(id=id, from_state='PENDING', to_state='APPROVED', decided_by='curl', ...)`.
   If the transition returns None (row was raced into a different state), return 409.
4. Call `await wazuh.run_active_response(agent_id=row.host_id, command='quarantine0', arguments=[...])`.
5. On success: `await store.transition(... from_state='APPROVED', to_state='EXECUTED', executed_at=now)`. Return state `EXECUTED`.
6. On `WazuhDispatchError`: `await store.transition(... from_state='APPROVED', to_state='FAILED', error_message=str(exc))`. Return state `FAILED` (still HTTP 200 — request was processed, action failed).

Client sees the terminal state in the response — no polling.

### Concurrency

All SQLite writes go through a single `asyncio.Lock` held by the orchestrator
process. aiohttp serves reads concurrently; the lock only serializes state
transitions. v1 has one orchestrator replica, so no cross-process coordination
is needed.

### Error response shape

All errors return JSON `{"error": "..."}` with the appropriate HTTP code.
Handlers raise `web.HTTPNotFound(text=json.dumps({...}), content_type='application/json')`
etc. — no middleware framework in v1.

## 9. Wazuh Active Response integration

### `quarantine.sh` (runs on the agent)

Ships at `data-plane/orchestrator/wazuh-ar/quarantine.sh`. Mounted into the
wazuh-agent container at `/var/ossec/active-response/bin/quarantine.sh`
(mode 750, owned root:wazuh — matches Wazuh AR convention).

Wazuh's AR contract: the script receives a single JSON message on stdin
describing the alert + parameters. The script must read it, optionally act on
it, write a JSON confirmation back, and exit 0 on success.

```bash
#!/bin/bash
# data-plane/orchestrator/wazuh-ar/quarantine.sh
# IntelliFIM v1 walking-skeleton: touch a marker file so we can prove the AR
# pipeline (manager -> agent -> script execution) end-to-end.
set -euo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
MARKER_DIR="/tmp"

INPUT=$(cat)
echo "$(date -u +%FT%TZ) quarantine.sh invoked input=${INPUT}" >> "$LOG_FILE"

# Extract update_id from the parameters block (passed by the dispatcher).
# Fall back to a timestamp if absent so the script never crashes.
UPDATE_ID=$(echo "$INPUT" | grep -oE '"update_id"\s*:\s*"[^"]+"' \
              | sed -E 's/.*"([^"]+)"$/\1/' || echo "no-id-$(date +%s)")

MARKER="${MARKER_DIR}/intellifim-quarantine-${UPDATE_ID}.flag"
touch "$MARKER"

# Confirmation Wazuh expects
echo '{"version":1,"origin":{"name":"quarantine","module":"active-response"},"command":"check_keys","parameters":{"keys":[]}}'
exit 0
```

No `jq` dependency (the Wazuh agent base image may not have it). Plain
`grep`/`sed` keeps the script portable.

### Wazuh Manager configuration

A small XML snippet ships at `data-plane/orchestrator/wazuh-ar/ossec-snippet.xml`
and is appended into the manager's `ossec.conf` via a config volume mount or
init step (decided in the plan):

```xml
<ossec_config>
  <command>
    <name>quarantine</name>
    <executable>quarantine.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <command>quarantine</command>
    <location>local</location>
    <!-- no rules_id - dispatched only on demand via the REST API -->
  </active-response>
</ossec_config>
```

The dispatcher's API payload uses `command="quarantine0"` (Wazuh's `0` suffix
convention for non-rule-triggered AR commands).

### `WazuhClient` (inside the orchestrator)

Thin wrapper around `httpx.AsyncClient`. Failure surfaces as a custom
`WazuhDispatchError` (NOT swallowed) so the API caller sees `state=FAILED +
error_message`.

```python
class WazuhDispatchError(Exception): ...

class WazuhClient:
    def __init__(self, manager_url: str, user: str, password: str, *,
                 timeout_seconds: float = 5.0) -> None: ...
    async def authenticate(self) -> None: ...
        # POST /security/user/authenticate, caches JWT in self._token
    async def run_active_response(self, *, agent_id: str, command: str,
                                  arguments: list[str]) -> None: ...
        # PUT /active-response with the JWT.
        # On 401: re-authenticate ONCE and retry. After two consecutive 401s,
        # raise WazuhDispatchError.
        # On transport error or 5xx: raise WazuhDispatchError.
    async def aclose(self) -> None: ...
```

Env vars:
- `WAZUH_MANAGER_URL` (default `https://wazuh-manager:55000`)
- `WAZUH_API_USER` (default `wazuh`)
- `WAZUH_API_PASSWORD` (default `wazuh`)

Dispatch payload structure:
```json
{
  "command": "quarantine0",
  "arguments": ["-", "{\"update_id\":\"<uuid>\"}"],
  "agents_list": ["<host_id>"]
}
```

TLS: v1 uses `verify=False` in the httpx client with an INFO-level startup log
("connecting to Wazuh Manager with TLS verification disabled — dev only").
v2 swaps to a real cert. JWT refresh is in-memory; no on-disk cache.

## 10. Engine, Config, and Lifecycle

### `OrchestratorEngine`

Mirrors the proven `PolicyEngine` / `AnomalyEngine` shape:

```python
class OrchestratorEngine:
    def __init__(
        self,
        *,
        consumer,
        store: ApprovalStore,
        tier_classifier: Callable[[float], Tier],
        now: Callable[[], datetime] = _default_now,
    ) -> None: ...

    async def run(self) -> None: ...
        # async for raw_message in consumer:
        #     update = self._extract_event(raw_message)
        #     if update is None: continue
        #     await self._process(update)

    @staticmethod
    def _extract_event(message) -> ThreatScoreUpdate | None: ...
        # Dual-mode: typed ThreatScoreUpdate (test) OR object with .value bytes (prod)

    async def _process(self, update: ThreatScoreUpdate) -> None: ...
        # 1. Classify tier; if IGNORE, log+return.
        # 2. await store.insert_if_no_pending(...); if False (dedupe'd or
        #    duplicate update_id), log+return.
```

Engine writes to `ApprovalStore` only; reads (for the REST API) go through the
same store object from the aiohttp request handlers. Both share the
`asyncio.Lock` defined on the store.

### `ApprovalStore`

Async-friendly SQLite wrapper. Uses `aiosqlite` so the engine's `_process` and
the REST handlers don't block the event loop on disk I/O.

```python
class ApprovalStore:
    def __init__(self, db_path: str) -> None: ...
    async def init_schema(self) -> None: ...        # CREATE TABLE / INDEX IF NOT EXISTS
    async def insert_if_no_pending(
        self, *, id: UUID, host_id: str, priority: str,
        score: float, last_reason: str, now: datetime,
    ) -> bool: ...                                  # True if inserted, False if dedupe'd
    async def list(self, state: str | None = "PENDING") -> list[ApprovalRow]: ...
    async def get(self, id: UUID) -> ApprovalRow | None: ...
    async def transition(
        self, *, id: UUID, from_state: str, to_state: str,
        now: datetime, decided_by: str | None = None,
        executed_at: datetime | None = None,
        error_message: str | None = None,
    ) -> ApprovalRow | None: ...                    # None if from_state mismatch (caller -> 409)
    async def aclose(self) -> None: ...
```

All writes go through a single `asyncio.Lock` held on the store instance.
Reads are concurrent.

### `PolicyConfig`-style config

`OrchestratorConfig.from_env()` with fields:
`bootstrap_servers`, `consumer_group`, `input_topic`, `db_path`, `api_host`,
`api_port`, `wazuh_manager_url`, `wazuh_api_user`, `wazuh_api_password`,
`tier_low_threshold`, `tier_high_threshold`.

Validation: `tier_low_threshold > 0`, `tier_high_threshold ≤ 100`,
`tier_low_threshold < tier_high_threshold`. Otherwise `ValueError` at startup.

### `__main__.py` lifecycle

Nested try/finally mirrors `PolicyEngine`:

```python
async def _run() -> None:
    cfg = OrchestratorConfig.from_env()
    store = ApprovalStore(cfg.db_path)
    await store.init_schema()
    try:
        wazuh = WazuhClient(cfg.wazuh_manager_url, cfg.wazuh_api_user, cfg.wazuh_api_password)
        try:
            consumer = AIOKafkaConsumer(cfg.input_topic, ...,
                                        group_id=cfg.consumer_group,
                                        enable_auto_commit=True,
                                        auto_offset_reset="latest")
            await consumer.start()
            try:
                engine = OrchestratorEngine(consumer=consumer, store=store, ...)
                api_app = build_api(store=store, wazuh=wazuh)
                runner = web.AppRunner(api_app)
                await runner.setup()
                site = web.TCPSite(runner, cfg.api_host, cfg.api_port)
                await site.start()
                try:
                    await engine.run()       # blocks until consumer closes
                finally:
                    await runner.cleanup()
            finally:
                await consumer.stop()
        finally:
            await wazuh.aclose()
    finally:
        await store.aclose()
```

`KeyboardInterrupt` in `main()` logs "shutdown requested" and exits cleanly.

## 11. Test strategy

Mirror prior sub-projects' pattern: per-component pytest with fakes; one E2E
smoke; one external-tool test (shellcheck on `quarantine.sh`).

### Unit tests (~32 Python)

- `test_config.py` (~6 tests): default values, env overrides, invalid thresholds raise.
- `test_store.py` (~7 tests): insert PENDING, INSERT OR IGNORE on duplicate id,
  per-host singleton via the partial index, transition with correct from_state,
  transition with wrong from_state returns None, list filter, get returns None.
  Uses an in-memory or temp-file SQLite per test.
- `test_wazuh_client.py` (~6 tests) using `respx`: authenticate caches JWT,
  run_active_response sends correct JSON, 401 → re-auth + retry once,
  two 401s → `WazuhDispatchError`, transport error → `WazuhDispatchError`,
  5xx → `WazuhDispatchError`.
- `test_engine.py` (~6 tests): below threshold no DB write, low-tier inserts
  priority=low row, high-tier inserts priority=high, duplicate update_id ignored
  (idempotent), host already PENDING ignored, dual-mode `_extract_event`
  (typed + bytes).
- `test_api.py` (~7 tests) using `aiohttp.test_utils.TestClient` and a fake
  `WazuhClient`: `/healthz`, GET /approvals defaults to PENDING, GET /approvals/{id}
  404, POST .../approve happy path → EXECUTED, POST .../approve on already-decided → 409,
  POST .../reject → REJECTED, dispatcher raises → FAILED + error_message.

### Shell-script test

`tests/test_quarantine_sh.py` (pytest-driven for consistency, no bats
dependency): pipes a fixture JSON into `bash quarantine.sh`, asserts the marker
file appears in a tempdir, asserts stdout parses as valid JSON with the
`origin.name = "quarantine"` field. ~2 tests.

### E2E smoke (`scripts/approve-pending.py`)

A small Python script that polls `GET /approvals` until one PENDING row appears
(timeout 60s), then POSTs `/approve` on it, then verifies `docker exec
wazuh-agent ls /tmp/intellifim-quarantine-<id>.flag` succeeds. Wrapped into
Task 12's fresh-checkout smoke as DoD #9.

## 12. Definition of Done

Extends sub-project #4's 8 items. Adds one more:

```
9. POST /approvals/<id>/approve on a PENDING request returned by the
   orchestrator after seeded traffic results in:
   (a) HTTP 200 with state="EXECUTED",
   (b) `docker exec wazuh-agent ls /tmp/intellifim-quarantine-<id>.flag`
       succeeds (file present),
   (c) `sqlite3` query on the orchestrator's DB shows the row in state
       EXECUTED with non-null executed_at.
```

All 9 DoD items must pass on a fresh checkout.

## 13. Patterns reused from sub-projects #1–#4

- Range-pinned cross-package deps (`intellifim-schemas>=0.4,<1.0`).
- Dual-mode `_extract_event` on the Kafka consumer (typed instance OR `.value` bytes).
- `now: Callable[[], datetime]` injection for deterministic engine + store tests.
- Nested try/finally lifecycle in `__main__.py` (one finally per resource opened).
- Single Docker image per Python service-family (one service here).
- `# noqa: BLE001` only at the broad-except boundary where it's deliberate
  (here: only inside `WazuhClient` error wrapping — broad exception is NOT used
  on the engine loop, which has narrow catches by design).
- Plan-as-immutable-contract; mid-execution amendments folded back into the
  plan's code blocks.
- Two-stage subagent review per task (spec compliance → code quality).
- `extra="forbid"` on every Pydantic schema; `AwareDatetime` for any datetime field.

## 14. New patterns introduced in this sub-project

- **First sub-project with a long-running HTTP server alongside the Kafka loop.**
  aiohttp + AIOKafkaConsumer co-existing in one event loop, started inside a
  nested try/finally so cleanup is exact even on mid-startup failures.
- **First use of SQLite + `aiosqlite`** in the data plane. Pattern: a single
  `asyncio.Lock` on the store serializes writes; reads are concurrent.
- **First Wazuh Manager API integration.** JWT lifecycle (authenticate +
  in-memory cache + single retry on 401) + `verify=False` startup warning.
- **First custom Active Response script.** Volume-mount strategy for the AR
  binary; `ossec-snippet.xml` for manager-side command registration.

## 15. v2 / v3 follow-ups (explicit deferrals so future-us doesn't re-litigate)

(Already enumerated in §3. Listed again here as a sub-project-scoped checklist
to fold back into the roadmap memory after #5 ships.)

- Postgres + migrations
- API auth (JWT/OIDC via Keycloak)
- TLS to Wazuh Manager (drop `verify=False`)
- Email / Slack / webhook notifications
- Audit topic `response.events` to Kafka
- TTL auto-expire on PENDING requests
- Auto-execute tier (no admin sign-off for low-severity)
- Tier promotion (LOW PENDING + HIGH update → promote in place)
- Real enforcement library (firewall-drop, disable-account, isolate-host)
- Idempotency on AR retry for non-idempotent actions
- Healthcheck + resource limits on `response-orchestrator`
- Pydantic request-body validation in the API
- Multi-replica orchestrator + Postgres-backed locking
- Windows enforcement (multi-agent, v3)
- Admin console UI (sub-project #6)
