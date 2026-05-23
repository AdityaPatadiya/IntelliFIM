# IntelliFIM Data Plane (v1 — walking skeleton)

Self-contained Docker Compose stack that delivers validated, canonical
security events from a Linux endpoint and a network sensor into the
`events.normalized` Kafka topic. This is the foundation every other
IntelliFIM sub-project (correlation, ML, scoring, dashboard) consumes.

See [`docs/superpowers/specs/2026-05-04-data-plane-v1-design.md`](../docs/superpowers/specs/2026-05-04-data-plane-v1-design.md)
for the full design. v2 (Schema Registry, observability, secrets) and
v3 (HA Kafka, K8s, multi-agent) are explicit follow-ups.

## What's in the box

28 services on Docker Compose:

- **Sources:** `wazuh-manager`, `wazuh-agent`, `zeek-sensor`
- **Shipping:** `filebeat-wazuh`, `filebeat-zeek`
- **Bus:** `kafka` (single broker, KRaft mode)
- **Correlation:** `correlation-engine` (per-host file ↔ network time-window join, see [correlator/](correlator/))
- **Anomaly detection:** `anomaly-detector` (per-event IsolationForest scoring, see [anomaly/](anomaly/))
- **Policy & scoring:** `policy-engine` + `opa` + `redis` (per-host dynamic threat score via Rego + sliding window, see [policy/](policy/))
- **Response orchestration:** `response-orchestrator` (3-tier classifier + SQLite approval store + aiohttp REST API + Wazuh AR dispatch, see [orchestrator/](orchestrator/))
- **Auth backend:** `auth-backend` (FastAPI + SQLite + HS256 JWT, seeds admin from env, see [auth_backend/](auth_backend/))
- **Admin console:** `admin-console` (React + Vite + shadcn live wiring of the Response Approvals + Reports pages, see [../chronos-ai-guard/](../chronos-ai-guard/))
- **Reporting:** `reporting` (port 8300; FastAPI + WeasyPrint + Jinja2 + matplotlib PDF generation; consumes `threat.scores` Kafka into local SQLite + fetches `/approvals` from the orchestrator on demand; persistent report store on `reporting_data` volume; see [reporting/](reporting/))
- **Normalizers:** `normalizer-wazuh-fim`, `normalizer-wazuh-auth`,
  `normalizer-zeek-conn`, `normalizer-zeek-dns`, `normalizer-zeek-http`,
  `normalizer-zeek-files`
- **Dev tooling:** `kafka-ui`, `victim-server`, `victim-client`
- **Simulation lab (on-demand, profile `sim`):** `simulator` (5 curated attack scenarios with built-in `threat.scores` verification; `profiles: [sim]` keeps it hidden from `up -d`. See [simulator/](simulator/))
- **Observability:** `prometheus` (port 9090), `grafana` (port 3000), `alertmanager` (port 9093) — scrapes the 6 in-house Python services every 15s, auto-provisions 2 dashboards (Pipeline overview + Threat & response health), routes 1 example alert rule (`IntelliFIMServiceDown`) to Alertmanager's console UI. See [prometheus/](prometheus/), [grafana/](grafana/), [alertmanager/](alertmanager/).
- **Persistence (v2):** `postgres` (port 5433 on host → 5432 in container, `bus` network) hosts 3 separate databases (`auth_backend`, `orchestrator`, `reporting`) for the 3 services that previously used SQLite. PDFs continue to live on the `reporting_data` Docker volume (only metadata is in Postgres). See [postgres/](postgres/).

## Prerequisites

- Docker Engine >= 24 with Compose v2
- ~4 GB free RAM, ~5 GB disk
- Python 3.12 (only if you want to run `tail-normalized.py` from the host)

## Bring up the stack

```bash
cd data-plane

# 1. One-time: prepare env file and the FIM monitored dir.
cp .env.dataplane.example .env.dataplane
mkdir -p monitored

# 2. Build the seven service images.
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

Wait ~90 seconds for Wazuh agent enrollment and Zeek to start writing logs.

## See events flow

### Browser

Open [http://localhost:8080](http://localhost:8080) for `kafka-ui`.
Topics -> `events.normalized` -> Messages.

### Terminal

```bash
# Install the schema package once (from repo root)
pip install -e schemas
pip install aiokafka

# Tail canonical events (Ctrl-C to stop)
python scripts/tail-normalized.py --bootstrap localhost:9094
```

## Generate test traffic

```bash
# Deterministic burst (FIM + a few HTTP GETs)
./scripts/seed-test-traffic.sh

# Replay a curated pcap
./scripts/replay-pcap.sh pcaps/http_get_basic.pcap
```

A FIM event also fires whenever you write to `monitored/`:

```bash
echo "hello" > monitored/anything.txt
```

## See correlations

The correlation engine joins file and network events from the same host
within ±60 s and publishes matches on `events.correlated`. Tail it:

```bash
python scripts/tail-correlated.py --bootstrap localhost:9094
```

Trigger a guaranteed correlation by running `seed-test-traffic.sh` (which
emits both FIM and network events for the same host) — at least one
`CorrelatedEvent` should print within ~30 s.

## See anomaly scores

The anomaly-detector consumes every CanonicalEvent on `events.normalized`,
scores it with a pre-trained IsolationForest (model baked into the image
at build time from `anomaly/training-data/baseline-events.jsonl`), and
publishes a `ScoredEvent` to `events.scored`. Tail it:

```bash
python scripts/tail-scored.py --bootstrap localhost:9094
```

Each line includes `model`, `score` (0.0-1.0 where 1.0 = max anomaly),
`is_anomaly` (`score >= threshold`), and the embedded source event. The
threshold defaults to `0.5` and is tunable via the `ANOMALY_THRESHOLD`
env var on the `anomaly-detector` service in compose.

## See dynamic threat scores

The policy-engine consumes every `ScoredEvent`, queries OPA for a per-event
score delta (per the Rego policy at `policy/policies/threat_score.rego`),
maintains a per-host sliding-window threat score in Redis, and publishes
`ThreatScoreUpdate` to `threat.scores`. Tail it:

```bash
python scripts/tail-scores.py --bootstrap localhost:9094
```

Each line shows `host`, `score` (0-100 sliding-window sum, default 5-min
window, clamped at 100), `contribs` (count of contributions in the
window), `last_delta` (this event's OPA decision), and `last_reason`
(OPA's explanation).

Edit the Rego policy under `policy/policies/`, then `docker compose
restart opa` to reload. v1 has no live-reload; v2 will add OPA's
`--watch` flag.

## Approve a response action

When a `ThreatScoreUpdate` lands with `score >= 30` (default `TIER_LOW_THRESHOLD`),
the `response-orchestrator` records it as a PENDING approval request in its
SQLite store. List, inspect, and approve via the REST API on port 8200:

```bash
# List PENDING requests
curl -s http://127.0.0.1:8200/approvals | jq

# Inspect one
curl -s http://127.0.0.1:8200/approvals/<id> | jq

# Approve (synchronous: dispatches `!quarantine0` to the agent via Wazuh API
#  and returns the terminal state — EXECUTED on success, FAILED on dispatcher error)
curl -s -X POST http://127.0.0.1:8200/approvals/<id>/approve | jq

# Or reject
curl -s -X POST http://127.0.0.1:8200/approvals/<id>/reject | jq

# Helper that polls + approves the first PENDING request
python scripts/approve-pending.py
```

On approval the orchestrator authenticates against the Wazuh Manager REST API
(`https://wazuh-manager:55000`, dev creds `wazuh/wazuh`, TLS verify disabled
for v1) and issues `PUT /active-response` with `command="!quarantine0"`.
The manager accepts the dispatch and queues it for the agent.

**v1 limitation:** the manager API returns 200 (dispatch accepted) but in
the current Wazuh 4.14 dev compose the AR command does not propagate to the
agent's `wazuh-execd`. The orchestrator's contract — authoritative state
transition + Wazuh API success — is honored; actual `quarantine.sh`
execution + marker file landing is a v2 target (deeper Wazuh-side AR queue
investigation needed).

## Use the admin console

Open `http://localhost:5173/auth` in a browser. Log in with the
credentials from `.env.dataplane` (defaults: `admin@intellifim.dev` /
`changeme`). Navigate to **Incident Management** (header reads "Response
Approvals" — same route): PENDING approval requests are polled every
3 seconds from the orchestrator's `/approvals` endpoint. Click
**Approve** to dispatch a `!quarantine0` AR command (synchronous; state
flips to `EXECUTED` within ~3 seconds on success). Click **Reject** to
close the request without dispatch. Viewers see disabled buttons with a
tooltip.

The **Reports** page is now live (sub-project #7): admins and analysts
see a "Generate report" card (name + date-range form) plus a "Past
reports" table. Clicking **Generate PDF** calls
`POST http://localhost:8300/reports/generate` and the new row appears at
the top of the list on success. **Download** streams the PDF via
authenticated blob → hidden anchor (preserves `Authorization: Bearer`).
Viewers see the table only — no generate form. CSV export is disabled
with a "v2" tooltip.

The remaining 7 pages (Dashboard, FileIntegrity, NetworkMonitoring,
AIAnomaly, EmployeeManagement, SystemConfig, AuditLogs) still render
mock data and are tagged with a "Mock data — v2" badge until later
sub-projects wire them up.

### Generate a report from the terminal

```bash
export ADMIN_EMAIL=$(grep ^ADMIN_EMAIL= .env.dataplane | cut -d= -f2-)
export ADMIN_PASSWORD=$(grep ^ADMIN_PASSWORD= .env.dataplane | cut -d= -f2-)
./scripts/generate-report.py
```

Logs in, generates a 24h-window Security Summary PDF, downloads it to
`/tmp/intellifim-smoke-<uuid>.pdf`. Exit codes: `0` success, `1` login
failed, `2` generate failed, `3` download failed, `4` missing creds env,
`5` reporting/auth-backend unreachable.

The orchestrator's REST API at `:8200` now requires `Authorization:
Bearer <jwt>` on every request except `/healthz`. POST `/approve` and
POST `/reject` additionally require role=admin or role=analyst; viewer
gets 403. To call the API directly from curl, log in first:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"admin@intellifim.dev","password":"changeme"}' \
    | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8200/approvals
```

## Consume canonical events from a downstream service

The canonical schema lives in the `intellifim-schemas` package. Any
sub-project that consumes events should depend on it directly:

```toml
# pyproject.toml
[project]
dependencies = [
    "intellifim-schemas>=0.3,<1.0",
    "aiokafka>=0.10",
]
```

Then:

```python
from aiokafka import AIOKafkaConsumer
from intellifim_schemas import CanonicalEvent

consumer = AIOKafkaConsumer(
    "events.normalized",
    bootstrap_servers="kafka:9092",   # or "localhost:9094" from host
    group_id="my-downstream-service",
)
await consumer.start()
async for msg in consumer:
    event = CanonicalEvent.model_validate_json(msg.value)
    ...
```

## Adding a new pcap

See [pcaps/README.md](pcaps/README.md).

## Run attack scenarios

The simulation lab lives at [simulator/](simulator/) (sub-project #8). It ships 5 curated scenarios that target `victim-server`; each verifies that the data plane detects the attack by tailing `threat.scores` for up to 60 seconds.

```bash
# From data-plane/:
./scripts/run-scenario.sh --list           # see all 5 scenarios
./scripts/run-scenario.sh data-exfil       # run one scenario
./scripts/run-all-scenarios.sh             # run all 5 sequentially
```

Scenarios:
- `data-exfil` — FIM (sensitive file) + zeek.http (POST) + zeek.dns (.invalid lookup)
- `webshell-drop` — FIM (cmd.php) + zeek.http (?c=id query string)
- `port-scan` — zeek.conn (1024-port asyncio sweep)
- `dns-tunnel` — zeek.dns (50 random subdomains under exfil.tunnel.invalid)
- `ransomware-rapid` — FIM (30 file create/truncate/delete cycles)

Each scenario exits `0` on detection (`✓ DETECTED score=X reason=...`), `2` on timeout (`✗ NO DETECTION`), `3` on attack-side failure, `4` on Kafka-unreachable.

**Override the threshold or timeout:**
```bash
./scripts/run-scenario.sh data-exfil --threshold 10.0 --timeout 120
```

**Verify the detection gate is real (sentinel test):**
```bash
./scripts/run-scenario.sh data-exfil --threshold 999    # exit 2 (impossibly high threshold)
```

**Cleanup** — file-based scenarios leave artifacts in `monitored/`:
```bash
rm -rf monitored/sensitive_* monitored/cmd_*.php monitored/doc_*
```

## Observability

Sub-project #9 (the final v1 sub-project) adds Prometheus metrics scraping, Grafana dashboards, and Alertmanager. All 6 in-house Python services (`auth-backend`, `response-orchestrator`, `reporting`, `correlation-engine`, `anomaly-detector`, `policy-engine`) expose `/metrics` endpoints; Prometheus scrapes them every 15s.

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
- No distributed traces (Jaeger).
- No Kafka exporter — `up` is the only Kafka health signal in v1.
- Grafana admin password is `admin/admin` for dev. v2 hardens.
- No Helm chart — Docker Compose only. v2 deferral.

## Postgres (v2)

Sub-project v2-1 migrated 3 SQLite-backed services (auth-backend, response-orchestrator, reporting) to a single Postgres 16 instance hosting 3 isolated databases:

| Database | Owner user | Used by |
|---|---|---|
| `auth_backend` | `auth` | auth-backend (`/auth/*` endpoints — users table) |
| `orchestrator` | `orchestrator` | response-orchestrator (approvals state machine) |
| `reporting` | `reporting` | reporting (threat_scores append-log + reports metadata) |

The root `postgres` superuser is used only by the one-shot init script at first boot.

```bash
# From data-plane/:
./scripts/check-postgres.sh                          # verify all 3 DBs + 3 users + tables exist
docker exec postgres psql -U postgres -l             # list databases
docker exec postgres psql -U postgres -d auth_backend -c "\dt"   # show tables
```

PDFs continue to live on the `reporting_data` Docker volume (only metadata is in Postgres). Host port is **5433** (not 5432) to avoid clashing with a Postgres install on the developer machine — services inside Compose use `postgres:5432` as usual.

**v2-1 limitations** (deferred to later v2/v3 work):
- No alembic — schemas managed by `CREATE TABLE IF NOT EXISTS` at startup.
- No TLS to Postgres — plain connections within the `bus` network. Pairs with the TLS-everywhere v2 theme.
- No HA — single Postgres replica. v3 adds streaming replication.
- No `postgres-exporter` for Prometheus — pairs with the observability v2 theme.
- No backup tooling — `pg_dump` cron + restore script is a v2/v3 follow-up.
- Db passwords in env vars, not Vault — Vault is its own v2 theme.

**For operators migrating from v1 (NOT a fresh checkout):** the legacy SQLite files in the OLD `auth_backend_data` and `orchestrator_data` volumes are unreferenced after the v2 swap. Remove them:
```bash
docker volume rm $(docker volume ls -q | grep -E "_(auth_backend_data|orchestrator_data)$")
```
The `reporting_data` volume STAYS (PDFs live there); just remove the legacy `reporting.db` file inside it:
```bash
docker exec reporting rm -f /data/reporting.db
```

## Tear down

```bash
docker compose --env-file .env.dataplane down       # keep volumes
docker compose --env-file .env.dataplane down -v    # also wipe Kafka data, Wazuh state
```

## Running the unit tests

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

# Rego policy tests (requires `opa` CLI or Docker):
opa test policy/policies/
# OR
docker run --rm -v $(pwd)/policy/policies:/p \
    openpolicyagent/opa:latest test /p
```

## Definition of done (v1)

This sub-project is "done" when all of the following pass on a fresh
checkout:

1. `docker compose up` after the steps above brings the stack up cleanly.
2. Touching a file in `monitored/` produces a `file.modified` /
   `file.created` canonical event on `events.normalized` within 5 s.
3. `victim-client`'s background curl loop produces ongoing
   `network.flow` / `network.http_request` events on
   `events.normalized`.
4. `scripts/replay-pcap.sh pcaps/http_get_basic.pcap` produces the
   expected zeek.* events.
5. All four of `pytest --import-mode=importlib schemas/tests normalizers/tests`,
   `pytest --import-mode=importlib correlator/tests`,
   `pytest --import-mode=importlib anomaly/tests`, AND
   `pytest --import-mode=importlib policy/tests` are green,
   PLUS the Rego tests via `opa test policy/policies/` (or the Docker
   equivalent) report `PASS: 5/5`
   (see "Running the unit tests" above for why the four-pass form is needed).
6. `python scripts/tail-correlated.py` prints at least one correlation
   after running `./scripts/seed-test-traffic.sh`.
7. `python scripts/tail-scored.py` prints at least one `ScoredEvent` after
   running `./scripts/seed-test-traffic.sh` (or `kafka-console-consumer` on
   `events.scored` finds ≥1 message with `"model_version":"isolation-forest-v1"`).
8. `python scripts/tail-scores.py` prints at least one `ThreatScoreUpdate`
   after running `./scripts/seed-test-traffic.sh` (or `kafka-console-consumer`
   on `threat.scores` finds ≥1 message with valid `score` field), AND
   `docker exec redis redis-cli ZCARD threat_score:host:001` returns ≥1.
9. `python scripts/approve-pending.py` against a stack that has been seeded
   via `./scripts/seed-test-traffic.sh` exits 0 with output containing
   `"state": "EXECUTED"` and a non-null `executed_at`, AND the Wazuh
   manager's `api.log` shows the corresponding `PUT /active-response` call
   returning HTTP 200 (the orchestrator's dispatch contract honored).
   Marker-file landing on the agent
   (`docker exec wazuh-agent ls /tmp/intellifim-quarantine-*.flag`) is a
   v2 target — see the spec's v2 backlog for the Wazuh-side AR propagation
   investigation needed to close that gap.
10. After bringing the stack up fresh and seeding traffic:
    a. `POST http://localhost:8000/auth/login` with the admin credentials
       returns a JWT `access_token`.
    b. Opening `http://localhost:5173/auth` in a browser and logging in
       redirects to the IncidentManagement (now "Response Approvals") page.
    c. The page lists at least one PENDING approval row (sourced from
       `GET /approvals` via the JWT).
    d. Clicking **Approve** on a PENDING row causes the row state to
       transition to EXECUTED within 3 seconds (the polling interval).
    e. The Wazuh manager's `api.log` shows the corresponding
       `PUT /active-response` call returning HTTP 200 (the orchestrator's
       dispatch contract honored — same v1 limitation as DoD #9 re: marker
       file landing on the agent).
