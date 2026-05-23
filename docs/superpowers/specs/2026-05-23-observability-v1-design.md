# Observability v1 — design

**Sub-project #9 of 9 (FINAL v1 sub-project)** in the IntelliFIM walking-skeleton. Adds the operational hygiene layer that the master spec §4.13 calls for, scoped tight: Prometheus + Grafana + Alertmanager scraping every in-house Python service. Helm chart is explicitly deferred to v2.

**Date:** 2026-05-23
**Author:** IntelliFIM team
**Status:** Approved — ready for implementation plan.

---

## 1. Goal

Ship the metric instrumentation + scraping + dashboarding + alerting layer that closes out v1:

1. Every in-house Python service exposes Prometheus metrics on a `/metrics` endpoint.
2. A new `prometheus` service scrapes all 6 every 15s.
3. A new `grafana` service auto-provisions a Prometheus datasource + 2 pre-built dashboards (Pipeline overview + Threat & response health).
4. A new `alertmanager` service receives alerts from Prometheus (one example rule: `IntelliFIMServiceDown`) and exposes a web UI; no outbound integrations (Slack/email/PagerDuty are v2).

The master tech-stack document (`docs/superpowers/specs/2026-05-04-intellifim-tech-stack-design.md` §4.13) calls for a much wider stack: Prometheus + Grafana + Loki + Jaeger/OpenTelemetry + Alertmanager + Blackbox exporter. This sub-project ships the **walking-skeleton subset**: metrics + dashboards + one alert rule. Loki, Jaeger, Blackbox, kafka-exporter, Slack/PagerDuty/email integrations, and the full Helm/Terraform/ArgoCD IaC stack are explicit v2/v3 deferrals — see §13.

## 2. Architecture

**3 new services added to the Compose stack** (all on the `bus` network, all bound to `127.0.0.1` on the host):

| Service | Image | Port | Purpose |
|---|---|---|---|
| `prometheus` | `prom/prometheus:v2.55.0` | 9090 | Scrapes every Python service's `/metrics`; 7-day retention; alerts route to `alertmanager:9093`. |
| `grafana` | `grafana/grafana:11.3.0` | 3000 | Auto-provisioned Prometheus datasource + 2 pre-built dashboards (JSON checked into the repo). Anonymous viewer access enabled for dev; admin login `admin/admin`. |
| `alertmanager` | `prom/alertmanager:v0.27.0` | 9093 | Receives Prometheus alerts; one example rule fires; operator views alerts via web UI. No outbound integrations in v1. |

**6 in-house Python services instrumented:**

| Service | `/metrics` endpoint | How exposed |
|---|---|---|
| `auth-backend` | `:8000/metrics` | `prometheus-fastapi-instrumentator` mounted on existing FastAPI app |
| `response-orchestrator` | `:8200/metrics` | New aiohttp `web.get("/metrics", ...)` route returning `generate_latest()` |
| `reporting` | `:8300/metrics` | `prometheus-fastapi-instrumentator` mounted on existing FastAPI app |
| `correlation-engine` | `:9100/metrics` | New `prometheus_client.start_http_server(9100)` at startup |
| `anomaly-detector` | `:9101/metrics` | Same — new metrics-only port |
| `policy-engine` | `:9102/metrics` | Same — new metrics-only port |

**Stack count: 24 → 27** in normal `docker compose up -d` operation. Simulator (`profiles: [sim]`) stays excluded — it's on-demand and would cause scrape failures.

## 3. Scope (in / out)

### In v1
- 3 custom service-level Prometheus metrics, uniform across all 6 services (lean RED method): `intellifim_messages_processed_total`, `intellifim_errors_total`, `intellifim_processing_seconds`.
- Auto-instrumented HTTP RED metrics on the 3 FastAPI/aiohttp services.
- 1 Prometheus scrape config covering all 6 Python services.
- 1 alert rule: `IntelliFIMServiceDown` (any scrape target unreachable for >2min).
- 1 Alertmanager config (console-only, `null-receiver`).
- 2 Grafana dashboards (Pipeline overview + Threat & response health), auto-provisioned.
- Grafana Prometheus datasource auto-provisioned.
- 1 verification script: `data-plane/scripts/check-observability.sh`.

### Out of v1 (deferred to v2/v3 — see §13)
- **Loki** (centralized logs) + Promtail.
- **Jaeger** + **OpenTelemetry SDK** in every service (distributed traces).
- **Blackbox exporter** (external uptime probes).
- **kafka-exporter** / Burrow (Kafka JMX → Prometheus, consumer lag per topic+partition).
- **Wazuh Indexer metrics** (depends on adding the Wazuh Indexer service first — v2).
- **Slack / PagerDuty / email / webhook** in Alertmanager (operator notification stack).
- **Additional alert rules**: HighErrorRate, KafkaConsumerLag, ApprovalQueueDepth, ReportGenerationFailure.
- **Helm chart scaffolding** — explicitly deferred per the scope decision in brainstorming; v2 cross-cutting pass.
- **Terraform / ArgoCD / Harbor / Linkerd** (full IaC + service-mesh stack — v3).
- **Grafana auth hardening** (replace `admin/admin`; OIDC integration — pairs with auth-backend v2 OIDC migration).
- **Long-term metrics storage** (Thanos / Cortex / Mimir).
- **Recording rules** (precompute common queries).
- **Dashboard-as-code** (jsonnet / grafonnet) — currently raw JSON.

## 4. Per-Service Metrics

### 4.1 The 3 custom service-level metrics (uniform across all 6 services)

Defined once per service in a new tiny helper module `data-plane/<service>/src/<service>/metrics.py`:

```python
from prometheus_client import Counter, Histogram

SERVICE_LABEL = "<service-name>"   # set per service, e.g. "policy-engine"

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

(The 6 copies are intentional — keeps each service's dep graph clean and avoids creating a shared cross-service Python package just for 30 lines of metric definitions.)

### 4.2 Where the metrics get incremented

Each service's main message-processing function does:

```python
from <service>.metrics import (
    messages_processed_total, errors_total, processing_seconds, SERVICE_LABEL,
)

with processing_seconds.labels(SERVICE_LABEL).time():
    try:
        # ... do the work ...
        messages_processed_total.labels(SERVICE_LABEL).inc()
    except Exception as e:
        errors_total.labels(SERVICE_LABEL, kind=type(e).__name__).inc()
        raise   # or log + continue, per service's existing error policy
```

Specific integration points per service:
- **auth-backend** — wrap the `/auth/login` and `/auth/register` handlers.
- **response-orchestrator** — wrap `engine.process_one(message)` (the per-Kafka-message handler) AND wrap each `/approvals` route handler.
- **reporting** — wrap `consumer.process_one(message)` (Kafka path) AND wrap `/reports/generate` (HTTP path).
- **correlation-engine** — wrap `engine.process_one(event)`.
- **anomaly-detector** — wrap `engine.process_one(event)`.
- **policy-engine** — wrap `engine.process_one(event)`.

### 4.3 How each service exposes `/metrics`

**For FastAPI services (auth-backend, reporting):**

```python
# in each service's api.py, just after `app = FastAPI(...)`
from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)   # adds GET /metrics
```

This adds the auto-instrumented HTTP RED metrics (`http_requests_total`, `http_request_duration_seconds`, `http_requests_inprogress`) AND mounts the `/metrics` endpoint.

**For the orchestrator (aiohttp):**

```python
# in orchestrator/api.py
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

async def metrics(_request: web.Request) -> web.Response:
    return web.Response(body=generate_latest(), content_type=CONTENT_TYPE_LATEST)

app.router.add_get("/metrics", metrics)
```

No auto-instrumentation library for aiohttp in v1 — we just expose the global registry. Auto-instrumented HTTP RED would require manual middleware. v2 deferral.

**For the 3 engines (correlation, anomaly, policy):**

They have no HTTP server today. At startup in `__main__.py`:

```python
import os
from prometheus_client import start_http_server
start_http_server(int(os.environ.get("METRICS_PORT", "9100")))
```

This spins up a tiny WSGI server on a separate port. The 3 engines get distinct ports (9100, 9101, 9102) via env-var override per service in `docker-compose.yml`.

### 4.4 Per-service Compose env additions

The 3 engine services each gain:

```yaml
    environment:
      METRICS_PORT: "9100"   # 9100 for correlator, 9101 for anomaly, 9102 for policy
    ports:
      - "127.0.0.1:9100:9100"
```

The 3 HTTP services don't need port changes — `/metrics` shares the existing port (8000 / 8200 / 8300).

### 4.5 `prometheus_client` dependency

Each Python service's `pyproject.toml` gains:

```toml
"prometheus-client>=0.20,<0.22",
```

The 2 FastAPI services (auth-backend, reporting) also add:

```toml
"prometheus-fastapi-instrumentator>=7.0,<8",
```

The orchestrator (aiohttp) and the 3 engines only need bare `prometheus-client`.

## 5. Prometheus

### 5.1 New Compose service

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
```

`prometheus_data` is a new named volume (7-day retention, fits comfortably in a few hundred MB for v1).

### 5.2 `prometheus.yml`

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

### 5.3 The one v1 alert rule

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

- `up{job=~"intellifim-.+"}` is automatically created by Prometheus per scrape target — value `1` if last scrape succeeded, `0` if not.
- `for: 2m` debounces transient scrape misses (service restart, brief network hiccup) — only fires if down for 2 consecutive minutes.
- Severity is `warning`. v1 ships only this one rule. v2 adds `critical` for higher-impact rules.

## 6. Alertmanager

### 6.1 New Compose service

```yaml
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
```

`alertmanager_data` named volume holds dedup/silence state across restarts.

### 6.2 `alertmanager.yml`

`data-plane/alertmanager/alertmanager.yml` (minimal v1 — console-only, no outbound integrations):

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

### 6.3 What "alerting" looks like in practice

1. Operator brings up the stack. All 6 services healthy → `up == 1` for everything → no alerts.
2. Operator stops one service: `docker compose stop policy-engine`.
3. Within 2 minutes (+ scrape interval), Prometheus fires the `IntelliFIMServiceDown` alert for `job="intellifim-policy"`.
4. Operator opens `http://localhost:9093` → sees the firing alert in Alertmanager UI with the formatted summary + description.
5. Operator brings the service back: `docker compose start policy-engine`. Within ~30 seconds, the alert resolves and disappears from the UI.

No Slack notifications, no PagerDuty, no email. Just the web UI. Master spec §4.13 integrations land in v2.

## 7. Grafana + Dashboards

### 7.1 New Compose service

```yaml
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
      GF_SECURITY_ADMIN_PASSWORD: "admin"   # dev-only; v2 hardens
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

Anonymous viewer access so operators hit `http://localhost:3000` without logging in. Admin login only needed to edit dashboards. Dev defaults insecure; v2 hardens.

### 7.2 Auto-provisioning

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

Both dashboards are committed JSON files in `data-plane/grafana/dashboards/`. Grafana auto-loads them at startup. UI edits get persisted to disk via the volume mount, but the canonical version is the file checked into the repo.

### 7.3 Dashboard 1: "Pipeline overview"

File: `data-plane/grafana/dashboards/pipeline-overview.json`.

4 rows × 6 panels (one column per Python service, ordered by pipeline position: correlator → anomaly → policy → orchestrator → auth-backend → reporting):

| Row | Panel type | PromQL | Purpose |
|---|---|---|---|
| 1 | Stat (single value, color-coded green/red) | `up{job="intellifim-<name>"}` | Service-up indicator per service |
| 2 | Time-series (line) | `rate(intellifim_messages_processed_total{service="<name>"}[1m])` | Throughput per service (msg/sec) |
| 3 | Time-series (line) | `rate(intellifim_errors_total{service="<name>"}[5m])` | Error rate per service (errors/sec, 5-min rate) |
| 4 | Time-series (heatmap) | `histogram_quantile(0.95, sum(rate(intellifim_processing_seconds_bucket{service="<name>"}[5m])) by (le))` | p95 processing latency per service |

Time range: last 1 hour. Refresh: 10s.

### 7.4 Dashboard 2: "Threat & response health"

File: `data-plane/grafana/dashboards/threat-and-response.json`.

| Panel | PromQL | Purpose |
|---|---|---|
| Reporting threat-score ingest rate | `rate(intellifim_messages_processed_total{service="reporting"}[1m])` | Rate at which reporting is consuming `threat.scores` |
| Policy-engine threat-score publish rate | `rate(intellifim_messages_processed_total{service="policy-engine"}[1m])` | Upstream rate; pair with above to spot consumer lag visually |
| Approval API call rate (stacked by handler) | `sum(rate(http_requests_total{job="intellifim-orchestrator", handler=~"/approvals.*"}[1m])) by (handler)` | How busy the approval flow is |
| Approval API 5xx error rate | `sum(rate(http_requests_total{job="intellifim-orchestrator", handler=~"/approvals.*", status=~"5.."}[1m])) by (status)` | 5xx errors on the approval endpoints |
| Approval API p95 latency | `histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{job="intellifim-orchestrator", handler=~"/approvals.*"}[5m])) by (le))` | How slow approvals are getting |
| Auth login rate (stacked by status) | `sum(rate(http_requests_total{job="intellifim-auth-backend", handler="/auth/login"}[1m])) by (status)` | Login successes/failures over time |
| Report generation success rate | `sum(rate(http_requests_total{job="intellifim-reporting", handler="/reports/generate", status="201"}[5m]))` | PDF reports created per 5min |
| Reporting service errors | `rate(intellifim_errors_total{service="reporting"}[5m])` | Reporting-side errors (e.g. orchestrator unreachable during generate) |

Time range: last 6 hours. Refresh: 30s.

### 7.5 No new env vars in `.env.dataplane`

Grafana admin credentials are hardcoded `admin/admin` for dev. v2 will pull from `.env.dataplane` + Vault.

## 8. HTTP Surface (summary)

| URL | What | Auth |
|---|---|---|
| `http://localhost:9090` | Prometheus UI + `/api/v1/query` etc. | None (dev) |
| `http://localhost:9090/-/healthy` | Prometheus health | None |
| `http://localhost:3000` | Grafana UI (dashboards) | Anonymous viewer; admin/admin for edit |
| `http://localhost:3000/api/health` | Grafana health | None |
| `http://localhost:9093` | Alertmanager UI (firing alerts) | None (dev) |
| `http://localhost:9093/-/healthy` | Alertmanager health | None |
| `http://localhost:8000/metrics` | auth-backend metrics | None — Prometheus scrapes via the bus network |
| `http://localhost:8200/metrics` | orchestrator metrics | None — bypasses the JWT middleware since `/metrics` isn't a `/approvals*` route |
| `http://localhost:8300/metrics` | reporting metrics | None — same: not under the JWT-required route gate |
| `http://localhost:9100/metrics` | correlation-engine metrics | None |
| `http://localhost:9101/metrics` | anomaly-detector metrics | None |
| `http://localhost:9102/metrics` | policy-engine metrics | None |

Important: the orchestrator's existing JWT middleware ONLY gates `/approvals/{id}/{approve,reject}` routes (per the existing aiohttp `_is_decide_route` filter). The new `/metrics` route is OUTSIDE that filter, so Prometheus can scrape without a token. The reporting service's FastAPI app has the JWT dependency wired per-route via `Depends(get_current_principal)`, NOT globally — so the new `/metrics` route is also unauthenticated. Auth-backend's `/metrics` is similarly outside the protected routes. This is intentional for v1: Prometheus scraping inside the Compose network does not need a token. v2 will add bearer-token-protected `/metrics` scraping when TLS+mTLS lands.

## 9. Storage

3 new named volumes:
- `prometheus_data` — TSDB; 7-day retention; expected size <500 MB for v1
- `grafana_data` — Grafana state (user prefs, panel edits, etc.); <50 MB
- `alertmanager_data` — silence/dedup state across restarts; <10 MB

No new SQLite, no new schemas, no schema-package bump.

## 10. Service Composition

### 10.1 New service blocks
3 blocks (prometheus, alertmanager, grafana) added to `data-plane/docker-compose.yml`. See §5.1, §6.1, §7.1 for the exact YAML.

### 10.2 Modified service blocks
6 existing service blocks gain:
- The 3 engines (correlator, anomaly, policy): add `METRICS_PORT` env var + `ports:` entry for 9100/9101/9102.
- The 3 HTTP services (auth-backend, orchestrator, reporting): no compose changes — `/metrics` is on the existing port.

### 10.3 Stack count
24 → **27 services** in normal `up -d`. Simulator (`profiles: [sim]`) stays excluded.

### 10.4 No schema-package bump
intellifim-schemas stays at 0.4.x. Observability is consumer-only of its own metrics.

## 11. Repo Layout

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
├── docker-compose.yml                       (MODIFIED; +3 services, +3 volumes, +6 services modified per §10.2)

# Existing service packages gain a metrics module + 2 tests each:
data-plane/auth_backend/src/auth_backend/metrics.py          (NEW)
data-plane/auth_backend/tests/test_metrics.py                (NEW; 2 tests)

data-plane/orchestrator/src/orchestrator/metrics.py          (NEW)
data-plane/orchestrator/tests/test_metrics.py                (NEW; 2 tests)

data-plane/reporting/src/reporting/metrics.py                (NEW)
data-plane/reporting/tests/test_metrics.py                   (NEW; 2 tests)

data-plane/correlator/src/correlator/metrics.py              (NEW)
data-plane/correlator/tests/test_metrics.py                  (NEW; 2 tests)

data-plane/anomaly/src/anomaly/metrics.py                    (NEW)
data-plane/anomaly/tests/test_metrics.py                     (NEW; 2 tests)

data-plane/policy/src/policy/metrics.py                      (NEW)
data-plane/policy/tests/test_metrics.py                      (NEW; 2 tests)

# Existing files modified:
data-plane/auth_backend/src/auth_backend/api.py              (+Instrumentator + handler wrap)
data-plane/auth_backend/pyproject.toml                       (+prometheus-fastapi-instrumentator, +prometheus-client)
data-plane/orchestrator/src/orchestrator/api.py              (+/metrics route + handler wrap)
data-plane/orchestrator/src/orchestrator/engine.py           (+wrap process_one)
data-plane/orchestrator/pyproject.toml                       (+prometheus-client)
data-plane/reporting/src/reporting/api.py                    (+Instrumentator + generate wrap)
data-plane/reporting/src/reporting/consumer.py               (+wrap process_one)
data-plane/reporting/pyproject.toml                          (+prometheus-fastapi-instrumentator, +prometheus-client)
data-plane/correlator/src/correlator/__main__.py             (+start_http_server)
data-plane/correlator/src/correlator/engine.py               (+wrap process_one)
data-plane/correlator/pyproject.toml                         (+prometheus-client)
data-plane/anomaly/src/anomaly/__main__.py                   (+start_http_server)
data-plane/anomaly/src/anomaly/engine.py                     (+wrap process_one)
data-plane/anomaly/pyproject.toml                            (+prometheus-client)
data-plane/policy/src/policy/__main__.py                     (+start_http_server)
data-plane/policy/src/policy/engine.py                       (+wrap process_one)
data-plane/policy/pyproject.toml                             (+prometheus-client)
data-plane/README.md                                         (+observability section)
```

### Branch
`feat/observability-v1` off main.

## 12. Testing

### 12.1 Unit tests (~12 new; total moves from 261 → ~273 Python + 5 Rego = 278 total)

| File | Count | Coverage |
|---|---|---|
| `data-plane/auth_backend/tests/test_metrics.py` | 2 | (a) `GET /metrics` returns 200 with correct content-type, body contains `http_requests_total`; (b) after a login attempt, `intellifim_messages_processed_total{service="auth-backend"}` increments by 1. |
| `data-plane/orchestrator/tests/test_metrics.py` | 2 | (a) `GET /metrics` returns 200, body contains `intellifim_messages_processed_total`; (b) after a successful `POST /approvals/{id}/approve`, the counter increments by 1. |
| `data-plane/reporting/tests/test_metrics.py` | 2 | (a) `GET /metrics` returns 200; (b) after `POST /reports/generate` (with respx-mocked orchestrator), the messages counter for `service="reporting"` increments. |
| `data-plane/correlator/tests/test_metrics.py` | 2 | (a) `messages_processed_total` increments after `engine.process_one(event)` happy-path; (b) `errors_total{kind="ValueError"}` increments after a `process_one` call that raises ValueError. |
| `data-plane/anomaly/tests/test_metrics.py` | 2 | Same shape — increments under happy/error paths. |
| `data-plane/policy/tests/test_metrics.py` | 2 | Same shape — increments under happy/error paths. |

### 12.2 Test patterns
- `from prometheus_client import REGISTRY` + `REGISTRY.get_sample_value("intellifim_messages_processed_total", {"service": "<name>"})` to read counter values directly.
- For test isolation, each test asserts a DELTA (read value before, perform action, read after, assert `after - before == expected`) — avoids cross-test counter accumulation.
- HTTP `/metrics` tests use the existing `TestClient` / `aiohttp.test_utils.TestServer` fixtures already in each service's `conftest.py`.
- The 3 engine tests bypass `start_http_server` and directly call `engine.process_one(...)` — the actual HTTP server is integration-tested at DoD time via `curl <host>:<port>/metrics`.

### 12.3 No new tests for config files
The `prometheus.yml`, `alerts.yml`, `alertmanager.yml`, and Grafana JSON files are validated at DoD time:
- `docker exec prometheus promtool check config /etc/prometheus/prometheus.yml` (config validity)
- `docker exec prometheus promtool check rules /etc/prometheus/alerts.yml` (rule syntax)
- Grafana's auto-loader fails loudly at startup if JSON is malformed (and the `check-observability.sh` script verifies dashboards loaded).

### 12.4 Definition of Done (10 items)

1. **`pytest` green** — all 12 new tests pass + full suite stays green: ~273 Python + 5 Rego = 278 total.
2. **`docker compose up -d`** on a fresh checkout brings up exactly **27 services** healthy within 60s (simulator stays hidden behind `profiles: [sim]`).
3. **Prometheus healthy** — `curl http://127.0.0.1:9090/-/healthy` returns 200.
4. **All 6 scrape targets UP** — `curl -s 'http://127.0.0.1:9090/api/v1/query?query=up{job=~"intellifim-.%2B"}'` returns 6 results, each with `.value[1] == "1"`. Verifies `prometheus.yml` + every service's `/metrics` endpoint.
5. **Grafana healthy + datasource + dashboards loaded** — `curl http://127.0.0.1:3000/api/health` returns 200; opening `http://127.0.0.1:3000` (anonymous viewer) and navigating to the "IntelliFIM" folder shows both dashboards; both render with live data when the stack has been processing traffic for a minute.
6. **Alertmanager healthy** — `curl http://127.0.0.1:9093/-/healthy` returns 200.
7. **End-to-end metrics signal** — run `./scripts/run-scenario.sh data-exfil` (sub-project #8 smoke); within 2 minutes, the "Pipeline overview" dashboard shows non-zero `messages_processed_total` rates on every service.
8. **End-to-end alert firing** — `docker compose stop policy-engine`; within 3 minutes, the `IntelliFIMServiceDown` alert appears in the Alertmanager UI at `http://127.0.0.1:9093`. `docker compose start policy-engine`; alert resolves within ~30 seconds.
9. **Config validation** — `docker exec prometheus promtool check config /etc/prometheus/prometheus.yml` returns success; `docker exec prometheus promtool check rules /etc/prometheus/alerts.yml` returns success.
10. **No breakage of prior DoD** — `./scripts/run-all-scenarios.sh` (sub-project #8) still passes 5/5; reporting still generates PDFs; admin-console still works.

### 12.5 Smoke verification script

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

Exit 0 = all systems healthy; non-zero = some component broken with reason printed.

## 13. Known v2/v3 Follow-ups

Carried forward from v1's deliberate scope reductions. These will appear in a "From #9" block in the roadmap memory after merge.

- **Loki** (centralized logs) + Promtail (log shipper)
- **Jaeger + OpenTelemetry SDK** in every service (distributed traces)
- **Blackbox exporter** (external uptime probes — currently only "scrape success" is the up signal)
- **kafka-exporter / Burrow** (Kafka JMX → Prometheus; per-topic/partition consumer lag)
- **Wazuh Indexer metrics** (depends on adding the Wazuh Indexer service first — v2)
- **Slack / PagerDuty / email / webhook** in Alertmanager (operator notification stack)
- **More alert rules:** HighErrorRate, KafkaConsumerLag, ApprovalQueueDepth, ReportGenerationFailure, AnomalyDetectorScoreDrift
- **Helm chart scaffolding** — explicitly deferred per scope decision (v2 cross-cutting pass)
- **Terraform / ArgoCD / Harbor / Linkerd** — full IaC + service-mesh (v3)
- **Grafana auth hardening** (replace `admin/admin`; OIDC integration — pairs with auth-backend v2 OIDC)
- **Grafana anonymous viewer access** — currently always-on; v2 toggles off for prod
- **Per-host or per-tenant dashboard variants** (depends on multi-host — v3)
- **Aggregated SLI/SLO dashboards** (couples with master spec compliance reporting v2)
- **Recording rules** (precompute common queries to reduce dashboard load)
- **Prometheus federation + HA** (v3 production)
- **Long-term metrics storage** (Thanos / Cortex / Mimir — v2)
- **Dashboard-as-code** (jsonnet / grafonnet) — currently raw JSON
- **Bearer-token-protected `/metrics` scraping** with TLS+mTLS (v2 hardening)
- **aiohttp HTTP RED auto-instrumentation** for orchestrator (currently manual counters only)

## 14. References

- Master tech-stack design: `docs/superpowers/specs/2026-05-04-intellifim-tech-stack-design.md` (§4.12 IaC, §4.13 Observability)
- Sub-project #1: data plane — `docs/superpowers/specs/2026-05-04-data-plane-v1-design.md` (Compose stack layout, `bus` network)
- Sub-project #4: policy engine (publishes `threat.scores` — the topic reporting tails) — `docs/superpowers/specs/2026-05-18-policy-engine-v1-design.md`
- Sub-project #5: response orchestrator (provides `/approvals` API — instrumented here) — `docs/superpowers/specs/2026-05-19-response-orchestrator-v1-design.md`
- Sub-project #6: admin console + auth-backend (JWT contract — `/metrics` is outside the gated routes) — `docs/superpowers/specs/2026-05-20-admin-console-v1-design.md`
- Sub-project #7: reporting (sibling consumer of `threat.scores` — instrumented here) — `docs/superpowers/specs/2026-05-20-reporting-v1-design.md`
- Sub-project #8: simulation lab (smoke for end-to-end metrics signal at DoD #7) — `docs/superpowers/specs/2026-05-22-simulation-lab-v1-design.md`
- Roadmap memory (canonical sub-project status): `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/project_intellifim_roadmap.md`
