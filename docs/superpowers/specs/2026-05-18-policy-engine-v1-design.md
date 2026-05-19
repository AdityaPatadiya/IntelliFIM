# IntelliFIM Policy & Scoring v1 — Design

> Sub-project #4 of 9 in the IntelliFIM v1 walking-skeleton sequence. Consumes `events.scored` (from sub-project #3 ML platform) and publishes `threat.scores` (NEW topic) for downstream sub-project #5 (response orchestrator) and #6 (admin console).

## 1. Purpose

Add a minimal policy + dynamic-threat-score layer to the data-plane stack: a single Python service that consumes every `ScoredEvent`, queries an OPA sidecar for a per-event `score_delta`, maintains a per-host sliding-window threat score in Redis, and publishes a `ThreatScoreUpdate` to a new Kafka topic `threat.scores`. This closes the policy loop end-to-end and unblocks sub-project #5 (response orchestrator needs a threat-score stream to decide tiered actions) and #6 (admin console displays per-host scores).

## 2. Scope: walking skeleton only

The master tech-stack spec (`2026-05-04-intellifim-tech-stack-design.md` §4.5) lists a larger policy stack: OPA + Rego + Sigma rules + MISP threat-intel enrichment + Redis hot state + full `role × device × location × time` context. **v1 ships only the minimum that proves the loop closes.** Following the breadth-first philosophy proven in sub-projects #1, #2, and #3, every additional integration is explicitly deferred to v2 (see §13).

**v1 ships:**
- One Rego policy file mapping `(anomaly_score, is_anomaly) → {score_delta, reason}`.
- One standalone OPA container queried via REST.
- One single-node Redis container holding per-host sliding-window sorted sets.
- One Python `policy-engine` service consuming `events.scored`, querying OPA, updating Redis, publishing to `threat.scores`.
- One new Pydantic schema `ThreatScoreUpdate` (intellifim-schemas 0.3.0 → 0.4.0).
- Unit tests for the Python service + Rego policy + a Docker integration smoke test.

## 3. Out of scope (explicitly deferred)

- **Sigma rules engine** (rule-based pattern detection alongside OPA).
- **MISP threat-intel enrichment** (IOC joins).
- **Tiered response decisions** (Tier 1/2/3 actions) — that's sub-project #5's job; the policy engine publishes a numeric score and lets #5 decide tiers.
- **Keycloak + RBAC + user/device/location context** — v1 has only `host_id`.
- **OPA bundle service + live reload (`--watch`)** — v1 mounts policies as a read-only volume; edits require `docker compose restart opa`.
- **Redis persistence (AOF/RDB) + Redis Cluster** — v1 is ephemeral, single-node.
- **Postgres audit log of policy decisions** — v1 emits to Kafka only.
- **Decay-only updates** — v1 only emits when a new `ScoredEvent` arrives (no background timer).
- **Tier suggestions** in `ThreatScoreUpdate` — added once #5's contract is concrete.
- **Per-user scoring + `(host, user)` composite keys** — v1 keys are `host` only.
- **A/B policy deployment / canary** — v1 has one policy version.

## 4. Architecture overview

```
events.scored (existing, 6 partitions — from sub-project #3)
       │
       ▼
┌──────────────────┐         ┌─────────────────┐
│  policy-engine   │ ──HTTP──►   opa           │  (Rego policies mounted as volume)
│ (Python service) │ ◄──────── /v1/data/...    │
│                  │         └─────────────────┘
│  • read scored   │
│  • query OPA     │         ┌─────────────────┐
│  • update Redis  │ ─ZADD─► │   redis         │  (sorted set per host:
│  • emit update   │ ◄──────── threat_score:host:001)
└──────────────────┘         └─────────────────┘
       │
       ▼
threat.scores (NEW, 6 partitions, 14d retention)
       │
       └──► consumed by sub-project #5 (response orchestrator) + #6 (dashboard)
```

- Single consumer group `policy-engine` reads from `events.scored` in parallel with no other consumers (correlator reads `events.normalized`, anomaly-detector reads `events.normalized`).
- Stack grows from 17 → **20 services** (+ `opa`, `redis`, `policy-engine`).
- No state shared with other consumers; no coupling beyond the published `threat.scores` topic.

### New artifacts

| Path | Purpose |
|---|---|
| `data-plane/policy/` (NEW package) | Python package `intellifim-policy` — `config.py`, `opa_client.py`, `redis_store.py`, `engine.py`, `__main__.py` |
| `data-plane/policy/policies/threat_score.rego` (NEW) | The single Rego policy mapping ScoredEvent → score_delta + reason |
| `data-plane/policy/policies/threat_score_test.rego` (NEW) | Rego unit tests, run via `opa test` |
| `data-plane/policy/Dockerfile` | Python service image |
| `data-plane/policy/README.md` | Package usage notes |
| `data-plane/schemas/src/intellifim_schemas/policy.py` (NEW) | `ThreatScoreUpdate` Pydantic model; intellifim-schemas bumps 0.3.0 → 0.4.0 |
| `data-plane/scripts/tail-scores.py` (NEW) | Host-side consumer of `threat.scores` |
| `data-plane/docker-compose.yml` | + `opa`, `redis`, `policy-engine` service blocks |
| `data-plane/scripts/create-topics.sh` | + `threat.scores` topic |

## 5. `threat.scores` Kafka topic + Redis data model

### Kafka topic

- Name: `threat.scores`
- Partitions: **6** (consistent with `events.normalized`, `events.correlated`, `events.scored`).
- Retention: **14 days**.
- Key: `host_id` bytes (preserves partition affinity across topics).
- Replication factor: 1 (single-broker v1).

### Redis sorted set per host

| Key | Type | Score (zset's notion) | Member |
|---|---|---|---|
| `threat_score:host:<host_id>` | sorted set | unix timestamp (float) | `{"delta": <int>, "event_id": "<uuid>"}` JSON |

**Cleanup is opportunistic** on every write: `ZREMRANGEBYSCORE key -inf (now - window_seconds)`. Contributions naturally age out without a background reaper.

**No persistence in v1**: Redis runs with `--save "" --appendonly no`. Scores are ephemeral; a Redis restart wipes them and they rebuild from new traffic.

## 6. `ThreatScoreUpdate` schema

```python
from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, NonNegativeInt, PositiveInt


class ThreatScoreUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    update_id: UUID
    computed_at: AwareDatetime
    host_id: str                                                     # Kafka partition key

    score: Annotated[float, Field(ge=0.0, le=100.0)]                 # current sliding-window sum, clamped
    window_seconds: PositiveInt                                       # window over which `score` was computed
    contributions_in_window: NonNegativeInt                          # count of score_delta entries summed

    last_event_id: UUID                                               # the source CanonicalEvent id (from ScoredEvent.source_event)
    last_score_delta: Annotated[int, Field(ge=0, le=100)]            # OPA's decision for THIS event
    last_reason: str                                                  # OPA's reason string for THIS event
```

**Emit policy for v1:** emit a `ThreatScoreUpdate` for **every** consumed `ScoredEvent`, regardless of whether `score_delta` is zero or whether the score actually changed. Simplest correct behavior; downstream consumers can dedupe. v2 may tighten to "emit on threshold crossing" once #5's contract is concrete.

## 7. Rego policy (`data-plane/policy/policies/threat_score.rego`)

```rego
package intellifim.policy

# Default: benign event
default decision := {"score_delta": 0, "reason": "benign event"}

# Strong anomaly
decision := {"score_delta": 25, "reason": "strong anomaly (score >= 0.7)"} if {
    input.event.anomaly_score >= 0.7
}

# Moderate anomaly (is_anomaly true AND in [0.5, 0.7))
decision := {"score_delta": 10, "reason": "moderate anomaly"} if {
    input.event.is_anomaly == true
    input.event.anomaly_score >= 0.5
    input.event.anomaly_score < 0.7
}

# Weak anomaly (score in [0.3, 0.5), regardless of is_anomaly flag)
decision := {"score_delta": 5, "reason": "weak anomaly (score 0.3-0.5)"} if {
    input.event.anomaly_score >= 0.3
    input.event.anomaly_score < 0.5
}
```

**Query endpoint:** `POST http://opa:8181/v1/data/intellifim/policy/decision` with body `{"input": {"event": <ScoredEvent as dict>}}`.
**Response:** `{"result": {"score_delta": <int>, "reason": "..."}}`.

The score-delta ladder (0, 5, 10, 25) is intentionally coarse-grained for v1 demo clarity. v2 can refine to a smooth function via Rego's arithmetic (`score_delta := round(input.event.anomaly_score * 30)`) once we have empirical data on what scores actually look like in production.

## 8. PolicyEngine, clients, config, lifecycle

### `PolicyEngine` (mirrors `AnomalyEngine` from sub-project #3)

```python
class PolicyEngine:
    """Consume ScoredEvents, query OPA, append to Redis, publish ThreatScoreUpdates.

    Offset-commit policy: same as data-plane normalizers + correlator + anomaly —
    no manual commit; expects the consumer to have enable_auto_commit=True
    (aiokafka default). Combined with the log-and-skip error policy in
    _safe_publish + _extract_event, no single bad message or transient
    publish/OPA/Redis failure can stall a partition.
    """

    def __init__(
        self,
        *,
        consumer: _Consumer,
        producer: _Producer,
        output_topic: str,
        opa: OpaClient,
        store: RedisScoreStore,
        window_seconds: int,
        now: Callable[[], datetime] = _default_now,
    ) -> None: ...

    async def run(self) -> None:
        async for raw_message in self._consumer:
            event = self._extract_event(raw_message)        # dual-mode (ScoredEvent | .value bytes)
            if event is None:
                continue
            update = await self._process(event)
            if update is None:                              # OPA or Redis failed
                continue
            await self._safe_publish(update)
```

Patterns reused verbatim from #2 and #3:
- Dual-mode `_extract_event` (accepts `ScoredEvent` instance OR `.value` bytes).
- `_safe_publish` wraps `Exception` with `# noqa: BLE001`, logs and skips.
- `now: Callable[[], datetime]` injection for deterministic tests.

### `OpaClient` (thin httpx wrapper)

Thin async wrapper around `POST /v1/data/intellifim/policy/decision`. `query(event) -> dict | None`. Returns `None` and logs a warning on transport errors, timeouts, malformed responses, 4xx, or 5xx. Uses `httpx.AsyncClient`; closed via `aclose()` in the entry point's nested `try/finally`.

### `RedisScoreStore` (thin redis-py 5.x async wrapper)

Two methods:
- `append_contribution(host_id, ts, delta, event_id) -> bool` — `ZADD` and opportunistic `ZREMRANGEBYSCORE`. Returns `False` on Redis error.
- `current_score(host_id, window_seconds, now) -> tuple[float, int]` — `ZRANGEBYSCORE` survivors + sum deltas + count. Returns `(0.0, 0)` on Redis error.

Closed via `aclose()` in the entry point's nested `try/finally`.

### `PolicyConfig`

Frozen dataclass; `from_env()` reads:

| Env var | Default | Notes |
|---|---|---|
| `KAFKA_BOOTSTRAP` | `kafka:9092` | Same as data-plane convention |
| `CONSUMER_GROUP` | `policy-engine` | Matches container name |
| `OPA_URL` | `http://opa:8181` | OPA REST endpoint |
| `REDIS_URL` | `redis://redis:6379/0` | redis-py URL |
| `THREAT_SCORE_WINDOW_SECONDS` | `300` | Must be > 0; rejected otherwise |

Module-level constants: `INPUT_TOPIC = "events.scored"`, `OUTPUT_TOPIC = "threat.scores"`.

### Entry point `__main__.py`

Same nested try/finally pattern as siblings, extended for OPA + Redis client cleanup:

```python
await consumer.start()
try:
    await producer.start()
    try:
        opa = OpaClient(cfg.opa_url)
        store = RedisScoreStore(cfg.redis_url)
        try:
            engine = PolicyEngine(...)
            await engine.run()
        finally:
            await store.aclose()
            await opa.aclose()
    finally:
        await producer.stop()
finally:
    await consumer.stop()
```

Plus `try/except KeyboardInterrupt` around `asyncio.run(_run())` for clean Ctrl-C.

### Error handling matrix

| Failure mode | Behavior |
|---|---|
| Malformed `ScoredEvent` JSON | Log warning, skip (dual-mode `_extract_event`) |
| Message has no `.value` | Log warning, skip |
| OPA unreachable / timeout / 4xx / 5xx / malformed response | Log warning, skip event — do NOT add 0-delta to Redis |
| Redis unreachable on append | Log warning, skip both Redis write AND publish |
| Redis unreachable on read | Log warning, skip publish (no current_score) |
| `producer.send_and_wait` raises | Log warning, skip publish — loop continues |
| `PolicyConfig.from_env()` invalid value | Fail-fast at startup |

### Compose service blocks

```yaml
  opa:
    image: openpolicyagent/opa:latest
    container_name: opa
    networks: [bus]
    command: ["run", "--server", "--addr=:8181", "/policies"]
    volumes:
      - ./policy/policies:/policies:ro
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8181/health"]
      interval: 5s
      timeout: 2s
      retries: 6

  redis:
    image: redis:7-alpine
    container_name: redis
    networks: [bus]
    command: ["redis-server", "--save", "", "--appendonly", "no"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 2s
      retries: 6

  policy-engine:
    image: intellifim-policy:dev
    container_name: policy-engine
    networks: [bus]
    depends_on:
      kafka:
        condition: service_healthy
      opa:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      KAFKA_BOOTSTRAP: "kafka:9092"
      CONSUMER_GROUP: "policy-engine"
      OPA_URL: "http://opa:8181"
      REDIS_URL: "redis://redis:6379/0"
      THREAT_SCORE_WINDOW_SECONDS: "300"
```

## 9. Test strategy

TDD throughout. `FakeConsumer` / `FakeProducer` shapes carry over from #2 and #3. Two new test-only dependencies: `fakeredis` (in-process Redis emulation) and `respx` (httpx mocking).

### Unit test inventory (~29 new Python tests + ~5 Rego tests)

| File | Coverage | Tests |
|---|---|---|
| `data-plane/schemas/tests/test_policy.py` (NEW) | `ThreatScoreUpdate` round-trip; `extra="forbid"`; `score`/`last_score_delta` bounds `[0,100]`; `window_seconds` positive; naive-datetime rejection; valid UUID round-trip | 6 |
| `data-plane/policy/tests/test_config.py` (NEW) | Env defaults; env overrides; `THREAT_SCORE_WINDOW_SECONDS <= 0` rejection; `OPA_URL`/`REDIS_URL` parsing; `INPUT_TOPIC`/`OUTPUT_TOPIC` constants | 5 |
| `data-plane/policy/tests/test_opa_client.py` (NEW) | Happy path; OPA returns malformed JSON → None; OPA timeout → None; OPA 4xx → None; OPA 5xx → None. Uses `respx`. | 5 |
| `data-plane/policy/tests/test_redis_store.py` (NEW) | `append_contribution` round-trip; `current_score` sums in-window deltas; `current_score` after window expiry; multi-host isolation; Redis-error returns `(0.0, 0)`; multiple contributions same host. Uses `fakeredis`. | 6 |
| `data-plane/policy/tests/test_engine.py` (NEW) | Happy-path emit; OPA failure → skip; Redis-append failure → skip; malformed JSON skip; producer-failure (FlakyProducer) continues loop; accepts both `ScoredEvent` instance AND `.value` bytes (dual-mode) | 7 |

**Total: 6 + 5 + 5 + 6 + 7 = 29 new Python tests.**

Combined with existing test suites: **~137 Python tests** across schemas (32), normalizers (38), correlator (20), anomaly (24), policy (23). Run as four pytest invocations due to the conftest collision documented in README.

### Rego policy tests (`opa test`)

```rego
# data-plane/policy/policies/threat_score_test.rego
package intellifim.policy

test_benign_event_returns_zero { ... }
test_weak_anomaly_returns_five { ... }
test_moderate_anomaly_returns_ten { ... }
test_strong_anomaly_returns_twenty_five { ... }
test_high_score_with_is_anomaly_false_still_strong { ... }
```

Run via `opa test data-plane/policy/policies/` (host) or `docker run --rm -v $(pwd)/data-plane/policy/policies:/p openpolicyagent/opa:latest test /p`.

**5 new Rego tests** — separate test surface from pytest. README documents both invocations.

### Integration smoke (DoD verification, not pytest)

```bash
docker compose --env-file .env.dataplane down -v
docker rmi intellifim-{normalizer,correlator,anomaly-detector,policy}:dev
docker build -f normalizers/Dockerfile -t intellifim-normalizer:dev .
docker build -f correlator/Dockerfile  -t intellifim-correlator:dev .
docker build -f anomaly/Dockerfile     -t intellifim-anomaly-detector:dev .
docker build -f policy/Dockerfile      -t intellifim-policy:dev .
docker compose up -d
./scripts/create-topics.sh && sleep 120

./scripts/seed-test-traffic.sh
sleep 60

# Verify ≥1 ThreatScoreUpdate on threat.scores
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic threat.scores \
    --from-beginning --max-messages 10 --timeout-ms 30000 \
    | grep -c '"score":'

# Verify Redis has the host-001 zset
docker exec redis redis-cli ZCARD "threat_score:host:001"
```

## 10. Definition of Done

1. **Image builds:** `docker build -f policy/Dockerfile -t intellifim-policy:dev .` succeeds.
2. **Stack runs:** `docker compose up -d` brings all **20** services to `Up`. `opa`, `redis`, `kafka`, `wazuh-manager` show `(healthy)`.
3. **Topic exists:** `create-topics.sh` creates `threat.scores` (6 partitions, 14d retention) idempotently.
4. **Consumer joins:** `policy-engine` container logs show joining the `policy-engine` consumer group and being assigned 6 partitions on `events.scored`.
5. **Score updates land end-to-end:** after `./scripts/seed-test-traffic.sh`, at least one valid `ThreatScoreUpdate` appears on `threat.scores`.
6. **Schema invariants hold on the wire:** every emitted `ThreatScoreUpdate` has `score ∈ [0,100]`, valid UUIDs, AwareDatetime, `last_score_delta ∈ [0,100]`, `window_seconds > 0`.
7. **Redis state matches reality:** `redis-cli ZCARD threat_score:host:001` returns a positive integer after a seed run.
8. **Tests green:** 4 pytest passes (~137 total: 32 schemas + 38 normalizers + 20 correlator + 24 anomaly + 23 policy) AND `opa test data-plane/policy/policies/` green (~5 Rego tests). **Combined ~142 tests.**

## 11. Patterns continued from sub-projects #1, #2, #3

This sub-project inherits and reinforces (no deviation):

- Tight Pydantic schemas: `extra="forbid"`, `AwareDatetime`, `Field(ge=, le=)` bounds, `PositiveInt`, `NonNegativeInt`.
- Single Docker image per Python service-family.
- Cross-package dep pins as RANGES, never `==X.Y.Z`. The new `intellifim-policy` pyproject pins `intellifim-schemas>=0.4,<1.0`. The schemas package bumps 0.3.0 → 0.4.0. All other consumer packages (normalizers `>=0.2,<1.0`, correlator `>=0.2,<1.0`, anomaly `>=0.3,<1.0`) continue to satisfy.
- Dual-mode `_extract_event(message)`: accepts `ScoredEvent` instance (test fast-path) OR object with `.value` bytes (production aiokafka path).
- `now: Callable[[], datetime]` injection for deterministic tests on stateful components.
- `_safe_publish` log-and-skip with `# noqa: BLE001` — Kafka outages do not crash the loop.
- Nested try/finally lifecycle in `__main__.py` — extended here for OPA + Redis client cleanup.
- Two-reviewer-per-task workflow: spec compliance reviewer FIRST, then code-quality reviewer; re-review on findings until both approve.
- Plan files are immutable contracts during execution; if a reviewer finds an architectural gap mid-execution, update the plan + re-dispatch (expect at least one "Task N.5" addition).

## 12. New patterns this sub-project introduces

- **External infra dependencies** (OPA, Redis) wired via `depends_on.<svc>.condition: service_healthy` in Compose — both infra containers have `healthcheck:` blocks.
- **Two test-only Python dependencies** (`fakeredis`, `respx`) so unit tests don't require live Redis or OPA. Both async-compatible, well-maintained.
- **Rego as a second test surface** — `opa test` is the canonical way to test Rego policies; sits alongside pytest in the README's "Running the unit tests" section.

## 13. Deferred to v2

Tracked here so they don't get lost when v2 hardening begins:

**Policy & scoring tooling:**
- Sigma rules engine (rule-based pattern detection alongside OPA).
- MISP threat-intel enrichment (IOC joins on src/dst IPs).
- OPA bundle service + signed policy distribution.
- OPA live reload (`--watch` flag) — currently a `docker compose restart opa` is required after a policy edit.
- Postgres audit log of every policy decision.

**Scoring semantics:**
- Tier suggestions (`tier_hint` field) in `ThreatScoreUpdate`. Defer until #5's contract is concrete.
- Threshold-crossing emit policy (vs. emit on every event). Defer until #5's contract is concrete.
- Decay-only updates — background timer publishing "score decayed" events between incoming `ScoredEvent`s.
- Per-user scoring + composite `(host, user)` keys.
- Full `role × device × location × time` context from master spec §4.5 — depends on Keycloak (auth, v2) + asset inventory (v2).

**Operations:**
- Redis persistence (AOF/RDB) + Redis Cluster.
- OPA decision logs to a sink (file, OTLP, or a dedicated Kafka topic).
- Score-distribution drift detection / alerting.
- A/B policy deployment / canary.
- Healthcheck + resource limits on `policy-engine` itself (consistent with the project-wide v2 hardening pass).

**Alternative scoring shapes (rejected scope options):**
- Consuming both `events.scored` AND `events.correlated` (option B).
- Full v1 per master spec including Sigma + MISP + tiered response (option C).

## 14. Where things live

- New package root: `data-plane/policy/`
- New schema module: `data-plane/schemas/src/intellifim_schemas/policy.py`
- New scripts: `data-plane/scripts/tail-scores.py`
- Rego policies: `data-plane/policy/policies/`
- New services in compose: `opa`, `redis`, `policy-engine`
- New Kafka topic: `threat.scores`
