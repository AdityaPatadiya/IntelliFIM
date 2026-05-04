# IntelliFIM Correlation Engine — v1 Design (Walking Skeleton)

**Date:** 2026-05-04
**Status:** Approved
**Sub-project of:** [IntelliFIM Technology Stack Design](2026-05-04-intellifim-tech-stack-design.md)
**Builds on:** [Data Plane v1 Design](2026-05-04-data-plane-v1-design.md)
**Scope:** v1 only. v2 (Flink, rule-based patterns) and v3 (statistical baselines, HA) are explicit follow-ups.

---

## 1. Purpose

Join file-integrity events with network events from the same host within a configurable time window (default ±60s) and publish each match as a `CorrelatedEvent` on a new Kafka topic `events.correlated`.

This is the smallest meaningful win that proves file ↔ network correlation works end-to-end. It exercises the full plumbing (consume from `events.normalized`, do stateful work over a time window, emit to a new canonical topic) and unblocks downstream sub-projects (scoring, response orchestrator, dashboard).

**Novel contribution from the project abstract this delivers:** "the system correlates file-level events with network behavior".

## 2. v1 Scope

**In scope:**
- Single-instance Python service consuming `events.normalized`
- Per-host in-memory rolling buffer (drops events older than the window)
- Bidirectional file ↔ network matching: every new file event searches the buffer for network events from the same host, and vice versa
- New canonical schema `CorrelatedEvent` added to `intellifim-schemas` (package version 0.1.0 → 0.2.0)
- New Kafka topic `events.correlated`
- One new Compose service `correlation-engine`
- Companion `tail-correlated.py` consumer script

**Explicit non-goals (deferred):**
- Apache Flink (→ v2 when horizontal scale + checkpointing are needed)
- Cross-host correlation (→ v2)
- Rule-based detection patterns (e.g., "ssh login + /etc/shadow modify = credential theft") (→ v2)
- Statistical baselines / anomaly detection (→ v3, needs ML)
- HA / multi-instance / exactly-once semantics (→ v3)
- Persistent state (in-memory only in v1; ~60s buffer is small)

## 3. Architectural Principles

- **Same shape as the data-plane normalizers.** Python 3.12, aiokafka, Pydantic schemas, single Compose service. Consistent dev experience across sub-projects.
- **Lightest tech that does the job.** A 60-second time-window join needs MB of in-memory state per host, not Flink's TB-scale state machinery. Defer Flink to v2.
- **Schema-first.** The `CorrelatedEvent` schema is the contract every downstream sub-project (scoring, response, dashboard) consumes. Tight Pydantic types and `extra="forbid"`, mirroring `CanonicalEvent`.
- **Bidirectional matching.** Whichever side of the pair arrives second triggers the match. No race conditions; the buffer naturally handles out-of-order arrival within the window.

## 4. Why Not Flink (for v1)

The master tech-stack spec calls for Apache Flink as the correlation layer in production. v1 deliberately deviates because:

1. **Operational cost.** Flink is JVM-based and requires a JobManager + TaskManager + a state backend (RocksDB or similar) — at least 3 new long-running services with their own resource and tuning concerns.
2. **Scale not yet justified.** v1 runs against a single Wazuh agent + single Zeek sensor. Total event rate < 100 events/sec. A single Python process handles this comfortably.
3. **Same data shape, different runtime.** When v2 switches to Flink, the `CorrelatedEvent` schema does not change. PyFlink jobs replace the Python process; consumers are unaffected.
4. **Walking-skeleton ethos.** Data-plane v1 made the same call (single-broker Kafka, no Schema Registry, in-memory normalizer state). Correlation engine v1 follows the precedent.

## 5. Architecture

### 5.1 Topology

```
events.normalized (Kafka, 6 partitions keyed by host_id)
        │
        ▼
┌────────────────────────────────────────────┐
│ correlation-engine (1 container, bus net)  │
│                                            │
│ Per-host rolling buffer:                   │
│   {host_id: deque[CanonicalEvent]}         │
│   Drops entries with                       │
│   timestamp < (now - window_seconds)       │
│                                            │
│ For each consumed event e:                 │
│   1. Append e to buffer[e.host_id]         │
│   2. Expire entries older than window      │
│   3. If e.event_type starts with "file.":  │
│        find all network.* events in buffer │
│        for the same host                   │
│      Else if e.event_type starts with      │
│        "network.": find all file.* events  │
│   4. If matches found, emit one            │
│      CorrelatedEvent containing e as       │
│      `triggering_event` and the matches    │
│      as `co_occurring_events`              │
└──────────────────────┬─────────────────────┘
                       │
                       ▼
              events.correlated (new Kafka topic)
```

### 5.2 New Kafka topic

| Topic | Producer | Consumers (v1) | Partitions | Retention | Partition Key |
|---|---|---|---|---|---|
| `events.correlated` | correlation-engine | downstream sub-projects | 6 | 14d | `host_id` |

Created via `data-plane/scripts/create-topics.sh` (extend the script).

### 5.3 New Compose service

```yaml
correlation-engine:
  image: intellifim-correlator:dev
  container_name: correlation-engine
  networks: [bus]
  depends_on:
    kafka:
      condition: service_healthy
  environment:
    KAFKA_BOOTSTRAP: "kafka:9092"
    CORRELATION_WINDOW_SECONDS: "60"
    CONSUMER_GROUP: "correlation-engine"
```

## 6. New Schema: `CorrelatedEvent`

Added to `data-plane/schemas/src/intellifim_schemas/correlation.py`. Re-exported from `intellifim_schemas` package init. Bumps package version `0.1.0 → 0.2.0`.

```python
# data-plane/schemas/src/intellifim_schemas/correlation.py
from typing import Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    PositiveInt,
)

from intellifim_schemas.event import CanonicalEvent

CorrelationType = Literal["file_with_network"]
# v2 will add: "rule_match", "behavioral_anomaly", "cross_host"


class CorrelatedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correlation_id: UUID
    correlation_type: CorrelationType
    correlated_at: AwareDatetime              # when the engine emitted this match
    window_seconds: PositiveInt               # the time-window used to find matches

    host_id: str                              # hoisted for Kafka partition key; equals triggering_event.host_id
    triggering_event: CanonicalEvent          # the event whose arrival fired the match
    co_occurring_events: list[CanonicalEvent] = Field(min_length=1)
```

`co_occurring_events` is constrained to `min_length=1` because emitting a "correlation" with zero co-occurring events is meaningless.

## 7. Repository Layout

New package `data-plane/correlator/` parallel to `normalizers/`:

```
data-plane/
├── correlator/                          ← NEW
│   ├── pyproject.toml
│   ├── Dockerfile
│   ├── README.md
│   ├── src/correlator/
│   │   ├── __init__.py
│   │   ├── __main__.py                  (env config + asyncio runner)
│   │   ├── config.py                    (CorrelatorConfig.from_env)
│   │   ├── buffer.py                    (per-host rolling buffer)
│   │   └── engine.py                    (consume → buffer → match → publish loop)
│   └── tests/
│       ├── __init__.py
│       ├── conftest.py
│       ├── test_buffer.py               (add, expire, per-host isolation)
│       └── test_engine.py               (file→net match, net→file match, no-match, mixed)
├── schemas/
│   └── src/intellifim_schemas/
│       ├── correlation.py               ← NEW
│       └── tests/test_correlation.py    ← NEW
└── scripts/
    ├── create-topics.sh                 (extended to add events.correlated)
    └── tail-correlated.py               ← NEW (mirror of tail-normalized.py)
```

`docker-compose.yml` extended with the `correlation-engine` service.

## 8. Engine Component Contract

Two units with clean boundaries:

### `buffer.py — HostBuffer`
- `add(event: CanonicalEvent) -> None` — append to the appropriate host's deque.
- `recent(host_id: str, predicate: Callable[[CanonicalEvent], bool]) -> list[CanonicalEvent]` — return events from this host's buffer that satisfy the predicate (used to find file-vs-network counterparts).
- Internal: each host has a `deque`; `add` first removes entries with `timestamp < (now - window)` (lazy expiration; cheap because deques are FIFO and we only check the front).
- Pure data structure. No I/O. Trivially unit-testable.

### `engine.py — CorrelationEngine`
- `__init__(consumer, producer, output_topic, window_seconds)` — same dependency-injection shape as `NormalizerLoop`.
- `async run()` — for each consumed event: validate (already done by upstream), add to buffer, find counterparts, emit `CorrelatedEvent` if any. All errors logged + skipped (consistent with normalizer base loop).
- Reuses the `_safe_publish` pattern from `NormalizerLoop` (catch any Kafka producer error; do not crash the loop).
- Documents offset-commit policy (auto-commit, same as normalizers).

## 9. Test Strategy

Mirrors the data-plane testing approach: hand-rolled fakes (FakeConsumer, FakeProducer), no mocking library, fast in-memory tests.

| Test file | Coverage |
|---|---|
| `test_buffer.py` | add+retrieve, lazy expiration of old entries, per-host isolation (events for host A don't surface for host B), empty-host returns [] |
| `test_engine.py` | file event triggers match against existing network event; network event triggers match against existing file event; no match when host differs; no emission when no counterparts in buffer; expired counterparts are not matched |
| `schemas/test_correlation.py` | `CorrelatedEvent` round-trip; `extra="forbid"` rejection; `co_occurring_events` min_length=1 enforcement |

Target: ~10-15 unit tests total. All must pass before commit.

## 10. End-to-End Smoke Test

After full Compose stack is up:

1. `./scripts/seed-test-traffic.sh` (writes files in `monitored/seed-<ts>/` AND triggers victim curl)
2. Wait ~30s
3. `python scripts/tail-correlated.py --bootstrap localhost:9094`
4. Expect: at least one `CorrelatedEvent` printed where `triggering_event.event_type` starts with `file.` and `co_occurring_events` contains at least one `network.flow` from the same host (or vice versa, depending on event ordering).

## 11. Definition of Done (v1)

The sub-project ships when **all** of the following hold:

1. `pytest --import-mode=importlib data-plane/schemas/tests data-plane/normalizers/tests data-plane/correlator/tests` all green (50 existing + ~12 new).
2. `docker compose -f data-plane/docker-compose.yml up -d` brings the full stack (now 16 services) up cleanly.
3. `events.correlated` topic exists after `./scripts/create-topics.sh`.
4. End-to-end smoke test (§10) produces at least one valid `CorrelatedEvent` on `events.correlated`.
5. `data-plane/correlator/README.md` documents bring-up, test-run, and consumer-integration.
6. The `intellifim-schemas` package version is bumped to 0.2.0 in `data-plane/schemas/pyproject.toml` AND `data-plane/normalizers/pyproject.toml` AND `data-plane/correlator/pyproject.toml`.

## 12. Migration Path to v2 / v3

v1 choices are deliberately reversible:

- **Python aiokafka → Apache Flink (v2):** the `CorrelatedEvent` schema does not change. PyFlink job consumes the same `events.normalized` topic and produces the same `events.correlated` topic with stateful keyed-window joins. Consumers are unaffected. The single `correlation-engine` Compose service is replaced by `flink-jobmanager` + `flink-taskmanager` + the deployed job.
- **Add rule-based patterns (v2):** add a `correlation_type: "rule_match"` literal value, plus a `rule_id: str` field. Existing `file_with_network` correlations continue working.
- **Add behavioral baselines (v3):** add a `correlation_type: "behavioral_anomaly"` value plus `anomaly_score: float` field. Consumers gradually start handling the new type.
- **HA / multi-instance (v3):** Flink handles this natively. Until then, single-instance is fine for v1's <100 events/sec.

## 13. Out-of-Scope Reminder

Sub-projects yet to come (each gets its own design + plan + execute cycle, in this dependency order):
- ML platform
- Policy & scoring (OPA + Rego, dynamic threat score)
- Response orchestrator + admin approval workflow
- Admin console (React)
- Reporting subsystem
- Simulation lab
- Observability + IaC

## 14. Next Step

Once this spec is approved and committed, the next step is to write the **implementation plan** for v1 — the concrete, ordered set of tasks (define schema → bootstrap correlator package → buffer with TDD → engine with TDD → config + entry point → Dockerfile → Compose wire-up → tail-correlated.py → README → final smoke test) — via the `superpowers:writing-plans` flow.
