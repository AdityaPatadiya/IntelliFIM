# IntelliFIM Data Plane — v1 Design (Walking Skeleton)

**Date:** 2026-05-04
**Status:** Approved
**Sub-project of:** [IntelliFIM Technology Stack Design](2026-05-04-intellifim-tech-stack-design.md)
**Scope:** v1 only. v2 (production hardening) and v3 (HA + K8s) are explicit follow-ups.

---

## 1. Purpose

Build the smallest end-to-end pipeline that delivers validated, canonical security events from a Linux endpoint and a network sensor into a Kafka topic that downstream IntelliFIM sub-projects (correlation engine, ML inference, scoring, dashboard) can consume.

The data-plane sub-project is the foundation everything else depends on. v1 prioritises a **working contract** over production hardening — the goal is to unblock downstream development with a stable canonical event schema and real flowing events.

## 2. v1 Scope

**In scope:**
- Single Linux endpoint via Wazuh agent
- Wazuh modules: FIM (`syscheck`) and authentication (`authentication_success`, `authentication_failed`, `sudo`)
- Single Zeek sensor watching a dedicated Compose network
- Zeek logs: `conn.log`, `dns.log`, `http.log`, `files.log`
- Kafka (single broker, KRaft mode) with 7 topics
- Six per-source normalizer services emitting to a canonical topic
- JSON wire format with Pydantic v2 validation (no Schema Registry yet)
- Live test traffic (curl-in-a-loop victim containers) + on-demand pcap replay
- Kafka UI for development inspection

**Explicit non-goals (deferred):**
- Schema Registry / Avro (→ v2)
- HA Kafka, multi-broker (→ v3)
- Wazuh Indexer + Dashboard (→ v2)
- TLS between services (→ v2)
- HashiCorp Vault for secrets (→ v2)
- Prometheus / Grafana observability (→ v2)
- Kubernetes / Helm charts (→ v3)
- Multi-agent / multi-sensor / Windows agent (→ v3)

## 3. Architecture

### 3.1 Container Topology (15 services)

| Group | Containers | Image |
|---|---|---|
| Source | `wazuh-agent` | `wazuh/wazuh-agent:4.14.5` |
|  | `wazuh-manager` | `wazuh/wazuh-manager:4.14.5` |
|  | `zeek-sensor` | `zeek/zeek:6.0.4` (shares `victim-server`'s netns — see §6) |
| Shipping | `filebeat-wazuh` | `elastic/filebeat:8.13.4` |
|  | `filebeat-zeek` | `elastic/filebeat:8.13.4` |
| Bus | `kafka` | `bitnamilegacy/kafka:3.7.0` (KRaft mode, dual listeners 9092/9094) |
| Normalizers (one per source) | `normalizer-wazuh-fim` | `intellifim-normalizer:dev` (custom) |
|  | `normalizer-wazuh-auth` | `intellifim-normalizer:dev` (custom) |
|  | `normalizer-zeek-conn` | `intellifim-normalizer:dev` (custom) |
|  | `normalizer-zeek-dns` | `intellifim-normalizer:dev` (custom) |
|  | `normalizer-zeek-http` | `intellifim-normalizer:dev` (custom) |
|  | `normalizer-zeek-files` | `intellifim-normalizer:dev` (custom) |
| Dev tooling | `kafka-ui` | `provectuslabs/kafka-ui:v0.7.2` |
| Test traffic | `victim-server` | `nginx:1.27-alpine` |
|  | `victim-client` | `curlimages/curl:8.7.1` |

Notes:
- All six normalizers share a single image; behaviour is selected at container start by `NORMALIZER_SOURCE`.
- The `bitnamilegacy/` namespace is used because Bitnami moved `bitnami/kafka` behind a paid Tanzu subscription in mid-2025; the same images are mirrored at `bitnamilegacy/kafka` for compatibility. v2 should pick a long-term home (Apache or Confluent).
- `tcpreplay` is invoked as a one-shot utility from `scripts/replay-pcap.sh`, not a long-running container.

### 3.2 Data Flow

```
┌──────────────────┐         ┌──────────────────┐
│ wazuh-agent      │         │ zeek-sensor      │
│  /data/monitor   │         │  watches dedicated│
│  + auditd        │         │  Compose network  │
└────────┬─────────┘         └────────┬──────────┘
         │ encrypted (1514)           │ JSON to /var/log/zeek/
         ▼                            │
┌──────────────────┐                  │
│ wazuh-manager    │                  │
│  alerts.json     │                  │
└────────┬─────────┘                  │
         │                            │
         ▼                            ▼
┌──────────────────┐         ┌──────────────────┐
│ filebeat-wazuh   │         │ filebeat-zeek    │
└────────┬─────────┘         └────────┬─────────┘
         │                            │
         └─────────────┬──────────────┘
                       ▼
       ┌─────────────────────────────────────┐
       │ kafka (KRaft, single broker)        │
       │ wazuh.fim, wazuh.auth               │
       │ zeek.conn, zeek.dns, zeek.http,     │
       │ zeek.files                          │
       │ events.normalized                   │
       └─────────────┬───────────────────────┘
                     ▼
       ┌─────────────────────────────────────┐
       │ 6 normalizer services               │
       │ (one per raw topic)                 │
       │ → emit to events.normalized         │
       └─────────────┬───────────────────────┘
                     ▼
              downstream sub-projects
```

### 3.3 Kafka Topics

| Topic | Producer | Consumer (v1) | Partitions | Retention | Partition Key |
|---|---|---|---|---|---|
| `wazuh.fim` | filebeat-wazuh | normalizer-wazuh-fim | 3 | 7d | `host_id` |
| `wazuh.auth` | filebeat-wazuh | normalizer-wazuh-auth | 3 | 7d | `host_id` |
| `zeek.conn` | filebeat-zeek | normalizer-zeek-conn | 3 | 3d | `host_id` |
| `zeek.dns` | filebeat-zeek | normalizer-zeek-dns | 3 | 3d | `host_id` |
| `zeek.http` | filebeat-zeek | normalizer-zeek-http | 3 | 3d | `host_id` |
| `zeek.files` | filebeat-zeek | normalizer-zeek-files | 3 | 7d | `host_id` |
| `events.normalized` | all 6 normalizers | downstream sub-projects | 6 | 14d | `host_id` |

Replication factor: 1 (single broker; v3 raises this to 3).

Partitioning by `host_id` preserves causal order within a single endpoint, which the correlation engine relies on.

## 4. Canonical Event Schema

The contract every downstream sub-project consumes. Defined in a shared `intellifim-schemas` Python package so that both producers (normalizers) and consumers (correlation, ML, dashboard) import the same models.

```python
# intellifim_schemas/event.py
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any, Literal
from uuid import UUID
from pydantic import (
    AwareDatetime, BaseModel, ConfigDict, Field,
    NonNegativeInt, PositiveInt,
)

EventType = Literal[
    "file.modified", "file.created", "file.deleted", "file.read",
    "auth.login_success", "auth.login_failed", "auth.logout", "auth.sudo",
    "network.flow", "network.dns_query", "network.http_request",
    "network.file_transfer",
]

Source = Literal[
    "wazuh.fim", "wazuh.auth",
    "zeek.conn", "zeek.dns", "zeek.http", "zeek.files",
]

Port = Annotated[int, Field(ge=1, le=65535)]
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class CanonicalEvent(BaseModel):
    # extra="forbid": unknown fields are a contract violation, not silently ignored.
    model_config = ConfigDict(extra="forbid")

    # identity
    event_id: UUID
    event_type: EventType
    source: Source
    schema_version: str = "1.0.0"

    # time — tz-aware UTC required so cross-host correlation is unambiguous
    timestamp: AwareDatetime
    ingest_timestamp: AwareDatetime

    # host
    host_id: str                # Wazuh agent ID or Zeek sensor ID
    host_name: str | None = None

    # actor
    user: str | None = None
    user_uid: NonNegativeInt | None = None       # uid 0 = root
    process_name: str | None = None
    process_pid: PositiveInt | None = None       # pid 0 is the kernel scheduler

    # file subject
    file_path: str | None = None
    file_hash_sha256: Sha256Hex | None = None
    file_size_bytes: NonNegativeInt | None = None  # 0 = empty file is valid

    # network subject
    src_ip: IPv4Address | IPv6Address | None = None
    src_port: Port | None = None
    dst_ip: IPv4Address | IPv6Address | None = None
    dst_port: Port | None = None
    protocol: str | None = None

    # passthrough — original event for debugging / future XAI
    raw: dict[str, Any] = Field(default_factory=dict)
```

### Per-source field mapping (v1)

| Canonical field | Wazuh FIM (`syscheck`) | Wazuh auth | Zeek `conn` | Zeek `dns` | Zeek `http` | Zeek `files` |
|---|---|---|---|---|---|---|
| `event_type` | derived from `syscheck.event` | derived from rule.id | `network.flow` | `network.dns_query` | `network.http_request` | `network.file_transfer` |
| `timestamp` | `timestamp` | `timestamp` | `ts` | `ts` | `ts` | `ts` |
| `host_id` | `agent.id` | `agent.id` | sensor ID (constant) | sensor ID | sensor ID | sensor ID |
| `host_name` | `agent.name` | `agent.name` | – | – | – | – |
| `user` | `syscheck.audit.user.name` | `data.dstuser` | – | – | – | – |
| `user_uid` | `syscheck.audit.user.id` | `data.uid` | – | – | – | – |
| `process_name` | `syscheck.audit.process.name` | `data.process` | – | – | – | – |
| `process_pid` | `syscheck.audit.process.id` | `data.pid` | – | – | – | – |
| `file_path` | `syscheck.path` | – | – | – | – | `filename` |
| `file_hash_sha256` | `syscheck.sha256_after` | – | – | – | – | `sha256` |
| `file_size_bytes` | `syscheck.size_after` | – | – | – | – | `seen_bytes` |
| `src_ip` | – | `data.srcip` | `id.orig_h` | `id.orig_h` | `id.orig_h` | `tx_hosts` |
| `src_port` | – | – | `id.orig_p` | `id.orig_p` | `id.orig_p` | – |
| `dst_ip` | – | `data.dstip` | `id.resp_h` | `id.resp_h` | `id.resp_h` | `rx_hosts` |
| `dst_port` | – | – | `id.resp_p` | `id.resp_p` | `id.resp_p` | – |
| `protocol` | – | – | `proto` | `dns` | `http` | – |

`raw` always carries the full original event for debugging and for future XAI explanations.

## 5. Normalizer Service Contract

Every normalizer is a small async Python service following the same shape:

- **One topic in, one topic out:** consumes from a single raw topic, produces to `events.normalized`.
- **Independent consumer group:** `normalizer-<source>` so each scales independently and one failure doesn't stall the others.
- **Library:** `aiokafka` for async Kafka I/O.
- **Validation:** every emitted message validated against `CanonicalEvent` before publish; malformed input is logged and dropped (does NOT crash the pipeline).
- **Shared base class:** `normalizers/base.py` owns the consume → transform → validate → produce loop. Per-source modules implement only `transform(raw_event: dict) -> CanonicalEvent`.
- **Same Dockerfile, different env vars:** image is identical for all six normalizers; behaviour selected by `NORMALIZER_SOURCE=zeek.conn` etc.
- **Size target:** ~50–100 LOC of source-specific transform logic per service.

### Failure handling

- Malformed input → log + drop + increment a counter. Do not block the partition.
- Kafka disconnect → backoff + reconnect; do not drop in-flight events (use `enable.idempotence=true` on the producer).
- Schema validation failure on output → log the offending input + drop. Indicates a mapping bug; visible immediately in logs.

## 6. Test Traffic Strategy

Two complementary sources of traffic for Zeek:

1. **Live victim containers** — 1–2 lightweight containers (e.g., `curlimages/curl`) on the dedicated Compose network running scripted curl loops to other victim containers. Provides a constant low-volume baseline of "normal" traffic.
2. **On-demand pcap replay** — `scripts/replay-pcap.sh <file.pcap>` invokes `tcpreplay` to inject deterministic, reproducible test events. Used for:
   - Reproducing specific attack scenarios.
   - Regression tests for normalizer field mapping.
   - Demonstrations.

A `pcaps/` directory holds curated test captures (e.g., known DNS exfiltration sample, known HTTP credential-stuffing sample).

## 7. Repository Layout

This sub-project introduces a top-level `data-plane/` directory:

```
IntelliFIM/
├── chronos-ai-guard/                 (existing)
├── docs/                             (existing)
├── Example/                          (existing)
├── data-plane/                       ← new
│   ├── docker-compose.yml
│   ├── .env.dataplane.example
│   ├── wazuh/
│   │   ├── manager/ossec.conf
│   │   └── agent/ossec.conf
│   ├── zeek/
│   │   └── local.zeek
│   ├── filebeat/
│   │   ├── filebeat-wazuh.yml
│   │   └── filebeat-zeek.yml
│   ├── normalizers/
│   │   ├── Dockerfile
│   │   ├── pyproject.toml
│   │   └── src/normalizers/
│   │       ├── __init__.py
│   │       ├── base.py
│   │       ├── wazuh_fim.py
│   │       ├── wazuh_auth.py
│   │       ├── zeek_conn.py
│   │       ├── zeek_dns.py
│   │       ├── zeek_http.py
│   │       └── zeek_files.py
│   ├── schemas/                      (intellifim-schemas package)
│   │   ├── pyproject.toml
│   │   └── src/intellifim_schemas/
│   │       ├── __init__.py
│   │       └── event.py
│   ├── pcaps/                        (curated test captures)
│   ├── scripts/
│   │   ├── replay-pcap.sh
│   │   ├── seed-test-traffic.sh
│   │   └── tail-normalized.py
│   └── README.md
```

The `intellifim-schemas` package is published from `data-plane/schemas/` because v1 lives entirely inside `data-plane/`. When other sub-projects start consuming it, the package will move to a top-level `packages/` directory and be installed by both producers and consumers.

## 8. Definition of Done

The sub-project ships when **all** of the following hold:

1. `docker compose -f data-plane/docker-compose.yml up` brings the stack up cleanly with no manual steps after `cp .env.dataplane.example .env.dataplane`.
2. Touching a file inside the bind-mounted monitored directory produces a validated `CanonicalEvent` with `event_type ∈ {file.created, file.modified, file.deleted}` on `events.normalized` within 5 seconds.
3. A `curl` from a victim container to another victim container produces validated `CanonicalEvent`s with `event_type` in `{network.flow, network.dns_query, network.http_request}` on `events.normalized`.
4. `scripts/replay-pcap.sh pcaps/<sample>.pcap` produces deterministic, expected canonical events.
5. `scripts/tail-normalized.py` (a ~30-line `aiokafka` consumer) prints validated `CanonicalEvent` objects from `events.normalized`.
6. `data-plane/README.md` documents:
   - How to bring the stack up.
   - How to inspect topics in `kafka-ui` (http://localhost:8080).
   - How to consume `events.normalized` from a new downstream service.
   - How to add a new pcap to the test set.
7. The `intellifim-schemas` package is `pip install`-able from `data-plane/schemas/`.

## 9. Migration Path to v2 / v3

Choices made here are deliberately reversible:

- **JSON → Avro:** the canonical event *shape* stays identical. v2 swaps the serializer in normalizers and adds Schema Registry. Downstream consumers gradually flip from JSON deserializer to Avro deserializer.
- **Single broker → 3-broker HA:** raise `replication.factor`, add brokers, no application-level change.
- **Compose → K8s:** every container has a clear single responsibility — porting to Helm charts is mechanical.
- **One Linux agent → many Linux + Windows agents:** Wazuh manager already supports this; the only change is enrolling more agents and possibly raising Kafka partitions.
- **Add new event sources:** new raw topic + new normalizer container; downstream consumers unchanged.

## 10. Out-of-Scope Reminder

This spec covers the data plane only. The following are separate sub-projects with their own design docs to come:

- Correlation engine (Flink jobs over `events.normalized`)
- ML platform (Feast, MLflow, BentoML, models)
- Policy & scoring (OPA + Rego, dynamic threat score)
- Response orchestrator + approval workflow
- Admin console (React)
- Reporting subsystem
- Simulation lab
- Observability + IaC

## 11. Next Step

Once this spec is approved and committed, the next step is to write the **implementation plan** for v1 — the concrete, ordered set of tasks (write Pydantic models, write base normalizer, write per-source normalizers, author Compose file, configure Wazuh, configure Zeek, configure Filebeat, write test scripts, write README) — via the `superpowers:writing-plans` flow.
