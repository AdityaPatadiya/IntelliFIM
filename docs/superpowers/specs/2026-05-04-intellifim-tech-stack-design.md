# IntelliFIM — Technology Stack Design

**Date:** 2026-05-04
**Status:** Approved (stack only; component-level designs to follow)
**Scope:** Production-grade, on-premises, enterprise deployment targeting Linux + Windows endpoints, orchestrated on Kubernetes.

---

## 1. Project Summary

IntelliFIM is an AI-driven Intrusion Prevention System (IPS) integrated with File Integrity Monitoring (FIM) and Network Traffic Analysis. It correlates file-level events with network behavior, evaluates risk through context-aware scoring (user role, device, location, temporal patterns), assigns a dynamic threat score, and executes a tiered response strategy with explainable reasoning.

The novel contribution lives in **correlation, scoring, XAI, tiered response, and slow-acting insider-threat detection** — *not* in reinventing endpoint agents or packet capture. The stack therefore integrates mature, production-grade open-source telemetry (Wazuh, Zeek) and concentrates engineering effort on the AI/policy/response layers.

## 2. Architectural Principles

- **Integrate proven telemetry; build what's novel.** Wazuh + Zeek provide the data plane; IntelliFIM provides correlation, ML, scoring, XAI, and response orchestration.
- **Stream-first.** All events flow through Kafka; consumers (correlation, ML, storage) are independently scalable.
- **Policy as code.** Threat-scoring rules and RBAC live in OPA/Rego, hot-reloadable and auditable.
- **Cross-platform parity.** Every enforcement action has Linux and Windows implementations behind a single interface.
- **Explainability is a first-class output.** Every detection ships with SHAP/LIME reasoning consumable by admins.
- **Production hygiene.** TLS everywhere, secrets in Vault, observability on day one, GitOps deploys.

## 3. Deployment Target

- **On-premises**, customer-controlled infrastructure.
- **Kubernetes** for production orchestration (k3s acceptable for small deployments, full K8s for large).
- **Docker Compose** for local development and the simulation environment.

## 4. Component Stack

### 4.1 Data Plane (Event Sources)

| Layer | Choice | Rationale |
|---|---|---|
| Endpoint agent (FIM + host events) | **Wazuh Agent** (Linux + Windows) | Cross-platform, production-grade, free; ships with `audit_who` enrichment, syscall integration, registry monitoring on Windows |
| Network sensor | **Zeek** (Linux box on SPAN port or network tap) | Best-in-class protocol parsing; emits structured JSON ideal for correlation |
| Optional signature IDS | **Suricata** (alongside Zeek) | Catches known-bad signatures Zeek isn't designed for |
| Log shipper | **Filebeat** | Reliable, standard, ships Zeek logs into Kafka |

### 4.2 Event Bus & Stream Processing

| Layer | Choice | Rationale |
|---|---|---|
| Message bus | **Apache Kafka** (3-broker cluster minimum) | Durable, replayable, horizontally scalable, enterprise standard |
| Schema registry | **Confluent Schema Registry** (or Apicurio) | Avro/JSON schemas keep producers and consumers in sync |
| Stream processor | **Apache Flink** (PyFlink) | Stateful, exactly-once correlation between FIM and network event streams within time windows |

### 4.3 Backend Services

| Layer | Choice | Rationale |
|---|---|---|
| Language / framework | **Python 3.12 + FastAPI** | Async, lives next to the ML stack, fast iteration |
| Background jobs | **Celery + Redis broker** | Model retraining, report generation, batch correlation |
| API gateway | **Traefik** (or Kong) | TLS termination, routing, rate limiting |
| Inter-service comms | **gRPC** (internal) + **REST** (external) | gRPC for low-latency correlation calls; REST for the dashboard |

### 4.4 AI / ML Layer

| Purpose | Choice | Rationale |
|---|---|---|
| Tabular anomaly detection | **scikit-learn** (Isolation Forest, One-Class SVM) | Mature, fast, well-suited to per-event scoring |
| Sequence / temporal models | **PyTorch** (LSTM / small Transformer) | Detects slow-acting insider threats over days/weeks |
| Online / incremental learning | **River** | Continuous model updates without full retraining |
| Feature store | **Feast** | Train/serve parity, reusable features |
| Model registry / tracking | **MLflow** | Versioned models, reproducible experiments, deployment metadata |
| Model serving | **BentoML** (alternative: TorchServe) | Production model APIs with batching and autoscaling |
| Explainable AI | **SHAP** (primary) + **LIME** (backup) | Per-detection reasoning, human-readable feature attributions |

### 4.5 Threat Scoring & Policy

| Purpose | Choice | Rationale |
|---|---|---|
| Policy engine | **Open Policy Agent (OPA)** with **Rego** | Declarative `role × device × location × time → score weights`; auditable; hot-reloadable |
| Known-pattern detection | **Sigma rules** | Industry-standard threat-detection language |
| Threat-intel enrichment | **MISP** integration | Pull IOCs, enrich events with known-bad indicators |

### 4.6 Storage

| Purpose | Choice | Rationale |
|---|---|---|
| Relational (users, devices, policies, audit) | **PostgreSQL 16** | Battle-tested system of record |
| Time-series events | **TimescaleDB** (PostgreSQL extension) | Same DB, optimized for high-volume FIM/network event firehose |
| Search & historical analytics | **OpenSearch** (Wazuh ships it; reuse) | Free Elasticsearch fork; powers log search and historical queries |
| Hot state / cache | **Redis** | Sessions, dynamic threat scores, rate limits |
| Object storage | **MinIO** (S3-compatible) | Backup snapshots, model artifacts, generated PDF reports |

### 4.7 Response & Enforcement

| Purpose | Choice | Rationale |
|---|---|---|
| Action dispatch | **Wazuh Active Response** + custom Python orchestrator | Wazuh ships scripts to agents; the orchestrator selects the action and tier |
| Linux enforcement | `nftables`, `pam_tally2`, `kill`, `auditctl` | Native, no extra dependencies |
| Windows enforcement | PowerShell: `Disable-ADAccount`, `Block-SmbShareAccess`, `netsh advfirewall`, `Stop-Process` | Standard Windows admin tooling |
| Approval workflow | Custom service (Postgres-backed) + email/Slack notifications | Tier-2/Tier-3 actions require admin sign-off |

Enforcement actions sit behind a single `EnforcementAction` interface with platform-specific implementations to keep the orchestrator OS-agnostic.

### 4.8 Authentication & Authorization

| Purpose | Choice | Rationale |
|---|---|---|
| Identity provider | **Keycloak** | OIDC, SAML, LDAP/AD federation, MFA — enterprise table stakes |
| Authorization | **OPA** (reused) | Same engine; RBAC policies as code |
| Secrets | **HashiCorp Vault** | API keys, agent certificates, DB credentials |

### 4.9 Frontend (Admin Console)

| Purpose | Choice | Rationale |
|---|---|---|
| Framework | **React 18 + TypeScript + Vite** | Already established in the repo; fast, modern |
| UI components | **shadcn/ui + TailwindCSS + Radix** | Already in the repo; accessible, customizable |
| Charts | **Apache ECharts** (with Recharts for simple cases) | ECharts handles heavy security viz (heatmaps, sankey, network graphs) |
| Server state | **TanStack Query** | Already in the repo |
| Client state | **Zustand** | Lightweight; complements TanStack Query |
| Real-time | **WebSockets** (FastAPI) + **socket.io-client** | Live alerts and threat-score updates |
| Forms | **react-hook-form + Zod** | Already in the repo |

### 4.10 Reporting

| Purpose | Choice |
|---|---|
| PDF generation | **WeasyPrint** + **Jinja2** templates |
| Scheduled reports | **Celery Beat** |
| Compliance templates | PCI-DSS, HIPAA, GDPR, ISO 27001, NIST 800-53 |

### 4.11 Simulation Environment

| Purpose | Choice |
|---|---|
| Isolated lab | **Docker Compose** (victim + attacker containers, plus Linux/Windows VMs as needed) |
| Attack scenarios | **Atomic Red Team** (MITRE ATT&CK techniques, scriptable) |
| Adversary emulation | **MITRE Caldera** (full red-team workflow) |
| Traffic generation | `tcpreplay` + custom Scapy scripts |

### 4.12 Infrastructure & Operations

| Purpose | Choice |
|---|---|
| Local dev | Docker Compose |
| Production orchestration | **Kubernetes** (k3s for small, full K8s for large) |
| Infrastructure as Code | **Terraform** + **Helm** |
| CI/CD | **GitHub Actions** + **ArgoCD** (GitOps) |
| Container registry | **Harbor** (self-hosted, CVE scanning) |
| Service mesh (optional) | **Linkerd** (mTLS between services) |

### 4.13 Observability

| Purpose | Choice |
|---|---|
| Metrics | **Prometheus** + **Grafana** |
| Logs | **Loki** (or reuse OpenSearch) |
| Traces | **Jaeger** via **OpenTelemetry** SDK in FastAPI |
| Alerting | **Alertmanager** → PagerDuty / Slack / email |
| Uptime probes | **Blackbox exporter** |

## 5. End-to-End Data Flow

```
Endpoints (Wazuh agent) ─┐
                         ├─► Wazuh Manager ─► Filebeat ─┐
Network tap (Zeek)       ─┘                             │
                                                        ▼
                                                     Kafka
                                                        │
                       ┌────────────────────────────────┼──────────────────────────────┐
                       ▼                                ▼                              ▼
               Flink Correlation             ML Inference (BentoML)         Raw → OpenSearch
               (file ↔ network              (Isolation Forest, LSTM)       (search/historical)
                within time windows)                    │
                       │                                ▼
                       └────────────► OPA Policy Engine ◄──── Context
                                              │       (user role, device, location, time)
                                              ▼
                                      Dynamic Threat Score
                                              │
                                              ▼
                                  Tiered Response Orchestrator
                                  ┌─────────┼─────────┬───────────────┐
                                  ▼         ▼         ▼               ▼
                                Tier 1    Tier 2    Tier 3      Admin Approval
                                (alert)   (isolate) (disable)   Workflow
                                              │
                                              ▼
                                    Wazuh Active Response
                                    → executes on endpoint
                                              │
                                              ▼
                                Audit log → PostgreSQL
                                Dashboard ◄── React + WebSockets
                                Reports → WeasyPrint PDFs
```

## 6. Mapping Abstract Requirements to Stack

| Abstract Requirement | Stack Component(s) |
|---|---|
| File integrity monitoring | Wazuh Agent (FIM module) |
| Real-time network traffic analysis | Zeek + Suricata |
| Context-aware anomaly detection | scikit-learn + PyTorch + River + Feast |
| Correlation of file + network events | Apache Flink (stateful stream join) |
| Risk evaluation by role/device/location/time | OPA + Rego policies |
| Dynamic threat score | OPA outputs + Redis hot state |
| Tiered response (isolation, alert, approval) | Custom orchestrator + Wazuh Active Response + Postgres approval workflow |
| Explainable AI | SHAP + LIME, surfaced in React dashboard |
| Slow-acting insider threat detection | PyTorch LSTM/Transformer over historical event store (TimescaleDB + OpenSearch) |
| Automated compliance reporting | WeasyPrint + Jinja2 + Celery Beat |
| Simulation environment | Docker Compose + Atomic Red Team + MITRE Caldera |

## 7. Out-of-Scope (Explicitly)

- SaaS / multi-tenant cloud deployment.
- Endpoint agent reimplementation (use Wazuh).
- Custom packet-capture stack (use Zeek).
- Custom SIEM UI (Wazuh Dashboard remains available for raw data; IntelliFIM's React console is the primary admin surface).

## 8. Next Steps

1. Decompose the system into independently-buildable sub-projects:
   - Data plane integration (Wazuh + Zeek + Kafka pipeline)
   - Correlation engine (Flink jobs)
   - ML platform (Feast + MLflow + BentoML + models)
   - Policy & scoring (OPA + Rego policies + Redis state)
   - Response orchestrator + approval workflow
   - Admin console (React)
   - Reporting subsystem
   - Simulation lab
   - Observability + IaC
2. For each sub-project: brainstorm → spec → implementation plan → build.
3. The first sub-project to design in detail is the **data-plane integration**, since every downstream component depends on it.
