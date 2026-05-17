# IntelliFIM ML Platform v1 — Design

> Sub-project #3 of 9 in the IntelliFIM v1 walking-skeleton sequence. Builds atop sub-project #1 (data plane, PR #43) and runs in parallel with sub-project #2 (correlation engine, PR #44). Both #2 and #3 consume `events.normalized`.

## 1. Purpose

Add a minimal anomaly-detection layer to the data plane: a single Python service that consumes every canonical event, scores it with a pre-trained Isolation Forest, and publishes a `ScoredEvent` to a new Kafka topic `events.scored`. This closes the ML loop end-to-end and unblocks downstream sub-projects #4 (OPA policy / dynamic threat score) and #6 (admin console — needs scores to display).

## 2. Scope: walking skeleton only

The master tech-stack spec (`2026-05-04-intellifim-tech-stack-design.md` §4.4) lists a much larger ML stack: Feast + MLflow + BentoML + scikit-learn + PyTorch + River + SHAP + LIME. **v1 ships only the minimum that proves the loop closes.** Following the breadth-first philosophy proven in sub-projects #1 and #2, every supporting tool is explicitly deferred to v2 (see §11).

**v1 ships:**
- One model family: Isolation Forest (scikit-learn).
- One trained model, baked into a Docker image at build time.
- One inference service consuming `events.normalized`, publishing to `events.scored`.
- One new Pydantic schema `ScoredEvent` (intellifim-schemas 0.2.0 → 0.3.0).
- A one-shot capture script + bundled JSONL training corpus.
- Unit tests + a Docker integration smoke test.

## 3. Out of scope (explicitly deferred)

- Feast, MLflow, BentoML (operational ML tooling).
- PyTorch LSTM / Transformer / River (additional model families).
- SHAP / LIME (XAI — the `features` dict on `ScoredEvent` is structured to support SHAP later without schema change).
- Per-host or per-user models (v1 trains one global model; v1 has one host anyway).
- Per-correlation scoring on `events.correlated` (alternative scope option, rejected).
- Per-host aggregate windowed scoring (alternative scope option, rejected — windowing logic already lives in the correlator).
- Automated retraining, model A/B testing, drift detection, threshold auto-calibration.
- Model quality metrics — we have no labeled anomaly set; defer to v2 alongside SHAP and a small synthetic adversarial corpus.

## 4. Architecture overview

```
                                       ┌──► correlation-engine ──► events.correlated
                                       │      (sub-project #2)
events.normalized (6 partitions) ──────┤
                                       │
                                       └──► anomaly-detector ──► events.scored  (NEW)
                                              (sub-project #3)
```

- Both consumers run in parallel, independent consumer groups. Aligns with the master spec §5 data-flow diagram.
- Stack grows from 16 → **17 services**.
- No state shared between the two consumers; no coupling.

### New artifacts

| Path | Purpose |
|---|---|
| `data-plane/anomaly/` (NEW package) | Python package `intellifim-anomaly` — feature extractor, training script, inference engine, config, entry point |
| `data-plane/anomaly/training-data/baseline-events.jsonl` | Bundled ~1000-event corpus captured once from a real seed run; committed to git |
| `data-plane/anomaly/scripts/capture-baseline.py` | One-shot Kafka tail script used by developers to refresh the bundled corpus |
| `data-plane/anomaly/Dockerfile` | Single-stage image; runs `python -m anomaly.train` as a build step, bakes `model.pkl` into `/app/` |
| `data-plane/schemas/src/intellifim_schemas/scoring.py` (NEW) | `ScoredEvent` Pydantic model; intellifim-schemas bumps 0.2.0 → 0.3.0 |
| `data-plane/scripts/tail-scored.py` (NEW) | Host-side consumer of `events.scored` (mirrors `tail-correlated.py`) |
| `data-plane/docker-compose.yml` | New `anomaly-detector` service block |
| `data-plane/scripts/create-topics.sh` | New `events.correlated`-style topic creation for `events.scored` |

## 5. `events.scored` Kafka topic

- Partitions: **6** (consistent with `events.normalized` and `events.correlated`).
- Retention: **14 days** (consistent).
- Key: `host_id` bytes (preserves partition affinity with `events.normalized`).
- Replication factor: 1 (single-broker v1).

## 6. `ScoredEvent` schema

```python
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from intellifim_schemas.event import CanonicalEvent

ModelVersion = Literal["isolation-forest-v1"]
# v2 widens to include "lstm-v1", "isolation-forest-v2", etc.


class ScoredEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score_id: UUID
    scored_at: AwareDatetime
    model_version: ModelVersion
    anomaly_score: Annotated[float, Field(ge=0.0, le=1.0)]
    is_anomaly: bool
    threshold: Annotated[float, Field(ge=0.0, le=1.0)]

    host_id: str                          # copy of source_event.host_id; partition key
    source_event: CanonicalEvent          # embed the full original (mirrors CorrelatedEvent pattern)
    features: dict[str, float]            # the feature vector that fed the model; SHAP-ready
```

### Score normalization

sklearn's `decision_function` returns roughly `[-0.5, 0.5]` (higher = more normal). The inference engine normalizes to `[0.0, 1.0]` (higher = more anomalous) at the boundary:

```python
anomaly_score = max(0.0, min(1.0, 0.5 - decision))
```

The schema's `Field(ge=0.0, le=1.0)` enforces this contract. Downstream OPA (sub-project #4) consumes already-normalized scores.

### Why `features` is on the wire

The `features` dict carries the exact numeric vector that fed the model. Two benefits:
1. **Debuggability** — when a "weird" score lands on `events.scored`, the operator can re-run the model offline against the recorded features and reproduce the score.
2. **XAI-readiness** — SHAP attributions are computed against the same feature vector. v2 can add SHAP without a schema change.

## 7. Feature extractor (`features.py`)

Pure function: `extract(event: CanonicalEvent) -> dict[str, float]`. Stateless. Used identically by `train.py` and the inference engine. **The set of keys is the contract** — drift between train and inference is caught at engine startup (see §9 drift guard).

23 features:

| Feature key(s) | Source | Shape | Notes |
|---|---|---|---|
| `hour_of_day` | `timestamp.hour` | int 0-23 (as float) | UTC |
| `day_of_week` | `timestamp.weekday()` | int 0-6 (as float) | 0 = Monday |
| `event_type__file_modified` ... (12 keys) | one-hot of `event_type` | 0.0 / 1.0 | One key per Literal value |
| `source__wazuh_fim` ... (6 keys) | one-hot of `source` | 0.0 / 1.0 | One key per Literal value |
| `log_file_size` | `log1p(file_size_bytes or 0)` | float ≥ 0 | 0 for non-file events |
| `src_port` | `src_port or 0` | float ≥ 0 | 0 for non-network events |
| `dst_port` | `dst_port or 0` | float ≥ 0 | 0 for non-network events |

Deliberately deferred (v2): `user`, `process_name`, `protocol`, `file_path` tokens, rolling-window counts.

## 8. Training workflow

### Three-step lifecycle

```
Step 1 (manual, one-time per dataset refresh):
   capture-baseline.py → training-data/baseline-events.jsonl

Step 2 (manual):
   git add data-plane/anomaly/training-data/baseline-events.jsonl

Step 3 (automatic, every docker build):
   `RUN python -m anomaly.train` inside Dockerfile → /app/model.pkl
```

### `capture-baseline.py`

One-shot Python script. Subscribes to `events.normalized` from `localhost:9094`, writes raw JSONL to `--output` path, exits after `--target-count` events or `--max-seconds`. Prints a per-source / per-event-type histogram on exit so the developer can confirm coverage before committing.

```bash
python data-plane/anomaly/scripts/capture-baseline.py \
    --bootstrap localhost:9094 --target-count 1000 --max-seconds 300 \
    --output data-plane/anomaly/training-data/baseline-events.jsonl
```

Target: ~1000 events, ~500KB-1MB file size, all 6 sources represented, at least most of the 12 event types.

### `train.py`

Pure training (no Kafka). Reads JSONL, applies `features.extract()`, fits `IsolationForest(n_estimators=100, contamination="auto", random_state=42)`, pickles a bundle:

```python
{"model": fitted_model, "feature_names": sorted_feature_keys, "model_version": "isolation-forest-v1"}
```

`feature_names` is sorted at training time so the inference engine has a stable column order. `random_state=42` makes training deterministic — same JSONL always produces byte-identical models.

Runnable two ways: `python -m anomaly.train` (CLI) and `RUN python -m anomaly.train` inside the Dockerfile.

### Dockerfile shape

```dockerfile
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY anomaly /app/anomaly
RUN pip install /app/anomaly

# Bake the trained model into the image so deployment is atomic
RUN python -m anomaly.train \
    --input /app/anomaly/training-data/baseline-events.jsonl \
    --output /app/model.pkl

CMD ["intellifim-anomaly-detector"]
```

Build context is `data-plane/` (one level up from the Dockerfile), so the `COPY schemas` / `COPY anomaly` paths resolve against sibling directories. Same pattern as `correlator/Dockerfile`.

Image version === model version. Retraining = rebuild image.

## 9. Inference service

### `AnomalyEngine` (mirrors `CorrelationEngine` from sub-project #2)

```python
class AnomalyEngine:
    """Consume CanonicalEvents from events.normalized, score, publish to events.scored.

    Offset-commit policy: enable_auto_commit=True (aiokafka default). Combined
    with the log-and-skip error policy in _safe_publish + _extract_event, no
    single bad message or transient publish failure can stall a partition.
    """

    def __init__(
        self,
        *,
        consumer: _Consumer,
        producer: _Producer,
        output_topic: str,
        model: Any,                          # fitted IsolationForest
        feature_names: list[str],            # stable column order from pickle
        model_version: ModelVersion,         # from pickle
        threshold: float,
        now: Callable[[], datetime] = _default_now,
    ) -> None: ...

    async def run(self) -> None:
        async for raw_message in self._consumer:
            event = self._extract_event(raw_message)   # dual-mode like correlator
            if event is None:
                continue
            scored = self._score(event)
            await self._safe_publish(scored)
```

Patterns reused verbatim from sub-project #2:
- Dual-mode `_extract_event` (accepts both `CanonicalEvent` instance and `.value` bytes).
- `_safe_publish` wraps `Exception` (`# noqa: BLE001`), logs and skips, never re-raises.
- `now: Callable[[], datetime]` injection for deterministic tests.

### Drift guard at startup

The engine loads the pickle, then verifies the pickled `feature_names` exactly match the current `features.extract()` output keys. If they diverge — i.e., someone retrained against an older revision of `features.py` — the process exits fast with a clear error. Caught at startup, not after the first malformed inference.

### `AnomalyConfig`

Frozen dataclass; `from_env()` reads:

| Env var | Default | Notes |
|---|---|---|
| `KAFKA_BOOTSTRAP` | `kafka:9092` | Same as data-plane convention |
| `CONSUMER_GROUP` | `anomaly-detector` | Matches container name |
| `ANOMALY_THRESHOLD` | `0.5` | Must be in `[0.0, 1.0]`; rejected otherwise |
| `MODEL_PATH` | `/app/model.pkl` | Where Dockerfile writes the trained pickle |

Module-level constants: `INPUT_TOPIC = "events.normalized"`, `OUTPUT_TOPIC = "events.scored"`.

### Entry point `__main__.py`

Same nested try/finally lifecycle as the correlator (this pattern caught a real resource-leak bug in PR #43 review):

```python
await consumer.start()
try:
    await producer.start()
    try:
        engine = AnomalyEngine(...)
        await engine.run()
    finally:
        await producer.stop()
finally:
    await consumer.stop()
```

Plus `try/except KeyboardInterrupt` around `asyncio.run(_run())` for clean Ctrl-C in dev.

### Error handling matrix

| Failure mode | Behavior |
|---|---|
| `model.pkl` missing or corrupted at startup | Fail-fast — process exits |
| `feature_names` in pickle disagree with current extractor output keys | Fail-fast at startup (drift guard) |
| Message has no `.value` | Log warning, skip |
| Message value isn't valid `CanonicalEvent` JSON | Log warning, skip |
| `features.extract()` raises (defensive — it's a pure function) | Log warning, skip |
| `producer.send_and_wait` raises (Kafka outage) | Log warning, skip — loop continues |
| `ANOMALY_THRESHOLD` env value invalid | Fail-fast at startup |

### Compose service

```yaml
  anomaly-detector:
    image: intellifim-anomaly-detector:dev
    container_name: anomaly-detector
    networks: [bus]
    depends_on:
      kafka:
        condition: service_healthy
    environment:
      KAFKA_BOOTSTRAP: "kafka:9092"
      CONSUMER_GROUP: "anomaly-detector"
      ANOMALY_THRESHOLD: "0.5"
```

## 10. Test strategy

TDD throughout. Same `FakeConsumer` / `FakeProducer` shapes as sub-project #2 (no mocking library). Three pytest invocations because of the known conftest collision documented in the data-plane README.

### Unit test inventory (target ~29 new tests)

| File | Coverage | Tests |
|---|---|---|
| `data-plane/schemas/tests/test_scored.py` (NEW) | `ScoredEvent` round-trip; `extra="forbid"`; `anomaly_score` and `threshold` bounds `[0,1]`; naive-datetime rejection; `Literal` rejection of unknown `model_version`; embedded `CanonicalEvent` round-trip | 6 |
| `data-plane/anomaly/tests/test_features.py` (NEW) | One-hot correctness for all 12 event_types + 6 sources; missing-field defaults (file event → 0 ports; network event → 0 file_size); `log1p` on file_size; hour/day extraction; feature dict has exactly 23 keys (regression guard) | 8 |
| `data-plane/anomaly/tests/test_config.py` (NEW) | Env defaults; env overrides; `ANOMALY_THRESHOLD` out-of-range rejection; `INPUT_TOPIC` / `OUTPUT_TOPIC` constants | 5 |
| `data-plane/anomaly/tests/test_engine.py` (NEW) | Per-event scoring round-trip (FakeConsumer + FakeProducer); threshold boundary; dual-mode `_extract_event`; malformed JSON skip; producer failure guard (FlakyProducer); drift guard at engine init | 7 |
| `data-plane/anomaly/tests/test_train.py` (NEW) | `train()` reads JSONL, fits IF, pickles bundle with `{model, feature_names, model_version}`; deterministic with `random_state=42` | 3 |

**Total: 6 + 8 + 5 + 7 + 3 = 29 new tests.**

Combined with existing test suites: ~107 tests across schemas (26), normalizers (38), correlator (20), anomaly (23). Run as three pytest invocations.

### Integration smoke (DoD verification, not pytest)

```bash
docker compose down -v && docker rmi intellifim-anomaly-detector:dev
docker build -f anomaly/Dockerfile -t intellifim-anomaly-detector:dev .
docker compose up -d
./scripts/create-topics.sh && sleep 90

./scripts/seed-test-traffic.sh
sleep 30

docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka:9092 --topic events.scored \
  --from-beginning --max-messages 10 --timeout-ms 30000 \
  | grep -c '"model_version":"isolation-forest-v1"'
# Expected: ≥1
```

## 11. Definition of Done

1. **Image builds:** `docker build -f anomaly/Dockerfile -t intellifim-anomaly-detector:dev .` succeeds. The `RUN python -m anomaly.train` step produces `/app/model.pkl` inside the image.
2. **Stack runs:** `docker compose up -d` brings all **17** services to `Up`.
3. **Topic exists:** `create-topics.sh` creates `events.scored` (6 partitions, 14d retention) idempotently.
4. **Consumer joins:** `anomaly-detector` container logs show the consumer group joining and being assigned partitions on `events.normalized`.
5. **Scoring works end-to-end:** after `./scripts/seed-test-traffic.sh`, at least one valid `ScoredEvent` lands on `events.scored` (verified via `tail-scored.py` or direct `kafka-console-consumer`).
6. **Schema invariants hold on the wire:** every emitted `ScoredEvent` has `model_version="isolation-forest-v1"`, `anomaly_score ∈ [0,1]`, `is_anomaly == (anomaly_score >= threshold)`, and the embedded `source_event` validates against `CanonicalEvent`.
7. **Tests green:** ~29 new unit tests pass. All three pytest invocations (schemas+normalizers, correlator, anomaly) green at ~107 total.

## 12. Patterns continued from sub-projects #1 and #2

This sub-project inherits and reinforces — no deviation:

- Tight Pydantic schemas: `extra="forbid"`, `AwareDatetime`, `Field(ge=, le=)` bounds, `Literal[...]` for versioned identifiers.
- Single Docker image per service-family; behavior baked at build time.
- Cross-package dep pins as RANGES, never `==X.Y.Z`. The new `intellifim-anomaly` pyproject pins `intellifim-schemas>=0.3,<1.0`. The schemas package bumps to 0.3.0.
- Dual-mode `_extract_event(message)`: accepts `CanonicalEvent` instance (test fast-path) OR object with `.value` bytes (production aiokafka path).
- `now: Callable[[], datetime]` injection for deterministic tests on stateful components.
- `_safe_publish` log-and-skip with `# noqa: BLE001` — Kafka outages do not crash the loop.
- Two-reviewer-per-task workflow: spec compliance reviewer FIRST, then code-quality reviewer; re-review on findings until both approve.
- Plan files are immutable contracts during execution; if a reviewer finds an architectural gap mid-execution, update the plan + re-dispatch (expect at least one "Task N.5" addition — this is the breadth-first pattern).

## 13. Deferred to v2 (see also master tech-stack spec §4.4)

Tracked here so they don't get lost when v2 hardening begins:

**ML tooling (deferred until they solve real problems):**
- Feast — feature store for train/serve parity.
- MLflow — model registry + experiment tracking.
- BentoML — model serving with batching / autoscaling / REST.

**Model coverage:**
- PyTorch LSTM / Transformer — sequence-aware detection.
- River — online / incremental updates.
- One-Class SVM, autoencoders — alternative anomaly families.
- Per-host or per-user models.

**Observability:**
- SHAP / LIME — XAI. The `features` dict is already shaped for SHAP.
- Model quality metrics — requires labeled adversarial dataset.
- Score-distribution drift detection.

**Operations:**
- Automated retraining pipeline. v1 is: capture → commit → rebuild image.
- Threshold calibration with labeled data.
- A/B model deployment / canarying.

**Alternative scoring shapes (rejected scope options):**
- Per-correlation scoring on `events.correlated`.
- Per-host aggregate windowed scoring.

## 14. Where things live

- New package root: `data-plane/anomaly/`
- New schema module: `data-plane/schemas/src/intellifim_schemas/scoring.py`
- New scripts: `data-plane/anomaly/scripts/capture-baseline.py`, `data-plane/scripts/tail-scored.py`
- Bundled corpus: `data-plane/anomaly/training-data/baseline-events.jsonl`
- New service in compose: `anomaly-detector`
- New Kafka topic: `events.scored`
