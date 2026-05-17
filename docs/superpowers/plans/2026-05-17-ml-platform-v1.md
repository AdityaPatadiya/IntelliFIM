# ML Platform v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a single Python service `anomaly-detector` to the data-plane stack that consumes `events.normalized`, scores each `CanonicalEvent` with a pre-trained scikit-learn `IsolationForest`, and publishes a `ScoredEvent` to a new Kafka topic `events.scored`.

**Architecture:** New Python package `intellifim-anomaly` at `data-plane/anomaly/` (mirrors the correlator's shape). New Pydantic schema `ScoredEvent` in `intellifim-schemas` (bumps to 0.3.0). Bundled JSONL training corpus + `train.py` that runs as a Docker build step so the model is baked into the image. Pure stateless feature extraction (`features.py`) shared between train and inference, with a startup drift guard to catch divergence. Same offset-commit, log-and-skip, dual-mode `_extract_event` patterns as the correlator.

**Tech Stack:** Python 3.12, Pydantic v2, aiokafka, scikit-learn (IsolationForest), numpy, pytest, Docker Compose. NO Feast / MLflow / BentoML / PyTorch / River / SHAP in v1 — all deferred to v2.

**Reference spec:** [`docs/superpowers/specs/2026-05-17-ml-platform-v1-design.md`](../specs/2026-05-17-ml-platform-v1-design.md)

**Reference for patterns:** Mirror the correlator at `data-plane/correlator/` — `CorrelationEngine` → `AnomalyEngine`, `HostBuffer`-free (we're stateless), same Dockerfile / config / __main__ / test shape.

**Branch:** Create `feat/ml-platform-v1` off `main` before Task 1.

---

## File Map

```
data-plane/
├── schemas/
│   └── src/intellifim_schemas/
│       ├── scoring.py                              ← NEW (ScoredEvent + ModelVersion)
│       └── __init__.py                             ← MODIFY (re-export ScoredEvent, ModelVersion)
│   ├── pyproject.toml                              ← MODIFY (version 0.2.0 → 0.3.0)
│   └── tests/test_scored.py                        ← NEW (6 tests)
│
├── anomaly/                                        ← NEW package
│   ├── pyproject.toml
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── README.md
│   ├── training-data/
│   │   └── baseline-events.jsonl                   ← NEW (captured in Task 7, ~1000 events)
│   ├── scripts/
│   │   └── capture-baseline.py                     ← NEW (one-shot capture tool)
│   ├── src/anomaly/
│   │   ├── __init__.py                             (empty)
│   │   ├── __main__.py                             (entry point)
│   │   ├── config.py                               (AnomalyConfig)
│   │   ├── features.py                             (extract() pure function)
│   │   ├── engine.py                               (AnomalyEngine)
│   │   └── train.py                                (training script)
│   └── tests/
│       ├── __init__.py                             (empty)
│       ├── conftest.py                             (make_event fixture)
│       ├── test_features.py                        (8 tests)
│       ├── test_config.py                          (5 tests)
│       ├── test_train.py                           (3 tests)
│       └── test_engine.py                          (7 tests)
│
├── docker-compose.yml                              ← MODIFY (add anomaly-detector service)
├── scripts/
│   ├── create-topics.sh                            ← MODIFY (add events.scored)
│   └── tail-scored.py                              ← NEW (host-side consumer)
└── README.md                                       ← MODIFY (service count, anomaly section, DoD #7)
```

**13 tasks total. ~30 new unit tests (6 schemas + 9 features + 5 config + 3 train + 7 engine) + 1 end-to-end smoke test verifying scoring fires on real seeded traffic.**

---

## Task 1: `ScoredEvent` schema (TDD)

**Files:**
- Create: `data-plane/schemas/src/intellifim_schemas/scoring.py`
- Create: `data-plane/schemas/tests/test_scored.py`
- Modify: `data-plane/schemas/src/intellifim_schemas/__init__.py` (re-export new types)
- Modify: `data-plane/schemas/pyproject.toml` (bump `version = "0.2.0"` → `"0.3.0"`)

### Step 1: Write the failing tests

Create `data-plane/schemas/tests/test_scored.py`:

```python
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from intellifim_schemas import CanonicalEvent, ScoredEvent


def _source_event() -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="file.modified",
        source="wazuh.fim",
        timestamp=datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc),
        ingest_timestamp=datetime(2026, 5, 17, 12, 0, 1, tzinfo=timezone.utc),
        host_id="host-001",
        file_path="/etc/shadow",
    )


def _base_payload() -> dict:
    return {
        "score_id": str(uuid4()),
        "scored_at": datetime.now(tz=timezone.utc).isoformat(),
        "model_version": "isolation-forest-v1",
        "anomaly_score": 0.72,
        "is_anomaly": True,
        "threshold": 0.5,
        "host_id": "host-001",
        "source_event": _source_event().model_dump(mode="json"),
        "features": {"hour_of_day": 12.0, "src_port": 0.0},
    }


def test_scored_event_basic_roundtrip():
    src = _source_event()
    event = ScoredEvent(
        score_id=uuid4(),
        scored_at=datetime(2026, 5, 17, 12, 0, 2, tzinfo=timezone.utc),
        model_version="isolation-forest-v1",
        anomaly_score=0.72,
        is_anomaly=True,
        threshold=0.5,
        host_id="host-001",
        source_event=src,
        features={"hour_of_day": 12.0, "src_port": 0.0},
    )
    serialized = event.model_dump_json()
    rebuilt = ScoredEvent.model_validate_json(serialized)
    assert rebuilt == event
    assert rebuilt.source_event.event_type == "file.modified"
    assert rebuilt.features["hour_of_day"] == 12.0


def test_scored_event_rejects_unknown_field():
    payload = _base_payload()
    payload["mystery_field"] = "boom"
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)


def test_scored_event_rejects_unknown_model_version():
    payload = _base_payload()
    payload["model_version"] = "lstm-v1"  # v2; not allowed in v1
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)


def test_scored_event_rejects_anomaly_score_out_of_range():
    payload = _base_payload()
    payload["anomaly_score"] = 1.5
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)
    payload["anomaly_score"] = -0.01
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)


def test_scored_event_rejects_threshold_out_of_range():
    payload = _base_payload()
    payload["threshold"] = -0.1
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)
    payload["threshold"] = 1.01
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)


def test_scored_event_rejects_naive_scored_at():
    payload = _base_payload()
    payload["scored_at"] = datetime(2026, 5, 17, 12, 0, 0).isoformat()  # no tz
    with pytest.raises(ValidationError):
        ScoredEvent.model_validate(payload)
```

### Step 2: Run tests, confirm they fail

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
pytest --import-mode=importlib data-plane/schemas/tests/test_scored.py -v
```

Expected: ImportError on `ScoredEvent` (it doesn't exist yet).

### Step 3: Implement the schema

Create `data-plane/schemas/src/intellifim_schemas/scoring.py`:

```python
"""Scoring schema for IntelliFIM.

Emitted by the anomaly-detector service onto the `events.scored` Kafka topic.
The `features` dict carries the exact numeric vector that fed the model so
v2's SHAP integration can compute attributions without a schema change.
"""
from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
)

from intellifim_schemas.event import CanonicalEvent

ModelVersion = Literal["isolation-forest-v1"]
# v2 will widen to include "lstm-v1", "isolation-forest-v2", etc.


class ScoredEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score_id: UUID
    scored_at: AwareDatetime
    model_version: ModelVersion
    anomaly_score: Annotated[float, Field(ge=0.0, le=1.0)]
    is_anomaly: bool
    threshold: Annotated[float, Field(ge=0.0, le=1.0)]

    host_id: str
    source_event: CanonicalEvent
    features: dict[str, float]
```

### Step 4: Update `__init__.py` to re-export the new types

Replace `data-plane/schemas/src/intellifim_schemas/__init__.py` with:

```python
from intellifim_schemas.correlation import CorrelatedEvent, CorrelationType
from intellifim_schemas.event import CanonicalEvent, EventType, Source
from intellifim_schemas.scoring import ModelVersion, ScoredEvent

__all__ = [
    "CanonicalEvent",
    "CorrelatedEvent",
    "CorrelationType",
    "EventType",
    "ModelVersion",
    "ScoredEvent",
    "Source",
]
```

### Step 5: Bump package version

In `data-plane/schemas/pyproject.toml`, change:

```toml
version = "0.2.0"
```

to:

```toml
version = "0.3.0"
```

### Step 6: Reinstall and run all schemas tests

```bash
pip install -e data-plane/schemas[dev]
pytest --import-mode=importlib data-plane/schemas/tests -v
```

Expected: 20 existing tests (14 event + 6 correlation) + 6 new = **26 passed**.

### Step 7: Stage files (DO NOT COMMIT)

```bash
git add data-plane/schemas/src/intellifim_schemas/scoring.py \
        data-plane/schemas/src/intellifim_schemas/__init__.py \
        data-plane/schemas/tests/test_scored.py \
        data-plane/schemas/pyproject.toml
```

> Suggested commit: `feat(schemas): add ScoredEvent and bump intellifim-schemas to 0.3.0`

---

## Task 2: Bootstrap `intellifim-anomaly` package

**Files:**
- Create: `data-plane/anomaly/pyproject.toml`
- Create: `data-plane/anomaly/README.md`
- Create: `data-plane/anomaly/src/anomaly/__init__.py`
- Create: `data-plane/anomaly/tests/__init__.py`
- Create: `data-plane/anomaly/tests/conftest.py`

### Step 1: Create `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "intellifim-anomaly"
version = "0.1.0"
description = "Per-event anomaly detection service for IntelliFIM"
requires-python = ">=3.12"
dependencies = [
    "intellifim-schemas>=0.3,<1.0",
    "aiokafka>=0.10,<0.12",
    "pydantic>=2.7,<3",
    "scikit-learn>=1.4,<2",
    "numpy>=1.26,<3",
]

[project.optional-dependencies]
dev = [
    "pytest>=8,<9",
    "pytest-asyncio>=0.23,<0.25",
]

[project.scripts]
intellifim-anomaly-detector = "anomaly.__main__:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
```

### Step 2: Create empty package init

```python
# data-plane/anomaly/src/anomaly/__init__.py
```

(Empty file.)

### Step 3: Create test scaffolding

```python
# data-plane/anomaly/tests/__init__.py
```

(Empty file.)

```python
# data-plane/anomaly/tests/conftest.py
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from intellifim_schemas import CanonicalEvent


@pytest.fixture
def make_event():
    """Factory for CanonicalEvent instances. Defaults to a wazuh.fim file.modified
    event at 2026-05-17T12:00:00Z for host-001. Override any field via kwargs."""

    def _make(
        *,
        event_type: str = "file.modified",
        source: str = "wazuh.fim",
        host_id: str = "host-001",
        timestamp: datetime | None = None,
        **extra,
    ) -> CanonicalEvent:
        if timestamp is None:
            timestamp = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
        return CanonicalEvent(
            event_id=uuid4(),
            event_type=event_type,
            source=source,
            timestamp=timestamp,
            ingest_timestamp=datetime.now(tz=timezone.utc),
            host_id=host_id,
            **extra,
        )

    return _make
```

### Step 4: Create README

```markdown
# intellifim-anomaly

Per-event anomaly detection service. Consumes `events.normalized`, scores
each `CanonicalEvent` with a pre-trained scikit-learn `IsolationForest`,
and publishes a `ScoredEvent` to `events.scored`.

The trained model is baked into the Docker image at build time from the
bundled corpus at `training-data/baseline-events.jsonl`. Retrain by
recapturing that file (`scripts/capture-baseline.py`) and rebuilding the
image.

Install for development:

    pip install -e data-plane/schemas
    pip install -e data-plane/anomaly[dev]

Run tests (uses `--import-mode=importlib` so the suite can coexist with
the schemas / normalizers / correlator suites in CI):

    pytest --import-mode=importlib data-plane/anomaly/tests
```

### Step 5: Install and verify

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
pip install -e data-plane/anomaly[dev]
python -c "import anomaly; print(anomaly.__file__)"
```

Expected: prints the path to the installed package (`/home/aditya/Documents/IntelliFIM/data-plane/anomaly/src/anomaly/__init__.py`).

### Step 6: Stage

```bash
git add data-plane/anomaly/pyproject.toml \
        data-plane/anomaly/README.md \
        data-plane/anomaly/src/anomaly/__init__.py \
        data-plane/anomaly/tests/__init__.py \
        data-plane/anomaly/tests/conftest.py
```

> Suggested commit: `feat(anomaly): bootstrap intellifim-anomaly package`

---

## Task 3: `features.py` — pure feature extractor (TDD)

**Files:**
- Create: `data-plane/anomaly/src/anomaly/features.py`
- Create: `data-plane/anomaly/tests/test_features.py`

### Step 1: Write the failing tests

```python
# data-plane/anomaly/tests/test_features.py
from datetime import datetime, timezone
from math import log1p

from anomaly.features import extract


_EXPECTED_KEYS = {
    "hour_of_day", "day_of_week", "log_file_size", "src_port", "dst_port",
    "event_type__file_modified", "event_type__file_created",
    "event_type__file_deleted", "event_type__file_read",
    "event_type__auth_login_success", "event_type__auth_login_failed",
    "event_type__auth_logout", "event_type__auth_sudo",
    "event_type__network_flow", "event_type__network_dns_query",
    "event_type__network_http_request", "event_type__network_file_transfer",
    "source__wazuh_fim", "source__wazuh_auth",
    "source__zeek_conn", "source__zeek_dns",
    "source__zeek_http", "source__zeek_files",
}


def test_extract_returns_exactly_23_keys(make_event):
    """Regression guard. The pickled model's feature_names is derived from
    these keys; adding/removing one would silently break inference."""
    features = extract(make_event())
    assert set(features.keys()) == _EXPECTED_KEYS
    assert len(features) == 23


def test_one_hot_event_type_set_correctly(make_event):
    features = extract(make_event(event_type="file.created"))
    assert features["event_type__file_created"] == 1.0
    # Every other event_type key is 0.0
    et_keys = [k for k in features if k.startswith("event_type__")]
    set_keys = [k for k, v in features.items() if k.startswith("event_type__") and v == 1.0]
    assert len(et_keys) == 12
    assert set_keys == ["event_type__file_created"]


def test_one_hot_source_set_correctly(make_event):
    features = extract(make_event(source="zeek.conn", event_type="network.flow"))
    assert features["source__zeek_conn"] == 1.0
    src_keys = [k for k in features if k.startswith("source__")]
    set_keys = [k for k, v in features.items() if k.startswith("source__") and v == 1.0]
    assert len(src_keys) == 6
    assert set_keys == ["source__zeek_conn"]


def test_file_event_has_zero_ports(make_event):
    features = extract(make_event(event_type="file.modified", file_size_bytes=42))
    assert features["src_port"] == 0.0
    assert features["dst_port"] == 0.0


def test_network_event_has_zero_log_file_size(make_event):
    features = extract(make_event(
        event_type="network.flow", source="zeek.conn",
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=49152, dst_port=443, protocol="tcp",
    ))
    assert features["log_file_size"] == 0.0
    assert features["src_port"] == 49152.0
    assert features["dst_port"] == 443.0


def test_log_file_size_uses_log1p(make_event):
    features = extract(make_event(file_size_bytes=1023))
    assert features["log_file_size"] == log1p(1023)


def test_hour_and_day_of_week_from_utc(make_event):
    # 2026-05-17 was a Sunday (weekday=6); choose 14:30 UTC
    ts = datetime(2026, 5, 17, 14, 30, 0, tzinfo=timezone.utc)
    features = extract(make_event(timestamp=ts))
    assert features["hour_of_day"] == 14.0
    assert features["day_of_week"] == 6.0


def test_all_keys_present_for_every_event_type(make_event):
    """No matter the event_type, all 23 keys must appear (one-hots stay 0.0)."""
    for et in ("file.deleted", "auth.login_failed", "network.dns_query"):
        src = "wazuh.fim" if et.startswith("file.") else (
            "wazuh.auth" if et.startswith("auth.") else "zeek.dns"
        )
        features = extract(make_event(event_type=et, source=src))
        assert set(features.keys()) == _EXPECTED_KEYS
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/anomaly/tests/test_features.py -v
```

Expected: ImportError on `anomaly.features`.

### Step 3: Implement `features.py`

```python
# data-plane/anomaly/src/anomaly/features.py
"""Pure stateless feature extractor.

Used identically by `train.py` and the inference engine. The set of keys
returned by `extract()` is the contract: drift between train and inference
is caught at engine startup via the drift guard in engine.py.
"""
from __future__ import annotations

from datetime import timezone
from math import log1p
from typing import get_args

from intellifim_schemas import CanonicalEvent, EventType, Source

_EVENT_TYPES: tuple[str, ...] = get_args(EventType)
_SOURCES: tuple[str, ...] = get_args(Source)


def _key(prefix: str, value: str) -> str:
    """`'event_type', 'file.modified'` → `'event_type__file_modified'`."""
    return f"{prefix}__{value.replace('.', '_')}"


def extract(event: CanonicalEvent) -> dict[str, float]:
    # Normalize to UTC so hour/day are comparable across hosts even if a future
    # ingestor ever ships a non-UTC AwareDatetime. Today every normalizer
    # emits UTC, but the feature definition shouldn't silently depend on that.
    ts = event.timestamp.astimezone(timezone.utc)
    features: dict[str, float] = {
        "hour_of_day": float(ts.hour),
        "day_of_week": float(ts.weekday()),
        "log_file_size": log1p(event.file_size_bytes or 0),
        "src_port": float(event.src_port or 0),
        "dst_port": float(event.dst_port or 0),
    }
    for et in _EVENT_TYPES:
        features[_key("event_type", et)] = 1.0 if event.event_type == et else 0.0
    for src in _SOURCES:
        features[_key("source", src)] = 1.0 if event.source == src else 0.0
    return features
```

### Step 4: Run tests, confirm 9 pass

```bash
pytest --import-mode=importlib data-plane/anomaly/tests/test_features.py -v
```

Expected: **9 passed**. (8 from the original spec + 1 added during code review: `test_non_utc_timestamp_normalized_to_utc` — defense-in-depth regression test for the UTC normalization that prevents silent feature drift if a future ingestor ships a non-UTC AwareDatetime.)

### Step 5: Stage

```bash
git add data-plane/anomaly/src/anomaly/features.py \
        data-plane/anomaly/tests/test_features.py
```

> Suggested commit: `feat(anomaly): add stateless 23-feature extractor`

---

## Task 4: `config.py` — `AnomalyConfig` (TDD)

**Files:**
- Create: `data-plane/anomaly/src/anomaly/config.py`
- Create: `data-plane/anomaly/tests/test_config.py`

### Step 1: Write the failing tests

```python
# data-plane/anomaly/tests/test_config.py
import pytest

from anomaly.config import INPUT_TOPIC, OUTPUT_TOPIC, AnomalyConfig


def test_input_topic_constant():
    assert INPUT_TOPIC == "events.normalized"


def test_output_topic_constant():
    assert OUTPUT_TOPIC == "events.scored"


def test_from_env_with_defaults(monkeypatch):
    monkeypatch.delenv("KAFKA_BOOTSTRAP", raising=False)
    monkeypatch.delenv("CONSUMER_GROUP", raising=False)
    monkeypatch.delenv("ANOMALY_THRESHOLD", raising=False)
    monkeypatch.delenv("MODEL_PATH", raising=False)
    cfg = AnomalyConfig.from_env()
    assert cfg.bootstrap_servers == "kafka:9092"
    assert cfg.consumer_group == "anomaly-detector"
    assert cfg.threshold == 0.5
    assert cfg.model_path == "/app/model.pkl"
    assert cfg.input_topic == "events.normalized"
    assert cfg.output_topic == "events.scored"


def test_from_env_overrides(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka.example.com:19092")
    monkeypatch.setenv("CONSUMER_GROUP", "anomaly-staging")
    monkeypatch.setenv("ANOMALY_THRESHOLD", "0.8")
    monkeypatch.setenv("MODEL_PATH", "/tmp/test-model.pkl")
    cfg = AnomalyConfig.from_env()
    assert cfg.bootstrap_servers == "kafka.example.com:19092"
    assert cfg.consumer_group == "anomaly-staging"
    assert cfg.threshold == 0.8
    assert cfg.model_path == "/tmp/test-model.pkl"


def test_from_env_rejects_threshold_out_of_range(monkeypatch):
    for bad in ("-0.1", "1.5", "abc"):
        monkeypatch.setenv("ANOMALY_THRESHOLD", bad)
        with pytest.raises(ValueError, match="ANOMALY_THRESHOLD"):
            AnomalyConfig.from_env()
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/anomaly/tests/test_config.py -v
```

Expected: ImportError on `anomaly.config`.

### Step 3: Implement `config.py`

```python
# data-plane/anomaly/src/anomaly/config.py
from __future__ import annotations

import os
from dataclasses import dataclass

INPUT_TOPIC = "events.normalized"
OUTPUT_TOPIC = "events.scored"


@dataclass(frozen=True)
class AnomalyConfig:
    bootstrap_servers: str
    consumer_group: str
    threshold: float
    model_path: str
    input_topic: str = INPUT_TOPIC
    output_topic: str = OUTPUT_TOPIC

    @classmethod
    def from_env(cls) -> "AnomalyConfig":
        raw = os.environ.get("ANOMALY_THRESHOLD", "0.5")
        try:
            threshold = float(raw)
        except ValueError as exc:
            raise ValueError(
                f"ANOMALY_THRESHOLD must be a float in [0,1], got {raw!r}"
            ) from exc
        if not (0.0 <= threshold <= 1.0):
            raise ValueError(
                f"ANOMALY_THRESHOLD must be in [0,1], got {threshold}"
            )
        return cls(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092"),
            consumer_group=os.environ.get("CONSUMER_GROUP", "anomaly-detector"),
            threshold=threshold,
            model_path=os.environ.get("MODEL_PATH", "/app/model.pkl"),
        )
```

### Step 4: Run tests, confirm 5 pass

```bash
pytest --import-mode=importlib data-plane/anomaly/tests/test_config.py -v
```

Expected: **5 passed**.

### Step 5: Stage

```bash
git add data-plane/anomaly/src/anomaly/config.py \
        data-plane/anomaly/tests/test_config.py
```

> Suggested commit: `feat(anomaly): add AnomalyConfig with env-var parsing`

---

## Task 5: `train.py` — training script (TDD)

**Files:**
- Create: `data-plane/anomaly/src/anomaly/train.py`
- Create: `data-plane/anomaly/tests/test_train.py`

### Step 1: Write the failing tests

```python
# data-plane/anomaly/tests/test_train.py
import pickle
from pathlib import Path

import numpy as np

from anomaly.features import extract
from anomaly.train import MODEL_VERSION, train


def _synthetic_events(make_event, n: int = 30):
    """Spread across event_types and sources to give IF some variety."""
    events = []
    for i in range(n):
        if i % 3 == 0:
            events.append(make_event(event_type="file.modified", source="wazuh.fim"))
        elif i % 3 == 1:
            events.append(make_event(
                event_type="network.flow", source="zeek.conn",
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=49152 + i, dst_port=443,
                protocol="tcp",
            ))
        else:
            events.append(make_event(
                event_type="network.http_request", source="zeek.http",
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=50000 + i, dst_port=80,
                protocol="tcp",
            ))
    return events


def test_train_returns_bundle_with_expected_keys(make_event):
    events = _synthetic_events(make_event, n=30)
    bundle = train(events)
    assert set(bundle.keys()) == {"model", "feature_names", "model_version"}
    assert bundle["model_version"] == MODEL_VERSION
    assert bundle["model_version"] == "isolation-forest-v1"


def test_train_pickle_feature_names_sorted(make_event):
    events = _synthetic_events(make_event, n=30)
    bundle = train(events)
    assert bundle["feature_names"] == sorted(bundle["feature_names"])
    # And the names match the extractor's output keys
    assert set(bundle["feature_names"]) == set(extract(events[0]).keys())


def test_train_is_deterministic(make_event):
    """random_state=42 makes the model deterministic — same inputs, same predictions."""
    events = _synthetic_events(make_event, n=30)
    bundle1 = train(events)
    bundle2 = train(events)
    # Build a small batch of feature vectors and compare decision_function outputs
    sample_features = [extract(e) for e in events[:5]]
    names = bundle1["feature_names"]
    X = np.array([[f[k] for k in names] for f in sample_features])
    d1 = bundle1["model"].decision_function(X)
    d2 = bundle2["model"].decision_function(X)
    assert np.allclose(d1, d2)
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/anomaly/tests/test_train.py -v
```

Expected: ImportError on `anomaly.train`.

### Step 3: Implement `train.py`

```python
# data-plane/anomaly/src/anomaly/train.py
"""Train an IsolationForest on a bundled JSONL corpus of CanonicalEvents.

Runs both as a CLI (`python -m anomaly.train --input ... --output ...`) and
as a Docker build step. The output pickle is a dict bundling the fitted
model, the sorted feature_names (for stable column order), and the
model_version string.
"""
from __future__ import annotations

import argparse
import pickle
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from intellifim_schemas import CanonicalEvent

from anomaly.features import extract

MODEL_VERSION = "isolation-forest-v1"


def train(events: list[CanonicalEvent]) -> dict[str, Any]:
    if not events:
        raise ValueError("cannot train on an empty event list")
    feature_rows = [extract(e) for e in events]
    feature_names = sorted(feature_rows[0].keys())
    X = np.array([[row[k] for k in feature_names] for row in feature_rows])
    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
    )
    model.fit(X)
    return {
        "model": model,
        "feature_names": feature_names,
        "model_version": MODEL_VERSION,
    }


def _read_jsonl(path: Path) -> list[CanonicalEvent]:
    events: list[CanonicalEvent] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(CanonicalEvent.model_validate_json(line))
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Train IsolationForest from JSONL corpus")
    parser.add_argument("--input", type=Path, required=True, help="JSONL of CanonicalEvents")
    parser.add_argument("--output", type=Path, required=True, help="Pickle output path")
    args = parser.parse_args()

    events = _read_jsonl(args.input)
    bundle = train(events)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "wb") as f:
        pickle.dump(bundle, f)
    print(f"trained {bundle['model_version']} on {len(events)} events; "
          f"wrote {args.output}")


if __name__ == "__main__":
    main()
```

### Step 4: Run tests, confirm 3 pass

```bash
pytest --import-mode=importlib data-plane/anomaly/tests/test_train.py -v
```

Expected: **3 passed**.

### Step 5: Stage

```bash
git add data-plane/anomaly/src/anomaly/train.py \
        data-plane/anomaly/tests/test_train.py
```

> Suggested commit: `feat(anomaly): add train.py — deterministic IsolationForest training`

---

## Task 6: `capture-baseline.py` — one-shot corpus capture script

**Files:**
- Create: `data-plane/anomaly/scripts/capture-baseline.py`

### Step 1: Write the script

```python
#!/usr/bin/env python3
"""Capture a baseline corpus of CanonicalEvents from events.normalized.

Subscribes to events.normalized via the host-exposed Kafka listener,
writes raw JSON lines to --output until --target-count or --max-seconds
is hit. Prints a per-source / per-event-type histogram on exit so the
developer can confirm coverage before committing.

Usage:
    python data-plane/anomaly/scripts/capture-baseline.py \\
        --bootstrap localhost:9094 \\
        --target-count 1000 \\
        --max-seconds 300 \\
        --output data-plane/anomaly/training-data/baseline-events.jsonl
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from collections import Counter
from pathlib import Path

from aiokafka import AIOKafkaConsumer

from intellifim_schemas import CanonicalEvent


async def _capture(bootstrap: str, target_count: int, max_seconds: int, output: Path) -> int:
    consumer = AIOKafkaConsumer(
        "events.normalized",
        bootstrap_servers=bootstrap,
        group_id=None,
        auto_offset_reset="latest",
    )
    await consumer.start()
    captured = 0
    by_source: Counter[str] = Counter()
    by_event_type: Counter[str] = Counter()
    loop = asyncio.get_event_loop()
    deadline = loop.time() + max_seconds

    try:
        with output.open("w") as out:
            while captured < target_count:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    print(f"[capture-baseline] timed out after {max_seconds}s",
                          file=sys.stderr)
                    break
                try:
                    msg = await asyncio.wait_for(
                        consumer.__anext__(), timeout=remaining
                    )
                except asyncio.TimeoutError:
                    break
                try:
                    event = CanonicalEvent.model_validate_json(msg.value)
                except Exception as exc:  # noqa: BLE001 - skip invalid
                    print(f"[capture-baseline] skip invalid: {exc}", file=sys.stderr)
                    continue
                out.write(msg.value.decode("utf-8") + "\n")
                captured += 1
                by_source[event.source] += 1
                by_event_type[event.event_type] += 1
                if captured % 100 == 0:
                    print(f"[capture-baseline] {captured}/{target_count}",
                          file=sys.stderr)
    finally:
        await consumer.stop()

    print(f"\n=== captured {captured} events ===", file=sys.stderr)
    print("by source:", file=sys.stderr)
    for k, n in sorted(by_source.items()):
        print(f"  {k}: {n}", file=sys.stderr)
    print("by event_type:", file=sys.stderr)
    for k, n in sorted(by_event_type.items()):
        print(f"  {k}: {n}", file=sys.stderr)
    return captured


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap", default="localhost:9094")
    parser.add_argument("--target-count", type=int, default=1000)
    parser.add_argument("--max-seconds", type=int, default=300)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    captured = asyncio.run(_capture(
        args.bootstrap, args.target_count, args.max_seconds, args.output,
    ))
    if captured == 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
```

### Step 2: Make executable

```bash
chmod +x data-plane/anomaly/scripts/capture-baseline.py
```

### Step 3: Sanity-check the script imports + arg-parses

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
python data-plane/anomaly/scripts/capture-baseline.py --help
```

Expected: prints usage with all 4 args; exits 0.

### Step 4: Stage

```bash
git add data-plane/anomaly/scripts/capture-baseline.py
```

> Suggested commit: `feat(anomaly): add capture-baseline.py one-shot corpus capture tool`

---

## Task 7: Capture the bundled training corpus

**Files:**
- Create: `data-plane/anomaly/training-data/baseline-events.jsonl` (~1000 events, ~500KB-1MB)

This task is operational, not code-writing — it brings up the data plane, runs seed-test-traffic to drive events through the pipeline, captures ~1000 events using the Task 6 script, verifies coverage, and commits the file.

### Step 1: Bring up the data plane

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane up -d
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 90
```

### Step 2: Launch the capture script in the background

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
mkdir -p /home/aditya/Documents/IntelliFIM/data-plane/anomaly/training-data
python /home/aditya/Documents/IntelliFIM/data-plane/anomaly/scripts/capture-baseline.py \
    --bootstrap localhost:9094 \
    --target-count 1000 \
    --max-seconds 600 \
    --output /home/aditya/Documents/IntelliFIM/data-plane/anomaly/training-data/baseline-events.jsonl \
    > /tmp/capture-baseline.log 2>&1 &
CAPTURE_PID=$!
sleep 5
```

### Step 3: Drive events through the pipeline

Run `seed-test-traffic.sh` a few times to generate diverse traffic. The victim-client's background curl loop produces a steady stream of `zeek.conn` / `zeek.http` events. Manual file writes to `monitored/` drive `wazuh.fim` events.

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
for i in 1 2 3 4 5; do
    ./scripts/seed-test-traffic.sh
    sleep 30
done
# Add a few more FIM events for diversity
for i in 1 2 3; do
    echo "training-event-$i-$(date +%s)" > monitored/training-$i.txt
    sleep 10
done

# Wait for capture to finish (or timeout at 10 min)
wait $CAPTURE_PID
echo "--- capture log ---"
cat /tmp/capture-baseline.log
```

### Step 4: Verify coverage

The capture script prints a histogram on exit. Inspect `/tmp/capture-baseline.log`:

- **Required:** every one of the 6 sources must have ≥1 event (`wazuh.fim`, `wazuh.auth`, `zeek.conn`, `zeek.dns`, `zeek.http`, `zeek.files`).
- **Strongly preferred:** ≥3 distinct `event_type` values across the corpus.
- **Sanity:** total events captured should be 500-1000. If less than 500, re-run more seed iterations and re-capture (truncating the previous output).

```bash
wc -l /home/aditya/Documents/IntelliFIM/data-plane/anomaly/training-data/baseline-events.jsonl
ls -lh /home/aditya/Documents/IntelliFIM/data-plane/anomaly/training-data/baseline-events.jsonl
```

Expected: 500-1000 lines, file size ~250KB-1MB.

> **If `wazuh.auth` coverage is 0** (the canonical case in v1 — containerized Wazuh agent has no PAM/sshd to fire auth events; documented in `project_intellifim_v1_shipped.md`): that's acceptable. The IsolationForest learns from whatever distribution it gets; missing one source means it never sees that column's one-hot active, which is fine — the column stays 0 in training and inference.

### Step 5: Smoke-test that the captured file trains successfully

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
python -m anomaly.train \
    --input /home/aditya/Documents/IntelliFIM/data-plane/anomaly/training-data/baseline-events.jsonl \
    --output /tmp/baseline-model.pkl
```

Expected: prints `trained isolation-forest-v1 on N events; wrote /tmp/baseline-model.pkl`. No errors.

### Step 6: Cleanup smoke artifacts + bring down stack

```bash
rm -f /tmp/capture-baseline.log /tmp/baseline-model.pkl
find /home/aditya/Documents/IntelliFIM/data-plane/monitored -maxdepth 1 -name 'seed-*' -type d -exec rm -rf {} + 2>/dev/null
rm -f /home/aditya/Documents/IntelliFIM/data-plane/monitored/training-*.txt
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane down
```

(NOT `down -v` — keep Wazuh state.)

### Step 7: Stage

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/anomaly/training-data/baseline-events.jsonl
```

> Suggested commit: `data(anomaly): commit baseline training corpus (~N events)`
>
> (Replace `~N events` with the actual line count from Step 4.)

---

## Task 8: `engine.py` — `AnomalyEngine` (TDD)

**Files:**
- Create: `data-plane/anomaly/src/anomaly/engine.py`
- Create: `data-plane/anomaly/tests/test_engine.py`

### Step 1: Write the failing tests

```python
# data-plane/anomaly/tests/test_engine.py
from datetime import datetime, timezone
from typing import Any

import pytest

from intellifim_schemas import ScoredEvent

from anomaly.engine import AnomalyEngine
from anomaly.features import extract
from anomaly.train import train


_T0 = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)


def _now_at(seconds_offset: int):
    def _now() -> datetime:
        from datetime import timedelta
        return _T0 + timedelta(seconds=seconds_offset)
    return _now


class FakeConsumer:
    def __init__(self, events: list):
        self._events = list(events)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._events:
            raise StopAsyncIteration
        return self._events.pop(0)


class FakeProducer:
    def __init__(self):
        self.published: list[tuple[str, bytes, bytes | None]] = []

    async def send_and_wait(self, topic: str, value: bytes, key: bytes | None = None):
        self.published.append((topic, value, key))


class FakeMessage:
    """Mimics aiokafka ConsumerRecord — only .value is used by _extract_event."""
    def __init__(self, value: bytes | None):
        self.value = value


def _fit_model(make_event):
    """Train a small IsolationForest for use in engine tests."""
    events = [
        make_event(event_type="file.modified", source="wazuh.fim")
        for _ in range(10)
    ] + [
        make_event(
            event_type="network.flow", source="zeek.conn",
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=49152 + i, dst_port=443, protocol="tcp",
        )
        for i in range(10)
    ]
    return train(events)


async def test_engine_scores_event_and_publishes(make_event):
    bundle = _fit_model(make_event)
    event = make_event(event_type="file.modified", source="wazuh.fim")
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    engine = AnomalyEngine(
        consumer=consumer, producer=producer,
        output_topic="events.scored",
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        model_version=bundle["model_version"],
        threshold=0.5,
        now=_now_at(0),
    )
    await engine.run()

    assert len(producer.published) == 1
    topic, value, key = producer.published[0]
    assert topic == "events.scored"
    assert key == b"host-001"
    rebuilt = ScoredEvent.model_validate_json(value)
    assert rebuilt.model_version == "isolation-forest-v1"
    assert rebuilt.host_id == "host-001"
    assert 0.0 <= rebuilt.anomaly_score <= 1.0
    assert rebuilt.threshold == 0.5
    assert rebuilt.source_event.event_id == event.event_id
    assert set(rebuilt.features.keys()) == set(bundle["feature_names"])


async def test_engine_threshold_boundary_inclusive(make_event, monkeypatch):
    """is_anomaly must be True when anomaly_score == threshold (>= boundary)."""
    bundle = _fit_model(make_event)
    event = make_event()
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    engine = AnomalyEngine(
        consumer=consumer, producer=producer,
        output_topic="events.scored",
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        model_version=bundle["model_version"],
        threshold=0.0,  # everything is_anomaly at this threshold
        now=_now_at(0),
    )
    await engine.run()
    rebuilt = ScoredEvent.model_validate_json(producer.published[0][1])
    assert rebuilt.is_anomaly is True


async def test_engine_accepts_kafka_message_with_value_bytes(make_event):
    bundle = _fit_model(make_event)
    event = make_event(event_type="file.modified")
    consumer = FakeConsumer([FakeMessage(event.model_dump_json().encode("utf-8"))])
    producer = FakeProducer()
    engine = AnomalyEngine(
        consumer=consumer, producer=producer,
        output_topic="events.scored",
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        model_version=bundle["model_version"],
        threshold=0.5,
        now=_now_at(0),
    )
    await engine.run()
    assert len(producer.published) == 1
    rebuilt = ScoredEvent.model_validate_json(producer.published[0][1])
    assert rebuilt.source_event.event_id == event.event_id


async def test_engine_drops_malformed_json(make_event):
    bundle = _fit_model(make_event)
    consumer = FakeConsumer([
        FakeMessage(b'{"not":"a canonical event"}'),
        FakeMessage(None),
    ])
    producer = FakeProducer()
    engine = AnomalyEngine(
        consumer=consumer, producer=producer,
        output_topic="events.scored",
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        model_version=bundle["model_version"],
        threshold=0.5,
        now=_now_at(0),
    )
    await engine.run()
    assert producer.published == []


async def test_engine_continues_after_producer_failure(make_event):
    """A transient producer error must not crash the loop."""
    bundle = _fit_model(make_event)
    e1 = make_event(event_type="file.modified")
    e2 = make_event(event_type="file.created")
    consumer = FakeConsumer([e1, e2])

    class FlakyProducer:
        def __init__(self):
            self.calls = 0
            self.published: list[Any] = []

        async def send_and_wait(self, topic: str, value: bytes, key: bytes | None = None):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("simulated kafka outage")
            self.published.append((topic, value, key))

    producer = FlakyProducer()
    engine = AnomalyEngine(
        consumer=consumer, producer=producer,
        output_topic="events.scored",
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        model_version=bundle["model_version"],
        threshold=0.5,
        now=_now_at(0),
    )
    await engine.run()
    assert producer.calls == 2
    assert len(producer.published) == 1


async def test_engine_accepts_canonical_event_instance(make_event):
    """Test fast-path: consumer yields a CanonicalEvent directly (not wrapped)."""
    bundle = _fit_model(make_event)
    event = make_event()
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    engine = AnomalyEngine(
        consumer=consumer, producer=producer,
        output_topic="events.scored",
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        model_version=bundle["model_version"],
        threshold=0.5,
        now=_now_at(0),
    )
    await engine.run()
    assert len(producer.published) == 1


def test_engine_drift_guard_rejects_mismatched_feature_names(make_event):
    """If pickled feature_names != extractor output, init must raise."""
    bundle = _fit_model(make_event)
    bad_names = bundle["feature_names"] + ["bogus_extra_feature"]
    with pytest.raises(RuntimeError, match="feature schema drift"):
        AnomalyEngine(
            consumer=FakeConsumer([]),
            producer=FakeProducer(),
            output_topic="events.scored",
            model=bundle["model"],
            feature_names=bad_names,
            model_version=bundle["model_version"],
            threshold=0.5,
            now=_now_at(0),
        )
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/anomaly/tests/test_engine.py -v
```

Expected: ImportError on `anomaly.engine`.

### Step 3: Implement `engine.py`

```python
# data-plane/anomaly/src/anomaly/engine.py
"""AnomalyEngine — consume CanonicalEvents, score with IsolationForest, publish ScoredEvents.

Offset-commit policy: same as data-plane normalizers + correlator — no
manual commit; expects the consumer to have enable_auto_commit=True
(aiokafka default). Combined with the log-and-skip error policy in
_safe_publish + _extract_event, no single bad message or transient
publish failure can stall a partition.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from uuid import UUID, uuid4

import numpy as np
from pydantic import ValidationError

from intellifim_schemas import CanonicalEvent, ScoredEvent

from anomaly.features import extract

log = logging.getLogger(__name__)


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


# Minimal valid CanonicalEvent used at engine init to verify the extractor's
# output keys match the pickled feature_names. This catches a class of bug
# where train.py and engine.py have drifted (someone edited features.py
# without rebuilding the model).
_SAMPLE_EVENT = CanonicalEvent(
    event_id=UUID("00000000-0000-0000-0000-000000000000"),
    event_type="file.modified",
    source="wazuh.fim",
    timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ingest_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    host_id="sample",
)


class _Consumer(Protocol):
    def __aiter__(self) -> "_Consumer": ...
    async def __anext__(self) -> Any: ...


class _Producer(Protocol):
    async def send_and_wait(
        self, topic: str, value: bytes, key: bytes | None = ...
    ) -> Any: ...


class AnomalyEngine:
    def __init__(
        self,
        *,
        consumer: _Consumer,
        producer: _Producer,
        output_topic: str,
        model: Any,
        feature_names: list[str],
        model_version: str,
        threshold: float,
        now: Callable[[], datetime] = _default_now,
    ) -> None:
        # Drift guard: extractor's output keys MUST match pickled feature_names.
        sample_keys = sorted(extract(_SAMPLE_EVENT).keys())
        if sample_keys != sorted(feature_names):
            raise RuntimeError(
                f"feature schema drift: pickle has {sorted(feature_names)}, "
                f"extractor produces {sample_keys}"
            )
        self._consumer = consumer
        self._producer = producer
        self._output_topic = output_topic
        self._model = model
        self._feature_names = list(feature_names)
        self._model_version = model_version
        self._threshold = threshold
        self._now = now

    async def run(self) -> None:
        async for raw_message in self._consumer:
            event = self._extract_event(raw_message)
            if event is None:
                continue
            scored = self._score(event)
            await self._safe_publish(scored)

    @staticmethod
    def _extract_event(message: Any) -> CanonicalEvent | None:
        # Real aiokafka messages have a `.value` attribute (bytes); test fakes
        # may yield CanonicalEvent instances directly. Accept both.
        if isinstance(message, CanonicalEvent):
            return message
        value = getattr(message, "value", None)
        if value is None:
            log.warning("dropping message with no value")
            return None
        try:
            return CanonicalEvent.model_validate_json(value)
        except ValidationError as exc:
            log.warning("dropping invalid CanonicalEvent (%s)", exc)
            return None

    def _score(self, event: CanonicalEvent) -> ScoredEvent:
        features = extract(event)
        X = np.array([[features[k] for k in self._feature_names]])
        decision = float(self._model.decision_function(X)[0])
        anomaly_score = max(0.0, min(1.0, 0.5 - decision))
        return ScoredEvent(
            score_id=uuid4(),
            scored_at=self._now(),
            model_version=self._model_version,
            anomaly_score=anomaly_score,
            is_anomaly=anomaly_score >= self._threshold,
            threshold=self._threshold,
            host_id=event.host_id,
            source_event=event,
            features=features,
        )

    async def _safe_publish(self, scored: ScoredEvent) -> None:
        try:
            await self._producer.send_and_wait(
                self._output_topic,
                value=scored.model_dump_json().encode("utf-8"),
                key=scored.host_id.encode("utf-8"),
            )
        except Exception as exc:  # noqa: BLE001 - Kafka error must not crash the loop
            log.warning(
                "publish failed (%s); skipping score %s", exc, scored.score_id
            )
```

### Step 4: Run tests, confirm 7 pass

```bash
pytest --import-mode=importlib data-plane/anomaly/tests/test_engine.py -v
```

Expected: **7 passed**.

### Step 5: Run the full anomaly suite

```bash
pytest --import-mode=importlib data-plane/anomaly/tests -v
```

Expected: 9 features + 5 config + 3 train + 7 engine = **24 passed**.

### Step 6: Stage

```bash
git add data-plane/anomaly/src/anomaly/engine.py \
        data-plane/anomaly/tests/test_engine.py
```

> Suggested commit: `feat(anomaly): add AnomalyEngine with drift guard and producer-error tolerance`

---

## Task 9: Entry point + Dockerfile

**Files:**
- Create: `data-plane/anomaly/src/anomaly/__main__.py`
- Create: `data-plane/anomaly/Dockerfile`
- Create: `data-plane/anomaly/.dockerignore`

### Step 1: Implement `__main__.py`

```python
# data-plane/anomaly/src/anomaly/__main__.py
from __future__ import annotations

import asyncio
import logging
import pickle
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from anomaly.config import AnomalyConfig
from anomaly.engine import AnomalyEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("anomaly")


def _load_model(path: str) -> tuple[Any, list[str], str]:
    """Load the pickled training bundle. Fail-fast if missing or malformed —
    an inference service without a model is meaningless."""
    with open(path, "rb") as f:
        bundle = pickle.load(f)
    return bundle["model"], bundle["feature_names"], bundle["model_version"]


async def _run() -> None:
    cfg = AnomalyConfig.from_env()
    model, feature_names, model_version = _load_model(cfg.model_path)

    # auto_offset_reset="latest": on a fresh restart, skip the historical
    # backlog. v1 is a walking skeleton / live demo. Production should
    # reconsider — see plan v2.
    consumer = AIOKafkaConsumer(
        cfg.input_topic,
        bootstrap_servers=cfg.bootstrap_servers,
        group_id=cfg.consumer_group,
        enable_auto_commit=True,
        auto_offset_reset="latest",
    )
    producer = AIOKafkaProducer(
        bootstrap_servers=cfg.bootstrap_servers,
        enable_idempotence=True,
    )

    log.info(
        "starting anomaly-detector in=%s out=%s model=%s threshold=%.3f",
        cfg.input_topic, cfg.output_topic, model_version, cfg.threshold,
    )

    # Nested try/finally so we clean up only what we successfully started.
    await consumer.start()
    try:
        await producer.start()
        try:
            engine = AnomalyEngine(
                consumer=consumer,
                producer=producer,
                output_topic=cfg.output_topic,
                model=model,
                feature_names=feature_names,
                model_version=model_version,
                threshold=cfg.threshold,
            )
            await engine.run()
        finally:
            await producer.stop()
    finally:
        await consumer.stop()


def main() -> None:
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        log.info("shutdown requested")


if __name__ == "__main__":
    main()
```

### Step 2: Create `.dockerignore`

```
__pycache__
.pytest_cache
.venv
*.egg-info
tests
```

### Step 3: Create `Dockerfile`

```dockerfile
# data-plane/anomaly/Dockerfile
# Build context must be data-plane/ (one level up) so we can COPY both
# schemas/ and anomaly/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY anomaly /app/anomaly
RUN pip install /app/anomaly

# Bake the trained model into the image so deployment is atomic.
# Image version === model version.
RUN python -m anomaly.train \
    --input /app/anomaly/training-data/baseline-events.jsonl \
    --output /app/model.pkl

CMD ["intellifim-anomaly-detector"]
```

### Step 4: Sanity-check the entry point imports

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
python -c "from anomaly.__main__ import main; print(main)"
```

Expected: `<function main at 0x...>`.

### Step 5: Build the image

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker build -f anomaly/Dockerfile -t intellifim-anomaly-detector:dev .
```

Expected: build succeeds; final layers run `python -m anomaly.train` and produce `/app/model.pkl`. Image size ~400-700 MB (sklearn + numpy add ~200 MB on top of slim).

### Step 6: Sanity-check image runs (exits fast — no Kafka)

```bash
docker run --rm \
    -e KAFKA_BOOTSTRAP=does-not-exist:9092 \
    intellifim-anomaly-detector:dev || true
```

Expected: container logs `starting anomaly-detector in=events.normalized out=events.scored model=isolation-forest-v1 threshold=0.500` BEFORE the Kafka connection error. The presence of that startup line is the success criterion — it confirms the model loaded and the drift guard passed.

### Step 7: Stage

```bash
git add data-plane/anomaly/src/anomaly/__main__.py \
        data-plane/anomaly/Dockerfile \
        data-plane/anomaly/.dockerignore
```

> Suggested commit: `feat(anomaly): add Docker entry point and image (with build-time training)`

---

## Task 10: Add `events.scored` topic to `create-topics.sh`

**Files:**
- Modify: `data-plane/scripts/create-topics.sh`

### Step 1: Edit the script

Find the `events.correlated` block and add `events.scored` after it. The current ending is:

```bash
# Correlated topic
create_topic events.correlated 6 $((14 * 24 * 60 * 60 * 1000))

echo "all topics created"
```

Replace with:

```bash
# Correlated topic
create_topic events.correlated 6 $((14 * 24 * 60 * 60 * 1000))

# Scored topic
create_topic events.scored 6 $((14 * 24 * 60 * 60 * 1000))

echo "all topics created"
```

### Step 2: Bash-syntax check

```bash
bash -n data-plane/scripts/create-topics.sh && echo "syntax OK"
```

Expected: prints `syntax OK`.

### Step 3: Stage

```bash
git add data-plane/scripts/create-topics.sh
```

> Suggested commit: `feat(scripts): add events.scored topic to create-topics.sh`

---

## Task 11: Wire `anomaly-detector` into Compose

**Files:**
- Modify: `data-plane/docker-compose.yml`

### Step 1: Append the new service

After the last service block (`correlation-engine`) and BEFORE the `volumes:` block, append:

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

Indent the service name with 2 spaces (matches the surrounding `correlation-engine` block).

### Step 2: Verify Compose validates

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane config -q
```

Expected: no output (success).

### Step 3: Bring up the stack

```bash
docker compose --env-file .env.dataplane up -d
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 90
```

### Step 4: Confirm the anomaly-detector is running and consuming

```bash
docker ps --filter name=anomaly-detector --format '{{.Status}}'
docker logs anomaly-detector 2>&1 | tail -10
```

Expected:
- Container status: `Up ...`
- Logs include `starting anomaly-detector in=events.normalized out=events.scored model=isolation-forest-v1 threshold=0.500`
- Logs include aiokafka lines like `Discovered coordinator for group anomaly-detector` and `Setting newly assigned partitions {... 6 partitions ...} for group anomaly-detector`

### Step 5: Bring down (KEEP volumes)

```bash
docker compose --env-file .env.dataplane down
```

### Step 6: Stage

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/docker-compose.yml
```

> Suggested commit: `feat(compose): wire anomaly-detector into the data-plane stack`

---

## Task 12: `tail-scored.py` consumer + first end-to-end scoring test

**Files:**
- Create: `data-plane/scripts/tail-scored.py`

### Step 1: Write the script

```python
#!/usr/bin/env python3
# data-plane/scripts/tail-scored.py
"""Subscribe to events.scored and pretty-print ScoredEvents.

Usage:
    pip install -e data-plane/schemas
    pip install aiokafka
    python data-plane/scripts/tail-scored.py [--bootstrap localhost:9094]
"""
from __future__ import annotations

import argparse
import asyncio
import json

from aiokafka import AIOKafkaConsumer

from intellifim_schemas import ScoredEvent


async def _tail(bootstrap: str) -> None:
    consumer = AIOKafkaConsumer(
        "events.scored",
        bootstrap_servers=bootstrap,
        group_id=None,
        auto_offset_reset="latest",
    )
    await consumer.start()
    try:
        async for msg in consumer:
            try:
                se = ScoredEvent.model_validate_json(msg.value)
            except Exception as exc:  # noqa: BLE001
                print(f"INVALID: {exc}\n  raw={msg.value[:200]!r}")
                continue
            line = json.dumps(
                {
                    "ts": se.scored_at.isoformat(),
                    "host": se.host_id,
                    "model": se.model_version,
                    "score": round(se.anomaly_score, 4),
                    "is_anomaly": se.is_anomaly,
                    "threshold": se.threshold,
                    "source_event": {
                        "event_type": se.source_event.event_type,
                        "source": se.source_event.source,
                    },
                },
                separators=(",", ":"),
            )
            print(line)
    finally:
        await consumer.stop()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap", default="localhost:9094")
    args = parser.parse_args()
    asyncio.run(_tail(args.bootstrap))


if __name__ == "__main__":
    main()
```

### Step 2: Make executable

```bash
chmod +x data-plane/scripts/tail-scored.py
```

### Step 3: Smoke-test end-to-end

Bring up the full stack:

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane up -d
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 90
```

Run the tail script in the background, then seed traffic:

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
python /home/aditya/Documents/IntelliFIM/data-plane/scripts/tail-scored.py --bootstrap localhost:9094 > /tmp/tail-scored.log 2>&1 &
TAIL_PID=$!
sleep 5
./scripts/seed-test-traffic.sh
sleep 30
kill $TAIL_PID 2>/dev/null || true
echo "---tail output (first 5 lines)---"
head -5 /tmp/tail-scored.log
echo "---count---"
wc -l /tmp/tail-scored.log
```

**Expected:** at least one JSON line showing a ScoredEvent with `"model":"isolation-forest-v1"`, `"host":"001"`, `"score"` between 0 and 1, and a `"source_event"` from one of the active sources (most likely `zeek.*` because of the constant curl loop).

If empty (tail subscription timing missed early scores), confirm via direct topic read:

```bash
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic events.scored \
    --from-beginning --max-messages 10 --timeout-ms 30000 \
    2>/dev/null | grep -c '"model_version":"isolation-forest-v1"'
```

Expected: ≥1.

If both report 0, troubleshoot:
- `docker logs anomaly-detector --tail 30` — is the consumer joining and getting partition assignments?
- `docker exec kafka /opt/bitnami/kafka/bin/kafka-consumer-groups.sh --bootstrap-server kafka:9092 --describe --group anomaly-detector` — is LAG dropping to 0?
- Confirm normalizers are still producing: `docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh --bootstrap-server kafka:9092 --topic events.normalized --from-beginning --max-messages 5 --timeout-ms 10000 2>/dev/null | wc -l`

### Step 4: Cleanup

```bash
rm -f /tmp/tail-scored.log
find /home/aditya/Documents/IntelliFIM/data-plane/monitored -maxdepth 1 -name 'seed-*' -type d -exec rm -rf {} + 2>/dev/null
docker compose --env-file .env.dataplane down
```

### Step 5: Stage

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/scripts/tail-scored.py
```

> Suggested commit: `feat(scripts): add tail-scored.py consumer for events.scored`

---

## Task 13: README + final fresh-checkout smoke test

**Files:**
- Modify: `data-plane/README.md` (4 changes — service count, anomaly bullet, "See anomaly scores" section, DoD #7)

### Step 1: Update `data-plane/README.md`

**Change A:** in the "What's in the box" section, replace `16 services on Docker Compose:` with `17 services on Docker Compose:`.

**Change B:** in the bulleted service list, INSERT a new bullet AFTER the `**Correlation:** ...` line and BEFORE the `**Normalizers:** ...` line:

```markdown
- **Anomaly detection:** `anomaly-detector` (per-event IsolationForest scoring, see [anomaly/](anomaly/))
```

**Change C:** INSERT a new section AFTER the existing "See correlations" section and BEFORE the "Consume canonical events from a downstream service" section:

```markdown
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
```

**Change D:** APPEND a 7th item to the "Definition of done (v1)" section, after item 6:

```markdown
7. `python scripts/tail-scored.py` prints at least one `ScoredEvent` after
   running `./scripts/seed-test-traffic.sh` (or `kafka-console-consumer` on
   `events.scored` finds ≥1 message with `"model_version":"isolation-forest-v1"`).
```

### Step 2: Final fresh-checkout smoke test

Wipe everything and follow the README from scratch:

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane down -v 2>/dev/null || true
docker rmi intellifim-normalizer:dev intellifim-correlator:dev intellifim-anomaly-detector:dev 2>/dev/null || true

# README's bring-up steps + new anomaly-detector image
docker build -f normalizers/Dockerfile -t intellifim-normalizer:dev .
docker build -f correlator/Dockerfile -t intellifim-correlator:dev .
docker build -f anomaly/Dockerfile -t intellifim-anomaly-detector:dev .

docker compose --env-file .env.dataplane up -d
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 120   # cold Wazuh enrollment takes longer than warm restart
```

Verify all 7 DoD items:

```bash
# DoD #1: services healthy (17 expected)
docker compose --env-file .env.dataplane ps

# DoD #2-#3: FIM + zeek events on events.normalized
echo "smoke-anomaly-$(date +%s)" > monitored/smoke.txt
sleep 30
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic events.normalized \
    --from-beginning --max-messages 100 --timeout-ms 30000 > /tmp/normalized.txt 2>/dev/null
echo "normalized: $(wc -l < /tmp/normalized.txt) lines"
echo "wazuh.fim: $(grep -c '"source":"wazuh.fim"' /tmp/normalized.txt)"
echo "zeek.*: $(grep -c '"source":"zeek' /tmp/normalized.txt)"

# DoD #4: pcap replay
./scripts/replay-pcap.sh pcaps/http_get_basic.pcap
sleep 10

# DoD #5: unit tests (three pytest invocations due to conftest collision)
cd /home/aditya/Documents/IntelliFIM
source .venv/bin/activate
pytest --import-mode=importlib data-plane/schemas/tests data-plane/normalizers/tests
pytest --import-mode=importlib data-plane/correlator/tests
pytest --import-mode=importlib data-plane/anomaly/tests
# Expected totals: ~64 + 20 + 24 = ~108 passed

# DoD #6: correlations
cd /home/aditya/Documents/IntelliFIM/data-plane
./scripts/seed-test-traffic.sh
sleep 60
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic events.correlated \
    --from-beginning --max-messages 5 --timeout-ms 30000 > /tmp/correlated.txt 2>/dev/null
echo "correlations: $(wc -l < /tmp/correlated.txt) lines"
echo "file_with_network: $(grep -c '"correlation_type":"file_with_network"' /tmp/correlated.txt)"

# DoD #7: anomaly scores
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic events.scored \
    --from-beginning --max-messages 10 --timeout-ms 30000 > /tmp/scored.txt 2>/dev/null
echo "scored: $(wc -l < /tmp/scored.txt) lines"
echo "isolation-forest-v1: $(grep -c '"model_version":"isolation-forest-v1"' /tmp/scored.txt)"
```

Expected: all 7 DoD items pass; ≥1 `ScoredEvent` with `"model_version":"isolation-forest-v1"`.

### Step 3: Cleanup smoke artifacts

```bash
rm -f /home/aditya/Documents/IntelliFIM/data-plane/monitored/smoke.txt
rm -f /tmp/normalized.txt /tmp/correlated.txt /tmp/scored.txt
find /home/aditya/Documents/IntelliFIM/data-plane/monitored -maxdepth 1 -name 'seed-*' -type d -exec rm -rf {} + 2>/dev/null
docker compose --env-file .env.dataplane down
```

(NOT `down -v` — keep volumes for user's next session.)

### Step 4: Stage

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/README.md
```

> Suggested commit: `docs(data-plane): document anomaly-detector and add DoD #7`

### Step 5: User opens PR

After all task commits are pushed (the user pushes the branch + opens the PR, per established workflow):

```bash
git push -u origin feat/ml-platform-v1
gh pr create --title "feat: ML platform v1 (anomaly detector walking skeleton)" --body "$(cat <<'EOF'
## Summary
Implements ML platform v1 per [docs/superpowers/specs/2026-05-17-ml-platform-v1-design.md](docs/superpowers/specs/2026-05-17-ml-platform-v1-design.md).

- Adds `ScoredEvent` schema (intellifim-schemas 0.2.0 → 0.3.0).
- New `intellifim-anomaly` Python package: `features.py` (23-feature stateless extractor) + `train.py` (deterministic IsolationForest training) + `engine.py` (consume → score → publish with drift guard).
- New Compose service `anomaly-detector` consuming `events.normalized`, producing `events.scored`. Stack grows from 16 → 17 services.
- Training runs as a Docker build step from a bundled ~N-event JSONL corpus; image version === model version.
- `tail-scored.py` consumer for observability.

## Test plan
- [x] `pytest --import-mode=importlib data-plane/schemas/tests data-plane/normalizers/tests` (26 + 38 = 64 passed).
- [x] `pytest --import-mode=importlib data-plane/correlator/tests` (20 passed).
- [x] `pytest --import-mode=importlib data-plane/anomaly/tests` (23 passed).
- [x] `seed-test-traffic.sh` produces ≥1 `ScoredEvent` with `model_version="isolation-forest-v1"` on `events.scored`.
- [x] All 7 DoD items in `data-plane/README.md` pass on a fresh checkout.

## v2 backlog (deferred)
- Feast, MLflow, BentoML (operational ML tooling — solve problems we don't have yet)
- PyTorch LSTM / River / Autoencoders (additional model families)
- SHAP / LIME XAI (the `features` dict on `ScoredEvent` is already structured for this)
- Per-host or per-user models; automated retraining; threshold calibration; A/B model deployment; drift detection

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review (run by plan author)

**1. Spec coverage**

| Spec section | Implementing task(s) |
|---|---|
| §1 Purpose | Tasks 1-13 collectively |
| §2 Scope (walking skeleton only) | Reflected in plan opening + Task 5 / Task 9 (only IF, no other models) |
| §3 Out of scope | Verified no task implements Feast / MLflow / BentoML / LSTM / SHAP |
| §4 Architecture overview | Tasks 9-11 (Dockerfile, compose service, topic) |
| §5 events.scored topic config | Task 10 (6 partitions, 14d retention) |
| §6 ScoredEvent schema | Task 1 |
| §7 Feature extractor | Task 3 |
| §8 Training workflow (capture → commit → docker build) | Tasks 6, 7, 9 |
| §9 Inference service (engine, config, error handling, drift guard) | Tasks 4, 8, 9 |
| §10 Test strategy | Tasks 1, 3, 4, 5, 8 (29 unit tests); Task 12 (E2E smoke) |
| §11 DoD (7 items) | Task 13 verifies all 7 |
| §12 Patterns continued from #1 + #2 | Consistent throughout (dual-mode extract, log-and-skip, time injection, range pins) |
| §13 v2 deferrals | Listed in PR body (Task 13 Step 5) |

**2. No placeholders**

No "TBD", "implement later", "add error handling", or skeleton-only steps. Every code block is complete and copy-pasteable. The single "~N events" placeholder in Task 7's suggested commit message is intentional — the implementer fills in the actual line count after the capture finishes.

**3. Type / method consistency**

- `AnomalyEngine.__init__` signature `(consumer, producer, output_topic, model, feature_names, model_version, threshold, now=...)` — used identically in Tasks 8, 9.
- `AnomalyConfig` fields `bootstrap_servers, consumer_group, threshold, model_path, input_topic, output_topic` — Tasks 4, 9.
- Topic names `events.normalized` (input) and `events.scored` (output) — Tasks 4, 9, 10, 11, 12.
- Consumer group `anomaly-detector` — Tasks 4, 11.
- Schema package version `0.3.0` — Tasks 1, 2.
- Model version literal `isolation-forest-v1` — Tasks 1, 5, 9, 13.
- Threshold default `0.5` — Tasks 4, 9, 11.

All consistent.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-05-17-ml-platform-v1.md`.** Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, two-stage review between tasks (spec compliance + code quality), user commits at each boundary.

**2. Inline Execution** — Execute tasks in this session using `superpowers:executing-plans`, batch execution with checkpoints for review.

Per the pattern established in sub-projects #1 and #2, Subagent-Driven is the right choice.

When ready to execute, the controller will: commit this plan to main alongside the spec, create branch `feat/ml-platform-v1` off main, then start dispatching Task 1.
