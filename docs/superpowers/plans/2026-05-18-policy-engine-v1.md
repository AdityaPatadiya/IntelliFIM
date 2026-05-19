# Policy & Scoring v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a single Python service `policy-engine` to the data-plane stack that consumes `events.scored`, queries an OPA sidecar for a per-event `score_delta`, maintains a per-host sliding-window threat score in Redis, and publishes a `ThreatScoreUpdate` to a new Kafka topic `threat.scores`.

**Architecture:** New Python package `intellifim-policy` at `data-plane/policy/` (mirrors anomaly/correlator/normalizers shape). Two new infrastructure containers (`opa` for policy evaluation, `redis` for sliding-window state). One new Pydantic schema `ThreatScoreUpdate` in `intellifim-schemas` (bumps to 0.4.0). One Rego policy file mapping `(anomaly_score, is_anomaly) → score_delta + reason`, tested via `opa test`. Same offset-commit, log-and-skip, dual-mode `_extract_event` patterns as siblings.

**Tech Stack:** Python 3.12, Pydantic v2, aiokafka, httpx (OPA REST client), redis-py 5.x (asyncio), pytest, fakeredis, respx, Docker Compose, OPA `openpolicyagent/opa:latest`, Redis `redis:7-alpine`. NO Sigma / MISP / Keycloak / Postgres in v1 — all deferred to v2.

**Reference spec:** [`docs/superpowers/specs/2026-05-18-policy-engine-v1-design.md`](../specs/2026-05-18-policy-engine-v1-design.md)

**Reference for patterns:** Mirror the anomaly-detector at `data-plane/anomaly/` — `AnomalyEngine` → `PolicyEngine`, same Dockerfile / config / __main__ / test shape. Differences: no model artifact (replaced by Rego policy mounted into OPA); two external clients (OPA HTTP + Redis async); two infra dependencies in Compose.

**Branch:** Create `feat/policy-engine-v1` off `main` before Task 1.

---

## File Map

```
data-plane/
├── schemas/
│   └── src/intellifim_schemas/
│       ├── policy.py                              ← NEW (ThreatScoreUpdate)
│       └── __init__.py                            ← MODIFY (re-export ThreatScoreUpdate)
│   ├── pyproject.toml                             ← MODIFY (version 0.3.0 → 0.4.0)
│   └── tests/test_policy.py                       ← NEW (6 tests)
│
├── policy/                                        ← NEW package
│   ├── pyproject.toml
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── README.md
│   ├── policies/
│   │   ├── threat_score.rego                      ← NEW (Rego policy)
│   │   └── threat_score_test.rego                 ← NEW (5 Rego tests via `opa test`)
│   ├── src/policy/
│   │   ├── __init__.py                            (empty)
│   │   ├── __main__.py                            (entry point)
│   │   ├── config.py                              (PolicyConfig)
│   │   ├── opa_client.py                          (OpaClient, httpx wrapper)
│   │   ├── redis_store.py                         (RedisScoreStore, redis-py async wrapper)
│   │   └── engine.py                              (PolicyEngine)
│   └── tests/
│       ├── __init__.py                            (empty)
│       ├── conftest.py                            (make_scored_event fixture)
│       ├── test_config.py                         (5 tests)
│       ├── test_opa_client.py                     (5 tests, respx)
│       ├── test_redis_store.py                    (6 tests, fakeredis)
│       └── test_engine.py                         (7 tests)
│
├── docker-compose.yml                             ← MODIFY (add opa + redis + policy-engine)
├── scripts/
│   ├── create-topics.sh                           ← MODIFY (add threat.scores)
│   └── tail-scores.py                             ← NEW (host-side consumer)
└── README.md                                      ← MODIFY (service count, policy section, DoD #8)
```

**12 tasks total. ~32 new Python tests (6 schemas + 5 config + 6 opa_client + 6 redis_store + 9 engine) + ~5 Rego tests + 1 end-to-end smoke test.**

---

## Task 1: `ThreatScoreUpdate` schema (TDD)

**Files:**
- Create: `data-plane/schemas/src/intellifim_schemas/policy.py`
- Create: `data-plane/schemas/tests/test_policy.py`
- Modify: `data-plane/schemas/src/intellifim_schemas/__init__.py` (re-export new type)
- Modify: `data-plane/schemas/pyproject.toml` (bump `version = "0.3.0"` → `"0.4.0"`)

### Step 1: Write the failing tests

Create `data-plane/schemas/tests/test_policy.py`:

```python
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from intellifim_schemas import ThreatScoreUpdate


def _base_payload() -> dict:
    return {
        "update_id": str(uuid4()),
        "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        "host_id": "host-001",
        "score": 42.5,
        "window_seconds": 300,
        "contributions_in_window": 7,
        "last_event_id": str(uuid4()),
        "last_score_delta": 10,
        "last_reason": "moderate anomaly",
    }


def test_threat_score_update_basic_roundtrip():
    event = ThreatScoreUpdate(
        update_id=uuid4(),
        computed_at=datetime(2026, 5, 18, 12, 0, 0, tzinfo=timezone.utc),
        host_id="host-001",
        score=42.5,
        window_seconds=300,
        contributions_in_window=7,
        last_event_id=uuid4(),
        last_score_delta=10,
        last_reason="moderate anomaly",
    )
    rebuilt = ThreatScoreUpdate.model_validate_json(event.model_dump_json())
    assert rebuilt == event


def test_threat_score_update_rejects_unknown_field():
    payload = _base_payload()
    payload["mystery_field"] = "boom"
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)


def test_threat_score_update_rejects_score_out_of_range():
    payload = _base_payload()
    payload["score"] = 100.01
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)
    payload["score"] = -0.01
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)


def test_threat_score_update_rejects_last_score_delta_out_of_range():
    payload = _base_payload()
    payload["last_score_delta"] = 101
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)
    payload["last_score_delta"] = -1
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)


def test_threat_score_update_rejects_non_positive_window():
    payload = _base_payload()
    payload["window_seconds"] = 0
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)
    payload["window_seconds"] = -10
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)


def test_threat_score_update_rejects_naive_computed_at():
    payload = _base_payload()
    payload["computed_at"] = datetime(2026, 5, 18, 12, 0, 0).isoformat()
    with pytest.raises(ValidationError):
        ThreatScoreUpdate.model_validate(payload)
```

### Step 2: Run tests, confirm they fail

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
pytest --import-mode=importlib data-plane/schemas/tests/test_policy.py -v
```

Expected: ImportError on `ThreatScoreUpdate`.

### Step 3: Implement the schema

Create `data-plane/schemas/src/intellifim_schemas/policy.py`:

```python
"""Policy / scoring schema for IntelliFIM.

Emitted by the policy-engine service onto the `threat.scores` Kafka topic.
Each ThreatScoreUpdate carries the per-host sliding-window threat score
plus enough context (last triggering event, last OPA decision) for
downstream consumers (response orchestrator, dashboard) to act without
joining other topics.
"""
from __future__ import annotations

from typing import Annotated
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeInt,
    PositiveInt,
)


class ThreatScoreUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    update_id: UUID
    computed_at: AwareDatetime
    host_id: str

    score: Annotated[float, Field(ge=0.0, le=100.0)]
    window_seconds: PositiveInt
    contributions_in_window: NonNegativeInt

    last_event_id: UUID
    last_score_delta: Annotated[int, Field(ge=0, le=100)]
    last_reason: str
```

### Step 4: Update `__init__.py`

Replace `data-plane/schemas/src/intellifim_schemas/__init__.py` with:

```python
from intellifim_schemas.correlation import CorrelatedEvent, CorrelationType
from intellifim_schemas.event import CanonicalEvent, EventType, Source
from intellifim_schemas.policy import ThreatScoreUpdate
from intellifim_schemas.scoring import ModelVersion, ScoredEvent

__all__ = [
    "CanonicalEvent",
    "CorrelatedEvent",
    "CorrelationType",
    "EventType",
    "ModelVersion",
    "ScoredEvent",
    "Source",
    "ThreatScoreUpdate",
]
```

### Step 5: Bump version

In `data-plane/schemas/pyproject.toml`, change `version = "0.3.0"` to `version = "0.4.0"`.

### Step 6: Reinstall and run all schemas tests

```bash
pip install -e data-plane/schemas[dev]
pytest --import-mode=importlib data-plane/schemas/tests -v
```

Expected: 26 existing (14 event + 6 correlation + 6 scoring) + 6 new policy = **32 passed**.

### Step 7: Stage (DO NOT COMMIT)

```bash
git add data-plane/schemas/src/intellifim_schemas/policy.py \
        data-plane/schemas/src/intellifim_schemas/__init__.py \
        data-plane/schemas/tests/test_policy.py \
        data-plane/schemas/pyproject.toml
```

> Suggested commit: `feat(schemas): add ThreatScoreUpdate and bump intellifim-schemas to 0.4.0`

---

## Task 2: Bootstrap `intellifim-policy` package

**Files:**
- Create: `data-plane/policy/pyproject.toml`
- Create: `data-plane/policy/README.md`
- Create: `data-plane/policy/src/policy/__init__.py`
- Create: `data-plane/policy/tests/__init__.py`
- Create: `data-plane/policy/tests/conftest.py`

### Step 1: Create `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "intellifim-policy"
version = "0.1.0"
description = "Policy + dynamic threat scoring service for IntelliFIM"
requires-python = ">=3.12"
dependencies = [
    "intellifim-schemas>=0.4,<1.0",
    "aiokafka>=0.10,<0.12",
    "pydantic>=2.7,<3",
    "httpx>=0.27,<0.29",
    "redis>=5.0,<6",
]

[project.optional-dependencies]
dev = [
    "pytest>=8,<9",
    "pytest-asyncio>=0.23,<0.25",
    "fakeredis>=2.20,<3",
    "respx>=0.21,<0.23",
]

[project.scripts]
intellifim-policy-engine = "policy.__main__:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
```

### Step 2: Create empty package init

```python
# data-plane/policy/src/policy/__init__.py
```

(Empty.)

### Step 3: Create test scaffolding

```python
# data-plane/policy/tests/__init__.py
```

(Empty.)

```python
# data-plane/policy/tests/conftest.py
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from intellifim_schemas import CanonicalEvent, ScoredEvent


@pytest.fixture
def make_scored_event():
    """Factory for ScoredEvent instances with embedded CanonicalEvent. Defaults to a
    wazuh.fim file.modified event scored at 0.6 (moderate anomaly), host-001."""

    def _make(
        *,
        host_id: str = "host-001",
        anomaly_score: float = 0.6,
        is_anomaly: bool | None = None,
        event_type: str = "file.modified",
        source: str = "wazuh.fim",
        threshold: float = 0.5,
    ) -> ScoredEvent:
        if is_anomaly is None:
            is_anomaly = anomaly_score >= threshold
        canonical = CanonicalEvent(
            event_id=uuid4(),
            event_type=event_type,
            source=source,
            timestamp=datetime(2026, 5, 18, 12, 0, 0, tzinfo=timezone.utc),
            ingest_timestamp=datetime.now(tz=timezone.utc),
            host_id=host_id,
        )
        return ScoredEvent(
            score_id=uuid4(),
            scored_at=datetime.now(tz=timezone.utc),
            model_version="isolation-forest-v1",
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            threshold=threshold,
            host_id=host_id,
            source_event=canonical,
            features={"hour_of_day": 12.0, "src_port": 0.0},
        )

    return _make
```

### Step 4: Create README

```markdown
# intellifim-policy

Policy + dynamic threat scoring service. Consumes `events.scored`, queries
an OPA sidecar for a per-event `score_delta`, maintains a per-host
sliding-window threat score in Redis, and publishes `ThreatScoreUpdate`
to `threat.scores`.

Install for development:

    pip install -e data-plane/schemas
    pip install -e data-plane/policy[dev]

Run Python tests:

    pytest --import-mode=importlib data-plane/policy/tests

Run Rego policy tests (requires `opa` CLI or Docker):

    opa test data-plane/policy/policies/
    # OR
    docker run --rm -v $(pwd)/data-plane/policy/policies:/p \
        openpolicyagent/opa:latest test /p
```

### Step 5: Install and verify

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
pip install -e data-plane/policy[dev]
python -c "import policy; print(policy.__file__)"
```

Expected: prints `/home/aditya/Documents/IntelliFIM/data-plane/policy/src/policy/__init__.py`.

### Step 6: Stage

```bash
git add data-plane/policy/pyproject.toml \
        data-plane/policy/README.md \
        data-plane/policy/src/policy/__init__.py \
        data-plane/policy/tests/__init__.py \
        data-plane/policy/tests/conftest.py
```

> Suggested commit: `feat(policy): bootstrap intellifim-policy package`

---

## Task 3: Rego policy + Rego tests

**Files:**
- Create: `data-plane/policy/policies/threat_score.rego`
- Create: `data-plane/policy/policies/threat_score_test.rego`

### Step 1: Write the Rego policy

Create `data-plane/policy/policies/threat_score.rego`:

```rego
package intellifim.policy

# Default: benign event
default decision := {"score_delta": 0, "reason": "benign event"}

# Strong anomaly (score >= 0.7 wins regardless of is_anomaly flag)
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

### Step 2: Write the Rego tests

Create `data-plane/policy/policies/threat_score_test.rego`:

```rego
package intellifim.policy

test_benign_event_returns_zero if {
    d := decision with input as {"event": {"anomaly_score": 0.1, "is_anomaly": false}}
    d == {"score_delta": 0, "reason": "benign event"}
}

test_weak_anomaly_returns_five if {
    d := decision with input as {"event": {"anomaly_score": 0.4, "is_anomaly": false}}
    d.score_delta == 5
    d.reason == "weak anomaly (score 0.3-0.5)"
}

test_moderate_anomaly_returns_ten if {
    d := decision with input as {"event": {"anomaly_score": 0.6, "is_anomaly": true}}
    d.score_delta == 10
    d.reason == "moderate anomaly"
}

test_strong_anomaly_returns_twenty_five if {
    d := decision with input as {"event": {"anomaly_score": 0.85, "is_anomaly": true}}
    d.score_delta == 25
    d.reason == "strong anomaly (score >= 0.7)"
}

test_high_score_with_is_anomaly_false_still_strong if {
    # score >= 0.7 wins regardless of is_anomaly flag
    d := decision with input as {"event": {"anomaly_score": 0.9, "is_anomaly": false}}
    d.score_delta == 25
}
```

### Step 3: Run the Rego tests

```bash
docker run --rm -v /home/aditya/Documents/IntelliFIM/data-plane/policy/policies:/p \
    openpolicyagent/opa:latest test /p
```

Expected: `PASS: 5/5` (5 tests pass).

If you have the `opa` CLI on the host, you can also run:
```bash
opa test data-plane/policy/policies/
```

### Step 4: Stage

```bash
git add data-plane/policy/policies/threat_score.rego \
        data-plane/policy/policies/threat_score_test.rego
```

> Suggested commit: `feat(policy): add threat_score Rego policy with 5 unit tests`

---

## Task 4: `PolicyConfig` (TDD)

**Files:**
- Create: `data-plane/policy/src/policy/config.py`
- Create: `data-plane/policy/tests/test_config.py`

### Step 1: Write the failing tests

```python
# data-plane/policy/tests/test_config.py
import pytest

from policy.config import INPUT_TOPIC, OUTPUT_TOPIC, PolicyConfig


def test_input_topic_constant():
    assert INPUT_TOPIC == "events.scored"


def test_output_topic_constant():
    assert OUTPUT_TOPIC == "threat.scores"


def test_from_env_with_defaults(monkeypatch):
    for k in ("KAFKA_BOOTSTRAP", "CONSUMER_GROUP", "OPA_URL", "REDIS_URL", "THREAT_SCORE_WINDOW_SECONDS"):
        monkeypatch.delenv(k, raising=False)
    cfg = PolicyConfig.from_env()
    assert cfg.bootstrap_servers == "kafka:9092"
    assert cfg.consumer_group == "policy-engine"
    assert cfg.opa_url == "http://opa:8181"
    assert cfg.redis_url == "redis://redis:6379/0"
    assert cfg.window_seconds == 300
    assert cfg.input_topic == "events.scored"
    assert cfg.output_topic == "threat.scores"


def test_from_env_overrides(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka.example.com:19092")
    monkeypatch.setenv("CONSUMER_GROUP", "policy-staging")
    monkeypatch.setenv("OPA_URL", "http://opa.example.com:8181")
    monkeypatch.setenv("REDIS_URL", "redis://redis.example.com:6379/1")
    monkeypatch.setenv("THREAT_SCORE_WINDOW_SECONDS", "600")
    cfg = PolicyConfig.from_env()
    assert cfg.bootstrap_servers == "kafka.example.com:19092"
    assert cfg.consumer_group == "policy-staging"
    assert cfg.opa_url == "http://opa.example.com:8181"
    assert cfg.redis_url == "redis://redis.example.com:6379/1"
    assert cfg.window_seconds == 600


def test_from_env_rejects_invalid_window(monkeypatch):
    for bad in ("0", "-10", "abc"):
        monkeypatch.setenv("THREAT_SCORE_WINDOW_SECONDS", bad)
        with pytest.raises(ValueError, match="THREAT_SCORE_WINDOW_SECONDS"):
            PolicyConfig.from_env()
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/policy/tests/test_config.py -v
```

Expected: ImportError on `policy.config`.

### Step 3: Implement `config.py`

```python
# data-plane/policy/src/policy/config.py
from __future__ import annotations

import os
from dataclasses import dataclass

INPUT_TOPIC = "events.scored"
OUTPUT_TOPIC = "threat.scores"


@dataclass(frozen=True)
class PolicyConfig:
    bootstrap_servers: str
    consumer_group: str
    opa_url: str
    redis_url: str
    window_seconds: int
    input_topic: str = INPUT_TOPIC
    output_topic: str = OUTPUT_TOPIC

    @classmethod
    def from_env(cls) -> "PolicyConfig":
        raw = os.environ.get("THREAT_SCORE_WINDOW_SECONDS", "300")
        try:
            window = int(raw)
        except ValueError as exc:
            raise ValueError(
                f"THREAT_SCORE_WINDOW_SECONDS must be a positive integer, got {raw!r}"
            ) from exc
        if window <= 0:
            raise ValueError(
                f"THREAT_SCORE_WINDOW_SECONDS must be a positive integer, got {window}"
            )
        return cls(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092"),
            consumer_group=os.environ.get("CONSUMER_GROUP", "policy-engine"),
            opa_url=os.environ.get("OPA_URL", "http://opa:8181"),
            redis_url=os.environ.get("REDIS_URL", "redis://redis:6379/0"),
            window_seconds=window,
        )
```

### Step 4: Run tests, confirm 5 pass

```bash
pytest --import-mode=importlib data-plane/policy/tests/test_config.py -v
```

Expected: **5 passed**.

### Step 5: Stage

```bash
git add data-plane/policy/src/policy/config.py \
        data-plane/policy/tests/test_config.py
```

> Suggested commit: `feat(policy): add PolicyConfig with env-var parsing`

---

## Task 5: `OpaClient` (TDD with respx)

**Files:**
- Create: `data-plane/policy/src/policy/opa_client.py`
- Create: `data-plane/policy/tests/test_opa_client.py`

### Step 1: Write the failing tests

```python
# data-plane/policy/tests/test_opa_client.py
import httpx
import pytest
import respx

from policy.opa_client import OpaClient


_OPA_URL = "http://opa:8181"
_QUERY_PATH = "/v1/data/intellifim/policy/decision"


async def test_opa_client_happy_path(make_scored_event):
    event = make_scored_event(anomaly_score=0.85)
    with respx.mock(base_url=_OPA_URL) as router:
        router.post(_QUERY_PATH).respond(
            200, json={"result": {"score_delta": 25, "reason": "strong anomaly"}}
        )
        client = OpaClient(_OPA_URL)
        try:
            result = await client.query(event)
        finally:
            await client.aclose()
        assert result == {"score_delta": 25, "reason": "strong anomaly"}


async def test_opa_client_returns_none_on_timeout(make_scored_event):
    event = make_scored_event()
    with respx.mock(base_url=_OPA_URL) as router:
        router.post(_QUERY_PATH).mock(side_effect=httpx.TimeoutException("timed out"))
        client = OpaClient(_OPA_URL, timeout_seconds=0.5)
        try:
            assert await client.query(event) is None
        finally:
            await client.aclose()


async def test_opa_client_returns_none_on_4xx(make_scored_event):
    event = make_scored_event()
    with respx.mock(base_url=_OPA_URL) as router:
        router.post(_QUERY_PATH).respond(404, json={"error": "not found"})
        client = OpaClient(_OPA_URL)
        try:
            assert await client.query(event) is None
        finally:
            await client.aclose()


async def test_opa_client_returns_none_on_5xx(make_scored_event):
    event = make_scored_event()
    with respx.mock(base_url=_OPA_URL) as router:
        router.post(_QUERY_PATH).respond(500, json={"error": "server error"})
        client = OpaClient(_OPA_URL)
        try:
            assert await client.query(event) is None
        finally:
            await client.aclose()


async def test_opa_client_returns_none_on_malformed_response(make_scored_event):
    event = make_scored_event()
    with respx.mock(base_url=_OPA_URL) as router:
        # Missing the wrapping "result" key
        router.post(_QUERY_PATH).respond(200, json={"score_delta": 25})
        client = OpaClient(_OPA_URL)
        try:
            assert await client.query(event) is None
        finally:
            await client.aclose()


async def test_opa_client_returns_none_on_non_json_body(make_scored_event):
    event = make_scored_event()
    with respx.mock(base_url=_OPA_URL) as router:
        router.post(_QUERY_PATH).respond(
            200, content=b"<html>not json</html>",
            headers={"content-type": "text/html"},
        )
        client = OpaClient(_OPA_URL)
        try:
            assert await client.query(event) is None
        finally:
            await client.aclose()
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/policy/tests/test_opa_client.py -v
```

Expected: ImportError on `policy.opa_client`.

### Step 3: Implement `opa_client.py`

```python
# data-plane/policy/src/policy/opa_client.py
"""Async HTTP client for OPA's REST API.

Returns the OPA decision dict on success, or None (logged) on any failure
mode (transport error, timeout, 4xx, 5xx, malformed response). The engine
treats None as 'skip this event' — never crash the loop.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from intellifim_schemas import ScoredEvent

log = logging.getLogger(__name__)

_QUERY_PATH = "/v1/data/intellifim/policy/decision"


class OpaClient:
    def __init__(self, opa_url: str, *, timeout_seconds: float = 2.0) -> None:
        self._url = opa_url.rstrip("/") + _QUERY_PATH
        self._client = httpx.AsyncClient(timeout=timeout_seconds)

    async def query(self, event: ScoredEvent) -> dict[str, Any] | None:
        body = {"input": {"event": event.model_dump(mode="json")}}
        try:
            response = await self._client.post(self._url, json=body)
        except httpx.RequestError as exc:
            log.warning("OPA query failed (%s)", exc)
            return None
        if response.status_code != 200:
            log.warning(
                "OPA returned status=%d body=%s", response.status_code, response.text[:200]
            )
            return None
        try:
            payload = response.json()
        except Exception as exc:  # noqa: BLE001 - any parse failure is a skip
            log.warning("OPA returned non-JSON body (%s)", exc)
            return None
        result = payload.get("result")
        if not isinstance(result, dict):
            log.warning("OPA response missing/invalid 'result' key: %s", payload)
            return None
        return result

    async def aclose(self) -> None:
        await self._client.aclose()
```

### Step 4: Run tests, confirm 6 pass

```bash
pytest --import-mode=importlib data-plane/policy/tests/test_opa_client.py -v
```

Expected: **6 passed**.

### Step 5: Stage

```bash
git add data-plane/policy/src/policy/opa_client.py \
        data-plane/policy/tests/test_opa_client.py
```

> Suggested commit: `feat(policy): add OpaClient httpx wrapper with log-and-skip error handling`

---

## Task 6: `RedisScoreStore` (TDD with fakeredis)

**Files:**
- Create: `data-plane/policy/src/policy/redis_store.py`
- Create: `data-plane/policy/tests/test_redis_store.py`

### Step 1: Write the failing tests

```python
# data-plane/policy/tests/test_redis_store.py
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import fakeredis.aioredis
import pytest

from policy.redis_store import RedisScoreStore


_T0 = datetime(2026, 5, 18, 12, 0, 0, tzinfo=timezone.utc)


async def _make_store_with_fake_redis():
    """Construct a RedisScoreStore backed by an in-process fakeredis client."""
    store = RedisScoreStore("redis://localhost:6379/0")
    # Replace the real client with a fakeredis client BEFORE any use.
    await store.aclose()  # close the real client we'll never use
    store._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return store


async def test_append_contribution_persists_in_zset():
    store = await _make_store_with_fake_redis()
    try:
        ok = await store.append_contribution(
            host_id="host-001", ts=_T0, delta=10, event_id=uuid4()
        )
        assert ok is True
        # Verify via the fake client directly
        count = await store._client.zcard("threat_score:host:host-001")
        assert count == 1
    finally:
        await store.aclose()


async def test_current_score_sums_in_window_deltas():
    store = await _make_store_with_fake_redis()
    try:
        await store.append_contribution(host_id="host-001", ts=_T0, delta=10, event_id=uuid4())
        await store.append_contribution(host_id="host-001", ts=_T0 + timedelta(seconds=30), delta=5, event_id=uuid4())
        score, count = await store.current_score(
            host_id="host-001", window_seconds=300, now=_T0 + timedelta(seconds=60),
        )
        assert score == 15.0
        assert count == 2
    finally:
        await store.aclose()


async def test_current_score_excludes_expired_contributions():
    store = await _make_store_with_fake_redis()
    try:
        # Old contribution outside 60s window
        await store.append_contribution(host_id="host-001", ts=_T0, delta=10, event_id=uuid4())
        # Fresh contribution inside 60s window
        await store.append_contribution(
            host_id="host-001", ts=_T0 + timedelta(seconds=80), delta=5, event_id=uuid4(),
        )
        score, count = await store.current_score(
            host_id="host-001", window_seconds=60, now=_T0 + timedelta(seconds=100),
        )
        assert score == 5.0
        assert count == 1
    finally:
        await store.aclose()


async def test_multi_host_isolation():
    store = await _make_store_with_fake_redis()
    try:
        await store.append_contribution(host_id="host-A", ts=_T0, delta=10, event_id=uuid4())
        await store.append_contribution(host_id="host-B", ts=_T0, delta=25, event_id=uuid4())
        score_a, _ = await store.current_score(host_id="host-A", window_seconds=300, now=_T0)
        score_b, _ = await store.current_score(host_id="host-B", window_seconds=300, now=_T0)
        assert score_a == 10.0
        assert score_b == 25.0
    finally:
        await store.aclose()


async def test_current_score_returns_zero_for_unknown_host():
    store = await _make_store_with_fake_redis()
    try:
        score, count = await store.current_score(
            host_id="host-NOPE", window_seconds=300, now=_T0,
        )
        assert score == 0.0
        assert count == 0
    finally:
        await store.aclose()


async def test_append_failure_returns_false(monkeypatch):
    store = await _make_store_with_fake_redis()
    try:
        # Force ZADD to raise by replacing the method
        from redis.exceptions import RedisError

        async def broken_zadd(*args, **kwargs):
            raise RedisError("simulated")

        monkeypatch.setattr(store._client, "zadd", broken_zadd)
        ok = await store.append_contribution(
            host_id="host-X", ts=_T0, delta=10, event_id=uuid4(),
        )
        assert ok is False
    finally:
        await store.aclose()
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/policy/tests/test_redis_store.py -v
```

Expected: ImportError on `policy.redis_store`.

### Step 3: Implement `redis_store.py`

```python
# data-plane/policy/src/policy/redis_store.py
"""Async Redis wrapper for the per-host sliding-window threat score.

Uses a Redis sorted set per host: key=`threat_score:host:<host_id>`,
score=unix timestamp (float), member=JSON `{"delta": N, "event_id": "..."}`.

On every read, expired entries (timestamp < now - window_seconds) are
removed via ZREMRANGEBYSCORE; the current score is the sum of surviving
`delta` fields.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from uuid import UUID

from redis.asyncio import Redis
from redis.exceptions import RedisError

log = logging.getLogger(__name__)


def _host_key(host_id: str) -> str:
    return f"threat_score:host:{host_id}"


class RedisScoreStore:
    def __init__(self, redis_url: str) -> None:
        self._client: Redis = Redis.from_url(redis_url, decode_responses=True)

    async def append_contribution(
        self, *, host_id: str, ts: datetime, delta: int, event_id: UUID,
    ) -> bool:
        key = _host_key(host_id)
        score = ts.timestamp()
        member = json.dumps({"delta": delta, "event_id": str(event_id)})
        try:
            await self._client.zadd(key, {member: score})
        except RedisError as exc:
            log.warning("Redis ZADD failed for %s (%s)", key, exc)
            return False
        return True

    async def current_score(
        self, *, host_id: str, window_seconds: int, now: datetime,
    ) -> tuple[float, int]:
        key = _host_key(host_id)
        cutoff = now.timestamp() - window_seconds
        try:
            await self._client.zremrangebyscore(key, "-inf", f"({cutoff}")
            members = await self._client.zrangebyscore(key, cutoff, "+inf")
        except RedisError as exc:
            log.warning("Redis read failed for %s (%s)", key, exc)
            return (0.0, 0)
        total = 0
        for m in members:
            try:
                total += int(json.loads(m)["delta"])
            except (ValueError, KeyError, TypeError) as exc:
                log.warning("malformed member in %s: %s (%s)", key, m, exc)
        return (float(total), len(members))

    async def aclose(self) -> None:
        await self._client.aclose()
```

### Step 4: Run tests, confirm 6 pass

```bash
pytest --import-mode=importlib data-plane/policy/tests/test_redis_store.py -v
```

Expected: **6 passed**.

### Step 5: Stage

```bash
git add data-plane/policy/src/policy/redis_store.py \
        data-plane/policy/tests/test_redis_store.py
```

> Suggested commit: `feat(policy): add RedisScoreStore with sliding-window zset model`

---

## Task 7: `PolicyEngine` (TDD)

**Files:**
- Create: `data-plane/policy/src/policy/engine.py`
- Create: `data-plane/policy/tests/test_engine.py`

### Step 1: Write the failing tests

```python
# data-plane/policy/tests/test_engine.py
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import fakeredis.aioredis
import pytest

from intellifim_schemas import ThreatScoreUpdate

from policy.engine import PolicyEngine
from policy.opa_client import OpaClient
from policy.redis_store import RedisScoreStore


_T0 = datetime(2026, 5, 18, 12, 0, 0, tzinfo=timezone.utc)


def _now_at(offset: int):
    def _now() -> datetime:
        return _T0 + timedelta(seconds=offset)
    return _now


class FakeConsumer:
    def __init__(self, events: list):
        self._events = list(events)
    def __aiter__(self): return self
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
    def __init__(self, value: bytes | None):
        self.value = value


class FakeOpa:
    def __init__(self, response: dict | None):
        self._response = response
        self.calls = 0
    async def query(self, event):
        self.calls += 1
        return self._response


async def _make_store():
    """RedisScoreStore backed by fakeredis."""
    store = RedisScoreStore("redis://localhost:6379/0")
    await store.aclose()
    store._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return store


async def test_engine_emits_update_on_happy_path(make_scored_event):
    event = make_scored_event(anomaly_score=0.85)
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"score_delta": 25, "reason": "strong anomaly"})
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()

        assert len(producer.published) == 1
        topic, value, key = producer.published[0]
        assert topic == "threat.scores"
        assert key == b"host-001"
        update = ThreatScoreUpdate.model_validate_json(value)
        assert update.host_id == "host-001"
        assert update.score == 25.0
        assert update.contributions_in_window == 1
        assert update.last_score_delta == 25
        assert update.last_reason == "strong anomaly"
        assert update.window_seconds == 300
    finally:
        await store.aclose()


async def test_engine_accepts_scored_event_value_bytes(make_scored_event):
    """Production-realistic path: consumer yields a message with .value bytes."""
    event = make_scored_event()
    consumer = FakeConsumer([FakeMessage(event.model_dump_json().encode("utf-8"))])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"score_delta": 10, "reason": "moderate"})
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert len(producer.published) == 1
        update = ThreatScoreUpdate.model_validate_json(producer.published[0][1])
        assert update.last_event_id == event.source_event.event_id
    finally:
        await store.aclose()


async def test_engine_skips_on_opa_failure(make_scored_event):
    event = make_scored_event()
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa(None)  # OPA returns None
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert producer.published == []
        # And nothing was written to Redis
        count = await store._client.zcard("threat_score:host:host-001")
        assert count == 0
    finally:
        await store.aclose()


async def test_engine_skips_on_redis_append_failure(make_scored_event, monkeypatch):
    event = make_scored_event()
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"score_delta": 5, "reason": "weak"})
    try:
        async def broken_append(*args, **kwargs):
            return False  # simulate Redis error path
        monkeypatch.setattr(store, "append_contribution", broken_append)
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert producer.published == []
    finally:
        await store.aclose()


async def test_engine_drops_malformed_json(make_scored_event):
    consumer = FakeConsumer([
        FakeMessage(b'{"not":"a scored event"}'),
        FakeMessage(None),
    ])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"score_delta": 0, "reason": "benign"})
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert producer.published == []
        assert opa.calls == 0  # OPA was never queried
    finally:
        await store.aclose()


async def test_engine_continues_after_producer_failure(make_scored_event):
    e1 = make_scored_event(anomaly_score=0.85)
    e2 = make_scored_event(anomaly_score=0.4)
    consumer = FakeConsumer([e1, e2])
    store = await _make_store()
    opa = FakeOpa({"score_delta": 5, "reason": "weak"})

    class FlakyProducer:
        def __init__(self):
            self.calls = 0
            self.published: list[Any] = []
        async def send_and_wait(self, topic, value, key=None):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("simulated kafka outage")
            self.published.append((topic, value, key))

    producer = FlakyProducer()
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert producer.calls == 2
        assert len(producer.published) == 1
    finally:
        await store.aclose()


async def test_engine_score_accumulates_across_events(make_scored_event):
    """Two events from same host → score is sum of both deltas."""
    e1 = make_scored_event(anomaly_score=0.85)
    e2 = make_scored_event(anomaly_score=0.6)
    consumer = FakeConsumer([e1, e2])
    producer = FakeProducer()
    store = await _make_store()
    # Return different deltas for each call
    class SequentialOpa:
        def __init__(self):
            self._responses = [
                {"score_delta": 25, "reason": "strong"},
                {"score_delta": 10, "reason": "moderate"},
            ]
        async def query(self, event):
            return self._responses.pop(0)
    opa = SequentialOpa()
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert len(producer.published) == 2
        first = ThreatScoreUpdate.model_validate_json(producer.published[0][1])
        second = ThreatScoreUpdate.model_validate_json(producer.published[1][1])
        assert first.score == 25.0
        assert first.contributions_in_window == 1
        assert second.score == 35.0  # 25 + 10
        assert second.contributions_in_window == 2
    finally:
        await store.aclose()


async def test_engine_skips_on_malformed_opa_decision(make_scored_event):
    """OPA returns a dict missing score_delta → engine logs and skips, no publish, no Redis write."""
    event = make_scored_event()
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"reason": "missing delta"})  # missing score_delta key
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert producer.published == []
        count = await store._client.zcard("threat_score:host:host-001")
        assert count == 0
    finally:
        await store.aclose()


async def test_engine_clamps_out_of_range_score_delta(make_scored_event):
    """OPA returns score_delta=150 (out of [0,100]) → engine clamps to 100, publishes valid update."""
    event = make_scored_event()
    consumer = FakeConsumer([event])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"score_delta": 150, "reason": "overflow tier"})
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )
        await engine.run()
        assert len(producer.published) == 1
        update = ThreatScoreUpdate.model_validate_json(producer.published[0][1])
        assert update.last_score_delta == 100  # clamped from 150
        assert update.score == 100.0  # also clamped by score=min(100, ...) clamp
    finally:
        await store.aclose()
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/policy/tests/test_engine.py -v
```

Expected: ImportError on `policy.engine`.

### Step 3: Implement `engine.py`

```python
# data-plane/policy/src/policy/engine.py
"""PolicyEngine — consume ScoredEvents, query OPA, update Redis, publish ThreatScoreUpdates.

Offset-commit policy: same as data-plane normalizers + correlator + anomaly —
no manual commit; expects the consumer to have enable_auto_commit=True
(aiokafka default). Combined with the log-and-skip error policy in
_safe_publish + OPA/Redis client failures (each returns None / False),
no single bad message or transient external failure can stall a partition.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from uuid import uuid4

from pydantic import ValidationError

from intellifim_schemas import ScoredEvent, ThreatScoreUpdate

from policy.opa_client import OpaClient
from policy.redis_store import RedisScoreStore

log = logging.getLogger(__name__)


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


class _Consumer(Protocol):
    def __aiter__(self) -> "_Consumer": ...
    async def __anext__(self) -> Any: ...


class _Producer(Protocol):
    async def send_and_wait(
        self, topic: str, value: bytes, key: bytes | None = ...
    ) -> Any: ...


class PolicyEngine:
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
    ) -> None:
        self._consumer = consumer
        self._producer = producer
        self._output_topic = output_topic
        self._opa = opa
        self._store = store
        self._window_seconds = window_seconds
        self._now = now

    async def run(self) -> None:
        async for raw_message in self._consumer:
            event = self._extract_event(raw_message)
            if event is None:
                continue
            update = await self._process(event)
            if update is None:
                continue
            await self._safe_publish(update)

    @staticmethod
    def _extract_event(message: Any) -> ScoredEvent | None:
        if isinstance(message, ScoredEvent):
            return message
        value = getattr(message, "value", None)
        if value is None:
            log.warning("dropping message with no value")
            return None
        try:
            return ScoredEvent.model_validate_json(value)
        except ValidationError as exc:
            log.warning("dropping invalid ScoredEvent (%s)", exc)
            return None

    async def _process(self, event: ScoredEvent) -> ThreatScoreUpdate | None:
        decision = await self._opa.query(event)
        if decision is None:
            return None

        try:
            score_delta = int(decision["score_delta"])
            reason = str(decision["reason"])
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("dropping malformed OPA decision %s (%s)", decision, exc)
            return None
        # Clamp to ThreatScoreUpdate.last_score_delta's [0, 100] Field range so
        # an out-of-range Rego value can't raise ValidationError and stall the
        # partition. Mirrors the score=min(100.0, ...) clamp below.
        score_delta = max(0, min(100, score_delta))

        appended = await self._store.append_contribution(
            host_id=event.host_id,
            ts=self._now(),
            delta=score_delta,
            event_id=event.source_event.event_id,
        )
        if not appended:
            return None

        score, contributions = await self._store.current_score(
            host_id=event.host_id,
            window_seconds=self._window_seconds,
            now=self._now(),
        )

        return ThreatScoreUpdate(
            update_id=uuid4(),
            computed_at=self._now(),
            host_id=event.host_id,
            score=min(100.0, float(score)),
            window_seconds=self._window_seconds,
            contributions_in_window=contributions,
            last_event_id=event.source_event.event_id,
            last_score_delta=score_delta,
            last_reason=reason,
        )

    async def _safe_publish(self, update: ThreatScoreUpdate) -> None:
        try:
            await self._producer.send_and_wait(
                self._output_topic,
                value=update.model_dump_json().encode("utf-8"),
                key=update.host_id.encode("utf-8"),
            )
        except Exception as exc:  # noqa: BLE001 - Kafka error must not crash the loop
            log.warning(
                "publish failed (%s); skipping update %s", exc, update.update_id
            )
```

### Step 4: Run tests, confirm 9 pass

```bash
pytest --import-mode=importlib data-plane/policy/tests/test_engine.py -v
```

Expected: **9 passed**.

### Step 5: Run full policy suite

```bash
pytest --import-mode=importlib data-plane/policy/tests -v
```

Expected: 5 config + 6 opa_client + 6 redis_store + 9 engine = **26 passed**.

### Step 6: Stage

```bash
git add data-plane/policy/src/policy/engine.py \
        data-plane/policy/tests/test_engine.py
```

> Suggested commit: `feat(policy): add PolicyEngine with OPA + Redis + producer-error tolerance`

---

## Task 8: Entry point + Dockerfile

**Files:**
- Create: `data-plane/policy/src/policy/__main__.py`
- Create: `data-plane/policy/Dockerfile`
- Create: `data-plane/policy/.dockerignore`

### Step 1: Implement `__main__.py`

```python
# data-plane/policy/src/policy/__main__.py
from __future__ import annotations

import asyncio
import logging

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from policy.config import PolicyConfig
from policy.engine import PolicyEngine
from policy.opa_client import OpaClient
from policy.redis_store import RedisScoreStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("policy")


async def _run() -> None:
    cfg = PolicyConfig.from_env()

    # auto_offset_reset="latest": skip historical backlog on fresh restart.
    # v1 walking-skeleton / live demo. v2 should reconsider.
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
        "starting policy-engine in=%s out=%s opa=%s redis=%s window=%ds",
        cfg.input_topic, cfg.output_topic, cfg.opa_url, cfg.redis_url, cfg.window_seconds,
    )

    # Nested try/finally so we clean up only what we successfully started.
    await consumer.start()
    try:
        await producer.start()
        try:
            opa = OpaClient(cfg.opa_url)
            store = RedisScoreStore(cfg.redis_url)
            try:
                engine = PolicyEngine(
                    consumer=consumer,
                    producer=producer,
                    output_topic=cfg.output_topic,
                    opa=opa,
                    store=store,
                    window_seconds=cfg.window_seconds,
                )
                await engine.run()
            finally:
                await store.aclose()
                await opa.aclose()
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
policies
```

(`policies` excluded because it's mounted into the OPA container via a Compose volume, not baked into the Python image.)

### Step 3: Create `Dockerfile`

```dockerfile
# data-plane/policy/Dockerfile
# Build context must be data-plane/ (one level up) so we can COPY both
# schemas/ and policy/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY policy /app/policy
RUN pip install /app/policy

CMD ["intellifim-policy-engine"]
```

### Step 4: Sanity-check the entry point imports

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
python -c "from policy.__main__ import main; print(main)"
```

Expected: `<function main at 0x...>`.

### Step 5: Build the image

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker build -f policy/Dockerfile -t intellifim-policy:dev .
```

Expected: build succeeds. Image size ~200-300 MB (httpx + redis-py + aiokafka add some weight but no heavy ML deps like anomaly's sklearn).

### Step 6: Sanity-check image runs (exits fast — no Kafka/OPA/Redis)

```bash
docker run --rm \
    -e KAFKA_BOOTSTRAP=does-not-exist:9092 \
    intellifim-policy:dev || true
```

Expected: container logs `starting policy-engine in=events.scored out=threat.scores opa=http://opa:8181 redis=redis://redis:6379/0 window=300s` BEFORE the Kafka connection error.

### Step 7: Stage

```bash
git add data-plane/policy/src/policy/__main__.py \
        data-plane/policy/Dockerfile \
        data-plane/policy/.dockerignore
```

> Suggested commit: `feat(policy): add Docker entry point and image`

---

## Task 9: Add `threat.scores` topic to `create-topics.sh`

**Files:**
- Modify: `data-plane/scripts/create-topics.sh`

### Step 1: Edit the script

Find the `events.scored` block and add `threat.scores` after it. Current ending:

```bash
# Scored topic
create_topic events.scored 6 $((14 * 24 * 60 * 60 * 1000))

echo "all topics created"
```

Replace with:

```bash
# Scored topic
create_topic events.scored 6 $((14 * 24 * 60 * 60 * 1000))

# Threat scores topic
create_topic threat.scores 6 $((14 * 24 * 60 * 60 * 1000))

echo "all topics created"
```

### Step 2: Bash-syntax check

```bash
bash -n data-plane/scripts/create-topics.sh && echo "syntax OK"
```

Expected: `syntax OK`.

### Step 3: Stage

```bash
git add data-plane/scripts/create-topics.sh
```

> Suggested commit: `feat(scripts): add threat.scores topic to create-topics.sh`

---

## Task 10: Wire opa + redis + policy-engine into Compose

**Files:**
- Modify: `data-plane/docker-compose.yml`

### Step 1: Append the three new service blocks

After the last service block (`anomaly-detector`) and BEFORE the `volumes:` block, append:

```yaml
  opa:
    # NOTE: `latest-debug` (not plain `latest`) — the default OPA image is
    # distroless and ships ONLY the `opa` binary; the healthcheck below
    # uses `wget` which is only present in the `-debug` variant. Verified
    # during Task 10 execution.
    image: openpolicyagent/opa:latest-debug
    container_name: opa
    networks: [bus]
    command: ["run", "--server", "--addr=:8181", "/policies"]
    volumes:
      - ./policy/policies:/policies:ro
    healthcheck:
      # OPA's /health endpoint returns 405 for HEAD requests, so we cannot
      # use `wget --spider` (which issues HEAD). `-O /dev/null` forces a GET
      # that returns 200. Verified during Task 10 execution.
      test: ["CMD", "wget", "-q", "-O", "/dev/null", "http://localhost:8181/health"]
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

2-space service-name indent; matches surrounding `anomaly-detector` block. Order: opa first (infra), redis second (infra), policy-engine last (depends on both).

### Step 2: Verify Compose validates

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane config -q
```

Expected: no output.

### Step 3: Verify the policy-engine image exists

```bash
docker images intellifim-policy:dev --format '{{.Repository}}:{{.Tag}} {{.Size}}'
```

Expected: `intellifim-policy:dev <size>MB`. If missing, rebuild via `docker build -f policy/Dockerfile -t intellifim-policy:dev .`.

### Step 4: Bring up the stack

```bash
docker compose --env-file .env.dataplane up -d
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 90
```

### Step 5: Verify all 20 services Up + policy-engine joined consumer group

```bash
docker compose --env-file .env.dataplane ps --format '{{.Name}} {{.Status}}'
docker logs policy-engine 2>&1 | tail -10
```

Expected:
- 20 services, all `Up`. `opa`, `redis`, `kafka`, `wazuh-manager` show `(healthy)`.
- `policy-engine` logs include `starting policy-engine in=events.scored out=threat.scores opa=http://opa:8181 redis=redis://redis:6379/0 window=300s`
- `policy-engine` logs include `Discovered coordinator for group policy-engine` and `Setting newly assigned partitions {... 6 partitions ...} for group policy-engine`

### Step 6: Bring down (KEEP volumes)

```bash
docker compose --env-file .env.dataplane down
```

### Step 7: Stage

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/docker-compose.yml
```

> Suggested commit: `feat(compose): wire opa + redis + policy-engine into the data-plane stack`

---

## Task 11: `tail-scores.py` consumer + first end-to-end test

**Files:**
- Create: `data-plane/scripts/tail-scores.py`

### Step 1: Write the script

```python
#!/usr/bin/env python3
# data-plane/scripts/tail-scores.py
"""Subscribe to threat.scores and pretty-print ThreatScoreUpdates.

Usage:
    pip install -e data-plane/schemas
    pip install aiokafka
    python data-plane/scripts/tail-scores.py [--bootstrap localhost:9094]
"""
from __future__ import annotations

import argparse
import asyncio
import json

from aiokafka import AIOKafkaConsumer

from intellifim_schemas import ThreatScoreUpdate


async def _tail(bootstrap: str) -> None:
    consumer = AIOKafkaConsumer(
        "threat.scores",
        bootstrap_servers=bootstrap,
        group_id=None,
        auto_offset_reset="latest",
    )
    await consumer.start()
    try:
        async for msg in consumer:
            try:
                u = ThreatScoreUpdate.model_validate_json(msg.value)
            except Exception as exc:  # noqa: BLE001
                print(f"INVALID: {exc}\n  raw={msg.value[:200]!r}")
                continue
            line = json.dumps(
                {
                    "ts": u.computed_at.isoformat(),
                    "host": u.host_id,
                    "score": round(u.score, 2),
                    "window_s": u.window_seconds,
                    "contribs": u.contributions_in_window,
                    "last_delta": u.last_score_delta,
                    "last_reason": u.last_reason,
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
chmod +x data-plane/scripts/tail-scores.py
```

### Step 3: Smoke-test end-to-end (synchronous Bash for all waits)

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane up -d
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 90
```

Run the tail script in background; seed traffic:

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
python /home/aditya/Documents/IntelliFIM/data-plane/scripts/tail-scores.py --bootstrap localhost:9094 > /tmp/tail-scores.log 2>&1 &
TAIL_PID=$!
sleep 5
./scripts/seed-test-traffic.sh
sleep 45
kill $TAIL_PID 2>/dev/null || true
echo "---first 5 lines---"
head -5 /tmp/tail-scores.log
echo "---count---"
wc -l < /tmp/tail-scores.log
```

Expected: at least one JSON line showing a ThreatScoreUpdate with `"host":"001"`, `"score"` in [0, 100], `"contribs"` ≥ 1, and a `"last_reason"` from the Rego policy.

Fallback (if tail subscription timing missed updates), verify direct read:
```bash
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic threat.scores \
    --from-beginning --max-messages 5 --timeout-ms 30000 \
    2>/dev/null | grep -c '"score":'
```
Expected: ≥1. Also verify Redis: `docker exec redis redis-cli ZCARD threat_score:host:001` should be ≥1.

### Step 4: Cleanup

```bash
rm -f /tmp/tail-scores.log
find /home/aditya/Documents/IntelliFIM/data-plane/monitored -maxdepth 1 -name 'seed-*' -type d -exec rm -rf {} + 2>/dev/null
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane down
```

### Step 5: Stage

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/scripts/tail-scores.py
```

> Suggested commit: `feat(scripts): add tail-scores.py consumer for threat.scores`

---

## Task 12: README + final fresh-checkout smoke test

**Files:**
- Modify: `data-plane/README.md`

### Step 1: Update `data-plane/README.md`

**Change A:** Service count `17 services on Docker Compose:` → `20 services on Docker Compose:`.

**Change B:** Add new bullet after `**Anomaly detection:** ...` and before `**Normalizers:** ...`:

```markdown
- **Policy & scoring:** `policy-engine` + `opa` + `redis` (per-host dynamic threat score via Rego + sliding window, see [policy/](policy/))
```

**Change C:** Add the "Bring up the stack" step 2 entry for the policy image:

In the existing step 2 block, append a 4th `docker build` command:

```bash
docker build -f policy/Dockerfile     -t intellifim-policy:dev .
```

**Change D:** Add a new section AFTER "See anomaly scores" and BEFORE "Consume canonical events from a downstream service":

```markdown
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
```

**Change E:** Update "Running the unit tests" to add `policy[dev]` install + a 4th pytest pass + the Rego test command:

Replace:

```bash
pip install -e schemas[dev]
pip install -e normalizers[dev]
pip install -e correlator[dev]
pip install -e anomaly[dev]

# Each package declares its own `tests/` package, which means a single
# combined `pytest` call collides on conftest registration. Run them
# in three passes (each with `--import-mode=importlib`):
pytest --import-mode=importlib schemas/tests normalizers/tests -v
pytest --import-mode=importlib correlator/tests -v
pytest --import-mode=importlib anomaly/tests -v
```

With:

```bash
pip install -e schemas[dev]
pip install -e normalizers[dev]
pip install -e correlator[dev]
pip install -e anomaly[dev]
pip install -e policy[dev]

# Each package declares its own `tests/` package, which means a single
# combined `pytest` call collides on conftest registration. Run them
# in four passes (each with `--import-mode=importlib`):
pytest --import-mode=importlib schemas/tests normalizers/tests -v
pytest --import-mode=importlib correlator/tests -v
pytest --import-mode=importlib anomaly/tests -v
pytest --import-mode=importlib policy/tests -v

# Rego policy tests (requires `opa` CLI or Docker):
opa test policy/policies/
# OR
docker run --rm -v $(pwd)/policy/policies:/p \
    openpolicyagent/opa:latest test /p
```

**Change F:** Append a new DoD item:

```markdown
8. `python scripts/tail-scores.py` prints at least one `ThreatScoreUpdate`
   after running `./scripts/seed-test-traffic.sh` (or `kafka-console-consumer`
   on `threat.scores` finds ≥1 message with valid `score` field), AND
   `docker exec redis redis-cli ZCARD threat_score:host:001` returns ≥1.
```

### Step 2: Final fresh-checkout smoke test

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane down -v 2>/dev/null || true
docker rmi intellifim-normalizer:dev intellifim-correlator:dev intellifim-anomaly-detector:dev intellifim-policy:dev 2>/dev/null || true

docker build -f normalizers/Dockerfile -t intellifim-normalizer:dev .
docker build -f correlator/Dockerfile  -t intellifim-correlator:dev .
docker build -f anomaly/Dockerfile     -t intellifim-anomaly-detector:dev .
docker build -f policy/Dockerfile      -t intellifim-policy:dev .

docker compose --env-file .env.dataplane up -d
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 120   # cold Wazuh enrollment takes longer
```

Verify all 8 DoD items:

```bash
# DoD #1: services healthy (20 expected)
docker compose --env-file .env.dataplane ps

# DoD #2-#3: FIM + zeek on events.normalized
echo "smoke-policy-$(date +%s)" > monitored/smoke.txt
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

# DoD #5: unit tests (4 pytest passes)
cd /home/aditya/Documents/IntelliFIM
source .venv/bin/activate
pytest --import-mode=importlib data-plane/schemas/tests data-plane/normalizers/tests
pytest --import-mode=importlib data-plane/correlator/tests
pytest --import-mode=importlib data-plane/anomaly/tests
pytest --import-mode=importlib data-plane/policy/tests
# Expected: ~70 + 20 + 24 + 26 = ~140 passed

# Rego tests
docker run --rm -v /home/aditya/Documents/IntelliFIM/data-plane/policy/policies:/p \
    openpolicyagent/opa:latest test /p
# Expected: 5 tests pass

# DoD #6: correlations
cd /home/aditya/Documents/IntelliFIM/data-plane
./scripts/seed-test-traffic.sh
sleep 60
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic events.correlated \
    --from-beginning --max-messages 5 --timeout-ms 30000 > /tmp/correlated.txt 2>/dev/null
echo "correlations: $(wc -l < /tmp/correlated.txt) lines"

# DoD #7: anomaly scores
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic events.scored \
    --from-beginning --max-messages 10 --timeout-ms 30000 > /tmp/scored.txt 2>/dev/null
echo "scored: $(wc -l < /tmp/scored.txt) lines"

# DoD #8: threat scores + Redis state
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server kafka:9092 --topic threat.scores \
    --from-beginning --max-messages 10 --timeout-ms 30000 > /tmp/threat.txt 2>/dev/null
echo "threat updates: $(wc -l < /tmp/threat.txt) lines"
echo "Redis ZCARD for host-001: $(docker exec redis redis-cli ZCARD threat_score:host:001)"
```

Expected: all 8 DoD items pass.

### Step 3: Cleanup smoke artifacts

```bash
rm -f /home/aditya/Documents/IntelliFIM/data-plane/monitored/smoke.txt
rm -f /tmp/normalized.txt /tmp/correlated.txt /tmp/scored.txt /tmp/threat.txt
find /home/aditya/Documents/IntelliFIM/data-plane/monitored -maxdepth 1 -name 'seed-*' -type d -exec rm -rf {} + 2>/dev/null
docker compose --env-file .env.dataplane down
```

### Step 4: Stage

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/README.md
```

> Suggested commit: `docs(data-plane): document policy-engine and add DoD #8`

### Step 5: User opens PR

```bash
git push -u origin feat/policy-engine-v1
gh pr create --title "feat: policy & scoring v1 (OPA + Redis + sliding-window threat score)" --body "$(cat <<'EOF'
## Summary
Implements policy & scoring v1 per [docs/superpowers/specs/2026-05-18-policy-engine-v1-design.md](docs/superpowers/specs/2026-05-18-policy-engine-v1-design.md).

- Adds `ThreatScoreUpdate` schema (intellifim-schemas 0.3.0 → 0.4.0).
- New `intellifim-policy` Python package: `OpaClient` (httpx) + `RedisScoreStore` (redis-py async + sliding-window zset) + `PolicyEngine`.
- One Rego policy mapping `(anomaly_score, is_anomaly) → {score_delta, reason}`, tested via `opa test` (5 tests).
- Two new infra services: `opa` (Rego evaluation) + `redis` (sliding-window state). One new Python service: `policy-engine`. Stack grows from 17 → 20 services.
- New topic `threat.scores`. `tail-scores.py` consumer for observability.

## Test plan
- [x] All four pytest invocations green: schemas + normalizers (~70) + correlator (20) + anomaly (24) + policy (26) = **~140 Python tests**.
- [x] Rego tests via `opa test data-plane/policy/policies/` = **5 tests pass** (total ~145 tests).
- [x] `seed-test-traffic.sh` produces ≥1 `ThreatScoreUpdate` on `threat.scores` AND Redis `ZCARD threat_score:host:001` ≥ 1.
- [x] All 8 DoD items in `data-plane/README.md` pass on a fresh checkout.

## v2 backlog (deferred)
- Sigma rules engine + MISP threat-intel enrichment
- Tier hints in `ThreatScoreUpdate` (coordinate with sub-project #5)
- OPA live reload (`--watch`) + bundle service
- Redis persistence + cluster mode
- Per-user scoring + full `role × device × location × time` context (depends on Keycloak)
- Healthcheck + resource limits on policy-engine
- Decay-only background updates (currently emit only on incoming events)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review (run by plan author)

**1. Spec coverage**

| Spec section | Implementing task(s) |
|---|---|
| §1 Purpose | Tasks 1-12 collectively |
| §2 Scope (walking skeleton) | Reflected in plan opening; Task 3 ships ONLY the threat_score Rego (no Sigma/MISP); Task 10 ships only opa + redis + policy-engine (no Keycloak/Postgres) |
| §3 Out of scope | Verified: no task implements Sigma/MISP/Keycloak/Postgres/OPA live-reload/tier-suggestions |
| §4 Architecture overview | Tasks 8 (Dockerfile), 10 (compose service blocks), 9 (topic) |
| §5 Kafka topic + Redis data model | Task 9 (topic), Task 6 (RedisScoreStore implements the zset model exactly) |
| §6 ThreatScoreUpdate schema | Task 1 |
| §7 Rego policy | Task 3 |
| §8 PolicyEngine + clients + config + lifecycle | Tasks 4 (config), 5 (OpaClient), 6 (RedisScoreStore), 7 (engine), 8 (main + Dockerfile) |
| §9 Test strategy | Tasks 1, 3, 4, 5, 6, 7 (29 Python + 5 Rego); Task 11 (E2E smoke); Task 12 (final smoke) |
| §10 DoD (8 items) | Task 12 verifies all 8 |
| §11 Patterns continued | Consistent throughout (dual-mode extract, log-and-skip, time injection, nested try/finally, range pins) |
| §12 New patterns introduced | depends_on healthcheck (Task 10), fakeredis+respx (Tasks 5-6), opa test (Task 3) |
| §13 v2 deferrals | Listed in PR body (Task 12 Step 5) |

**2. No placeholders**

No "TBD", "implement later", "add error handling", or skeleton-only steps. Every code block is complete and copy-pasteable.

**3. Type / method consistency**

- `PolicyEngine.__init__` signature `(consumer, producer, output_topic, opa, store, window_seconds, now=...)` — Tasks 7, 8.
- `OpaClient.query(event) -> dict | None` — Tasks 5, 7.
- `RedisScoreStore.append_contribution(host_id, ts, delta, event_id) -> bool` — Tasks 6, 7.
- `RedisScoreStore.current_score(host_id, window_seconds, now) -> tuple[float, int]` — Tasks 6, 7.
- `PolicyConfig` fields `bootstrap_servers, consumer_group, opa_url, redis_url, window_seconds, input_topic, output_topic` — Tasks 4, 8, 10.
- Topic names `events.scored` (input) and `threat.scores` (output) — Tasks 4, 8, 9, 10, 11.
- Consumer group `policy-engine` — Tasks 4, 10.
- Schema package version `0.4.0` — Tasks 1, 2.
- Redis key shape `threat_score:host:<host_id>` — Tasks 6, 11, 12.

All consistent.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-05-18-policy-engine-v1.md`.** Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, two-stage review between tasks (spec + code quality), user commits at each boundary. Same proven pattern from sub-projects #1, #2, and #3.

**2. Inline Execution** — Tasks in this session via `superpowers:executing-plans`, batch with checkpoints.

When ready: commit this plan to main alongside the spec, create branch `feat/policy-engine-v1` off main, then start dispatching Task 1.
