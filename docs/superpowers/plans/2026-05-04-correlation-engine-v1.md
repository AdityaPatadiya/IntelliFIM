# Correlation Engine v1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the IntelliFIM correlation engine v1 — a single Python service that consumes `events.normalized`, performs per-host time-window joins between file events and network events, and publishes matches as `CorrelatedEvent` instances on a new Kafka topic `events.correlated`.

**Architecture:** Stateless dispatcher pattern (mirroring data-plane's `NormalizerLoop`). Adds a `CorrelatedEvent` schema to `intellifim-schemas` (bumps to 0.2.0). New `intellifim-correlator` Python package with three small units: `HostBuffer` (per-host rolling deques), `CorrelationEngine` (consume → buffer → match → publish loop), `__main__` (asyncio runner). Single Compose service `correlation-engine` on the existing `bus` network.

**Tech Stack:** Python 3.12, Pydantic v2, aiokafka, pytest, Docker Compose. NO Flink in v1 — defer to v2.

**Reference spec:** [`docs/superpowers/specs/2026-05-04-correlation-engine-v1-design.md`](../specs/2026-05-04-correlation-engine-v1-design.md)

**Reference for patterns:** Mirror the data-plane's `data-plane/normalizers/` structure — `NormalizerLoop` → `CorrelationEngine`, `_helpers.py` patterns, single-service Dockerfile, etc.

**Branch:** Create `feat/correlation-engine-v1` off `main` before Task 1.

---

## File Map

```
data-plane/
├── schemas/
│   └── src/intellifim_schemas/
│       ├── correlation.py                     ← NEW
│       └── tests/test_correlation.py          ← NEW
├── correlator/                                ← NEW package
│   ├── pyproject.toml
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── README.md
│   ├── src/correlator/
│   │   ├── __init__.py
│   │   ├── __main__.py
│   │   ├── config.py
│   │   ├── buffer.py
│   │   └── engine.py
│   └── tests/
│       ├── __init__.py
│       ├── conftest.py
│       ├── test_config.py
│       ├── test_buffer.py
│       └── test_engine.py
├── docker-compose.yml                         ← MODIFY (add correlation-engine service)
└── scripts/
    ├── create-topics.sh                       ← MODIFY (add events.correlated)
    └── tail-correlated.py                     ← NEW
```

10 tasks total. Estimated ~10-15 unit tests + 1 end-to-end smoke test.

---

## Task 1: `CorrelatedEvent` schema (TDD)

**Files:**
- Create: `data-plane/schemas/src/intellifim_schemas/correlation.py`
- Create: `data-plane/schemas/tests/test_correlation.py`
- Modify: `data-plane/schemas/src/intellifim_schemas/__init__.py` (re-export new types)
- Modify: `data-plane/schemas/pyproject.toml` (bump `version = "0.1.0"` → `"0.2.0"`)
- Modify: `data-plane/normalizers/pyproject.toml` (relax `intellifim-schemas==0.1.0` → `>=0.2,<1.0` so the normalizer Dockerfile installs against the bumped schemas package without a resolver conflict)

### Step 1: Write the failing tests

Create `data-plane/schemas/tests/test_correlation.py`:

```python
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from intellifim_schemas import CanonicalEvent, CorrelatedEvent


def _file_event() -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="file.modified",
        source="wazuh.fim",
        timestamp=datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc),
        ingest_timestamp=datetime(2026, 5, 4, 12, 0, 1, tzinfo=timezone.utc),
        host_id="host-001",
        file_path="/etc/shadow",
    )


def _network_event() -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="network.flow",
        source="zeek.conn",
        timestamp=datetime(2026, 5, 4, 12, 0, 30, tzinfo=timezone.utc),
        ingest_timestamp=datetime(2026, 5, 4, 12, 0, 31, tzinfo=timezone.utc),
        host_id="host-001",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=49152,
        dst_port=443,
        protocol="tcp",
    )


def test_correlated_event_basic_roundtrip():
    triggering = _file_event()
    co = _network_event()
    event = CorrelatedEvent(
        correlation_id=uuid4(),
        correlation_type="file_with_network",
        correlated_at=datetime.now(tz=timezone.utc),
        window_seconds=60,
        host_id="host-001",
        triggering_event=triggering,
        co_occurring_events=[co],
    )
    serialized = event.model_dump_json()
    rebuilt = CorrelatedEvent.model_validate_json(serialized)
    assert rebuilt == event
    assert rebuilt.triggering_event.event_type == "file.modified"
    assert len(rebuilt.co_occurring_events) == 1


def test_correlated_event_rejects_unknown_field():
    """extra='forbid' is the contract — unknown fields must be rejected."""
    payload = {
        "correlation_id": str(uuid4()),
        "correlation_type": "file_with_network",
        "correlated_at": datetime.now(tz=timezone.utc).isoformat(),
        "window_seconds": 60,
        "host_id": "host-001",
        "triggering_event": _file_event().model_dump(mode="json"),
        "co_occurring_events": [_network_event().model_dump(mode="json")],
        "mystery_field": "boom",
    }
    with pytest.raises(ValidationError):
        CorrelatedEvent.model_validate(payload)


def test_correlated_event_rejects_unknown_correlation_type():
    payload = {
        "correlation_id": str(uuid4()),
        "correlation_type": "rule_match",  # v2; not allowed in v1
        "correlated_at": datetime.now(tz=timezone.utc).isoformat(),
        "window_seconds": 60,
        "host_id": "host-001",
        "triggering_event": _file_event().model_dump(mode="json"),
        "co_occurring_events": [_network_event().model_dump(mode="json")],
    }
    with pytest.raises(ValidationError):
        CorrelatedEvent.model_validate(payload)


def test_correlated_event_requires_at_least_one_co_occurring():
    """Emitting a 'correlation' with zero co-occurring events is meaningless."""
    payload = {
        "correlation_id": str(uuid4()),
        "correlation_type": "file_with_network",
        "correlated_at": datetime.now(tz=timezone.utc).isoformat(),
        "window_seconds": 60,
        "host_id": "host-001",
        "triggering_event": _file_event().model_dump(mode="json"),
        "co_occurring_events": [],
    }
    with pytest.raises(ValidationError):
        CorrelatedEvent.model_validate(payload)


def test_correlated_event_rejects_zero_window_seconds():
    payload = {
        "correlation_id": str(uuid4()),
        "correlation_type": "file_with_network",
        "correlated_at": datetime.now(tz=timezone.utc).isoformat(),
        "window_seconds": 0,
        "host_id": "host-001",
        "triggering_event": _file_event().model_dump(mode="json"),
        "co_occurring_events": [_network_event().model_dump(mode="json")],
    }
    with pytest.raises(ValidationError):
        CorrelatedEvent.model_validate(payload)


def test_correlated_event_rejects_naive_correlated_at():
    payload = {
        "correlation_id": str(uuid4()),
        "correlation_type": "file_with_network",
        "correlated_at": datetime(2026, 5, 4, 12, 0, 0).isoformat(),  # no tz
        "window_seconds": 60,
        "host_id": "host-001",
        "triggering_event": _file_event().model_dump(mode="json"),
        "co_occurring_events": [_network_event().model_dump(mode="json")],
    }
    with pytest.raises(ValidationError):
        CorrelatedEvent.model_validate(payload)
```

### Step 2: Run tests, confirm they fail

```bash
source .venv/bin/activate
pytest --import-mode=importlib data-plane/schemas/tests/test_correlation.py -v
```

Expected: ImportError on `CorrelatedEvent` (it doesn't exist yet).

### Step 3: Implement the schema

Create `data-plane/schemas/src/intellifim_schemas/correlation.py`:

```python
"""Correlation schema for IntelliFIM.

Emitted by the correlation engine onto the `events.correlated` Kafka topic.
Type constraints mirror CanonicalEvent's strictness: invalid values rejected
at the schema boundary.
"""
from __future__ import annotations

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
    correlated_at: AwareDatetime
    window_seconds: PositiveInt

    host_id: str
    triggering_event: CanonicalEvent
    co_occurring_events: list[CanonicalEvent] = Field(min_length=1)
```

### Step 4: Update `__init__.py` to re-export the new types

Replace `data-plane/schemas/src/intellifim_schemas/__init__.py` with:

```python
from intellifim_schemas.correlation import CorrelatedEvent, CorrelationType
from intellifim_schemas.event import CanonicalEvent, EventType, Source

__all__ = [
    "CanonicalEvent",
    "CorrelatedEvent",
    "CorrelationType",
    "EventType",
    "Source",
]
```

### Step 5: Bump package version

In `data-plane/schemas/pyproject.toml`, change:

```toml
version = "0.1.0"
```

to:

```toml
version = "0.2.0"
```

### Step 6: Reinstall the package and run tests

```bash
pip install -e data-plane/schemas[dev]
pytest --import-mode=importlib data-plane/schemas/tests -v
```

Expected: all original 14 tests + 6 new tests = **20 passed**.

### Step 7: Stage files (DO NOT COMMIT)

```bash
git add data-plane/schemas/src/intellifim_schemas/correlation.py \
        data-plane/schemas/src/intellifim_schemas/__init__.py \
        data-plane/schemas/tests/test_correlation.py \
        data-plane/schemas/pyproject.toml \
        data-plane/normalizers/pyproject.toml
```

> Suggested commit: `feat(schemas): add CorrelatedEvent and bump intellifim-schemas to 0.2.0`

---

## Task 2: Bootstrap `intellifim-correlator` package

**Files:**
- Create: `data-plane/correlator/pyproject.toml`
- Create: `data-plane/correlator/README.md`
- Create: `data-plane/correlator/src/correlator/__init__.py`
- Create: `data-plane/correlator/tests/__init__.py`
- Create: `data-plane/correlator/tests/conftest.py`

### Step 1: Create `pyproject.toml`

```toml
# data-plane/correlator/pyproject.toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "intellifim-correlator"
version = "0.1.0"
description = "Per-host time-window correlation engine for IntelliFIM"
requires-python = ">=3.12"
dependencies = [
    "intellifim-schemas>=0.2,<1.0",
    "aiokafka>=0.10,<0.12",
    "pydantic>=2.7,<3",
]

[project.optional-dependencies]
dev = [
    "pytest>=8,<9",
    "pytest-asyncio>=0.23,<0.25",
]

[project.scripts]
intellifim-correlator = "correlator.__main__:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
```

### Step 2: Create empty package init

```python
# data-plane/correlator/src/correlator/__init__.py
```

(Empty file.)

### Step 3: Create test scaffolding

```python
# data-plane/correlator/tests/__init__.py
```

```python
# data-plane/correlator/tests/conftest.py
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from intellifim_schemas import CanonicalEvent


@pytest.fixture
def make_event():
    """Factory for CanonicalEvent instances. Defaults to a wazuh.fim file.modified
    event at 2026-05-04T12:00:00Z for host-001. Override any field via kwargs."""

    def _make(
        *,
        event_type: str = "file.modified",
        source: str = "wazuh.fim",
        host_id: str = "host-001",
        timestamp: datetime | None = None,
        **extra,
    ) -> CanonicalEvent:
        if timestamp is None:
            timestamp = datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc)
        kwargs = dict(
            event_id=uuid4(),
            event_type=event_type,
            source=source,
            timestamp=timestamp,
            ingest_timestamp=datetime.now(tz=timezone.utc),
            host_id=host_id,
        )
        kwargs.update(extra)
        return CanonicalEvent(**kwargs)

    return _make
```

### Step 4: Create README

```markdown
# intellifim-correlator

Per-host time-window correlation engine. Consumes `events.normalized` and
publishes `CorrelatedEvent` instances on `events.correlated` whenever a
file event has at least one co-occurring network event from the same host
within the configured window (default 60 s), or vice versa.

Install for development:

    pip install -e data-plane/schemas
    pip install -e data-plane/correlator[dev]

Run tests:

    pytest --import-mode=importlib data-plane/correlator/tests
```

### Step 5: Install and verify

```bash
pip install -e data-plane/correlator[dev]
python -c "import correlator; print(correlator.__file__)"
```

Expected: prints the path to the installed package.

### Step 6: Stage

```bash
git add data-plane/correlator/pyproject.toml \
        data-plane/correlator/README.md \
        data-plane/correlator/src/correlator/__init__.py \
        data-plane/correlator/tests/__init__.py \
        data-plane/correlator/tests/conftest.py
```

> Suggested commit: `feat(correlator): bootstrap intellifim-correlator package`

---

## Task 3: `HostBuffer` (TDD)

**Files:**
- Create: `data-plane/correlator/src/correlator/buffer.py`
- Create: `data-plane/correlator/tests/test_buffer.py`

### Step 1: Write the failing tests

```python
# data-plane/correlator/tests/test_buffer.py
from datetime import datetime, timedelta, timezone

from correlator.buffer import HostBuffer


_T0 = datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc)


def _now_factory(seconds_offset: int):
    """Returns a callable that always returns _T0 + seconds_offset."""
    def _now() -> datetime:
        return _T0 + timedelta(seconds=seconds_offset)
    return _now


def test_add_and_recent_returns_event(make_event):
    buf = HostBuffer(window_seconds=60, now=_now_factory(0))
    event = make_event(timestamp=_T0)
    buf.add(event)
    found = buf.recent("host-001", lambda e: e.event_type.startswith("file."))
    assert found == [event]


def test_recent_isolates_by_host(make_event):
    buf = HostBuffer(window_seconds=60, now=_now_factory(0))
    a = make_event(host_id="host-A", timestamp=_T0)
    b = make_event(host_id="host-B", timestamp=_T0)
    buf.add(a)
    buf.add(b)
    found_a = buf.recent("host-A", lambda e: True)
    found_b = buf.recent("host-B", lambda e: True)
    assert found_a == [a]
    assert found_b == [b]


def test_recent_returns_empty_for_unknown_host(make_event):
    buf = HostBuffer(window_seconds=60, now=_now_factory(0))
    buf.add(make_event(host_id="host-A", timestamp=_T0))
    assert buf.recent("host-NOPE", lambda e: True) == []


def test_old_events_are_expired_on_add(make_event):
    """Events older than window_seconds (relative to `now`) are dropped when
    new entries are added or queried."""
    buf = HostBuffer(window_seconds=60, now=_now_factory(120))  # now is T0 + 120s
    old = make_event(timestamp=_T0)  # 120s old, outside 60s window
    fresh = make_event(timestamp=_T0 + timedelta(seconds=90))  # 30s old, inside window
    buf.add(old)
    buf.add(fresh)
    found = buf.recent("host-001", lambda e: True)
    assert found == [fresh]


def test_recent_filters_by_predicate(make_event):
    buf = HostBuffer(window_seconds=60, now=_now_factory(0))
    file_event = make_event(event_type="file.modified", timestamp=_T0)
    net_event = make_event(event_type="network.flow", source="zeek.conn", timestamp=_T0)
    buf.add(file_event)
    buf.add(net_event)
    files = buf.recent("host-001", lambda e: e.event_type.startswith("file."))
    nets = buf.recent("host-001", lambda e: e.event_type.startswith("network."))
    assert files == [file_event]
    assert nets == [net_event]
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/correlator/tests/test_buffer.py -v
```

Expected: ImportError on `correlator.buffer`.

### Step 3: Implement `HostBuffer`

```python
# data-plane/correlator/src/correlator/buffer.py
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Callable

from intellifim_schemas import CanonicalEvent


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


class HostBuffer:
    """Per-host rolling buffer of CanonicalEvents with lazy expiration.

    Events older than `window_seconds` (relative to the injected `now`) are
    discarded on add and on query. Pure data structure — no I/O.
    """

    def __init__(
        self,
        *,
        window_seconds: int,
        now: Callable[[], datetime] = _default_now,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError(f"window_seconds must be positive, got {window_seconds}")
        self._window = timedelta(seconds=window_seconds)
        self._now = now
        self._buffers: dict[str, deque[CanonicalEvent]] = defaultdict(deque)

    def add(self, event: CanonicalEvent) -> None:
        host_buffer = self._buffers[event.host_id]
        self._expire(host_buffer)
        host_buffer.append(event)

    def recent(
        self,
        host_id: str,
        predicate: Callable[[CanonicalEvent], bool],
    ) -> list[CanonicalEvent]:
        host_buffer = self._buffers.get(host_id)
        if host_buffer is None:
            return []
        self._expire(host_buffer)
        return [e for e in host_buffer if predicate(e)]

    def _expire(self, host_buffer: deque[CanonicalEvent]) -> None:
        cutoff = self._now() - self._window
        while host_buffer and host_buffer[0].timestamp < cutoff:
            host_buffer.popleft()
```

### Step 4: Run tests, confirm 5 pass

```bash
pytest --import-mode=importlib data-plane/correlator/tests/test_buffer.py -v
```

Expected: **5 passed**.

### Step 5: Stage

```bash
git add data-plane/correlator/src/correlator/buffer.py \
        data-plane/correlator/tests/test_buffer.py
```

> Suggested commit: `feat(correlator): add HostBuffer with per-host lazy expiration`

---

## Task 4: `CorrelatorConfig` (TDD)

**Files:**
- Create: `data-plane/correlator/src/correlator/config.py`
- Create: `data-plane/correlator/tests/test_config.py`

### Step 1: Write the failing tests

```python
# data-plane/correlator/tests/test_config.py
import pytest

from correlator.config import (
    INPUT_TOPIC,
    OUTPUT_TOPIC,
    CorrelatorConfig,
)


def test_input_topic_constant():
    assert INPUT_TOPIC == "events.normalized"


def test_output_topic_constant():
    assert OUTPUT_TOPIC == "events.correlated"


def test_from_env_with_defaults(monkeypatch):
    monkeypatch.delenv("KAFKA_BOOTSTRAP", raising=False)
    monkeypatch.delenv("CORRELATION_WINDOW_SECONDS", raising=False)
    monkeypatch.delenv("CONSUMER_GROUP", raising=False)
    cfg = CorrelatorConfig.from_env()
    assert cfg.bootstrap_servers == "kafka:9092"
    assert cfg.window_seconds == 60
    assert cfg.consumer_group == "correlation-engine"
    assert cfg.input_topic == "events.normalized"
    assert cfg.output_topic == "events.correlated"


def test_from_env_overrides(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka.example.com:19092")
    monkeypatch.setenv("CORRELATION_WINDOW_SECONDS", "120")
    monkeypatch.setenv("CONSUMER_GROUP", "correlator-staging")
    cfg = CorrelatorConfig.from_env()
    assert cfg.bootstrap_servers == "kafka.example.com:19092"
    assert cfg.window_seconds == 120
    assert cfg.consumer_group == "correlator-staging"


def test_from_env_rejects_invalid_window(monkeypatch):
    monkeypatch.setenv("CORRELATION_WINDOW_SECONDS", "0")
    with pytest.raises(ValueError, match="CORRELATION_WINDOW_SECONDS"):
        CorrelatorConfig.from_env()
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/correlator/tests/test_config.py -v
```

Expected: ImportError on `correlator.config`.

### Step 3: Implement `CorrelatorConfig`

```python
# data-plane/correlator/src/correlator/config.py
from __future__ import annotations

import os
from dataclasses import dataclass

INPUT_TOPIC = "events.normalized"
OUTPUT_TOPIC = "events.correlated"


@dataclass(frozen=True)
class CorrelatorConfig:
    bootstrap_servers: str
    window_seconds: int
    consumer_group: str
    input_topic: str = INPUT_TOPIC
    output_topic: str = OUTPUT_TOPIC

    @classmethod
    def from_env(cls) -> "CorrelatorConfig":
        window_str = os.environ.get("CORRELATION_WINDOW_SECONDS", "60")
        try:
            window = int(window_str)
        except ValueError as exc:
            raise ValueError(
                f"CORRELATION_WINDOW_SECONDS must be a positive integer, got {window_str!r}"
            ) from exc
        if window <= 0:
            raise ValueError(
                f"CORRELATION_WINDOW_SECONDS must be a positive integer, got {window}"
            )
        return cls(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092"),
            window_seconds=window,
            consumer_group=os.environ.get("CONSUMER_GROUP", "correlation-engine"),
        )
```

### Step 4: Run tests, confirm 5 pass

```bash
pytest --import-mode=importlib data-plane/correlator/tests/test_config.py -v
```

Expected: **5 passed**.

### Step 5: Stage

```bash
git add data-plane/correlator/src/correlator/config.py \
        data-plane/correlator/tests/test_config.py
```

> Suggested commit: `feat(correlator): add CorrelatorConfig with env-var parsing`

---

## Task 5: `CorrelationEngine` (TDD)

**Files:**
- Create: `data-plane/correlator/src/correlator/engine.py`
- Create: `data-plane/correlator/tests/test_engine.py`

### Step 1: Write the failing tests

```python
# data-plane/correlator/tests/test_engine.py
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from intellifim_schemas import CorrelatedEvent

from correlator.buffer import HostBuffer
from correlator.engine import CorrelationEngine


_T0 = datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc)


def _now_at(seconds_offset: int):
    def _now() -> datetime:
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


async def test_file_event_after_network_emits_correlation(make_event):
    """Network event arrives first, then file event; the file event triggers a match."""
    network = make_event(
        event_type="network.flow", source="zeek.conn",
        timestamp=_T0, host_id="host-001",
    )
    file_event = make_event(
        event_type="file.modified", source="wazuh.fim",
        timestamp=_T0 + timedelta(seconds=10), host_id="host-001",
    )
    consumer = FakeConsumer([network, file_event])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(10))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(10),
    )
    await engine.run()

    assert len(producer.published) == 1
    topic, value, key = producer.published[0]
    assert topic == "events.correlated"
    assert key == b"host-001"
    rebuilt = CorrelatedEvent.model_validate_json(value)
    assert rebuilt.correlation_type == "file_with_network"
    assert rebuilt.host_id == "host-001"
    assert rebuilt.window_seconds == 60
    assert rebuilt.triggering_event.event_type == "file.modified"
    assert len(rebuilt.co_occurring_events) == 1
    assert rebuilt.co_occurring_events[0].event_type == "network.flow"


async def test_network_event_after_file_emits_correlation(make_event):
    """File first, then network; the network event triggers the match."""
    file_event = make_event(
        event_type="file.modified", source="wazuh.fim",
        timestamp=_T0, host_id="host-001",
    )
    network = make_event(
        event_type="network.flow", source="zeek.conn",
        timestamp=_T0 + timedelta(seconds=10), host_id="host-001",
    )
    consumer = FakeConsumer([file_event, network])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(10))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(10),
    )
    await engine.run()

    assert len(producer.published) == 1
    rebuilt = CorrelatedEvent.model_validate_json(producer.published[0][1])
    assert rebuilt.triggering_event.event_type == "network.flow"
    assert rebuilt.co_occurring_events[0].event_type == "file.modified"


async def test_no_match_when_hosts_differ(make_event):
    a = make_event(event_type="file.modified", host_id="host-A", timestamp=_T0)
    b = make_event(event_type="network.flow", source="zeek.conn",
                   host_id="host-B", timestamp=_T0)
    consumer = FakeConsumer([a, b])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(0))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(0),
    )
    await engine.run()
    assert producer.published == []


async def test_no_emission_when_no_counterparts(make_event):
    """Two file events from same host, no network events: nothing to correlate."""
    a = make_event(event_type="file.modified", timestamp=_T0)
    b = make_event(event_type="file.created", timestamp=_T0 + timedelta(seconds=5))
    consumer = FakeConsumer([a, b])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(5))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(5),
    )
    await engine.run()
    assert producer.published == []


async def test_expired_counterparts_are_not_matched(make_event):
    """Network event arrives, then 120 s later a file event arrives. Window
    is 60 s — the network event should have expired from the buffer."""
    network = make_event(event_type="network.flow", source="zeek.conn", timestamp=_T0)
    file_event = make_event(
        event_type="file.modified", source="wazuh.fim",
        timestamp=_T0 + timedelta(seconds=120),
    )
    consumer = FakeConsumer([network, file_event])
    producer = FakeProducer()
    # `now` advances to T0+120 by the time the file event is processed.
    buffer = HostBuffer(window_seconds=60, now=_now_at(120))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(120),
    )
    await engine.run()
    assert producer.published == []


async def test_loop_continues_after_producer_failure(make_event):
    """A transient producer error must not crash the loop."""
    a_net = make_event(event_type="network.flow", source="zeek.conn", timestamp=_T0)
    a_file = make_event(event_type="file.modified", timestamp=_T0 + timedelta(seconds=1))
    b_net = make_event(event_type="network.flow", source="zeek.conn",
                       host_id="host-B", timestamp=_T0)
    b_file = make_event(event_type="file.modified", host_id="host-B",
                        timestamp=_T0 + timedelta(seconds=2))
    consumer = FakeConsumer([a_net, a_file, b_net, b_file])

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
    buffer = HostBuffer(window_seconds=60, now=_now_at(2))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(2),
    )
    await engine.run()
    assert producer.calls == 2  # both correlations attempted
    assert len(producer.published) == 1  # only the second one succeeded
```

### Step 2: Run tests, confirm they fail

```bash
pytest --import-mode=importlib data-plane/correlator/tests/test_engine.py -v
```

Expected: ImportError on `correlator.engine`.

### Step 3: Implement `CorrelationEngine`

```python
# data-plane/correlator/src/correlator/engine.py
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from uuid import uuid4

from pydantic import ValidationError

from intellifim_schemas import CanonicalEvent, CorrelatedEvent

from correlator.buffer import HostBuffer

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


class CorrelationEngine:
    """Consumes CanonicalEvents from `events.normalized`, maintains a per-host
    rolling buffer, and emits CorrelatedEvents whenever a file event matches
    a network event from the same host within the time window (or vice versa).

    Offset-commit policy: same as data-plane normalizers — no manual commit;
    expects the consumer to have `enable_auto_commit=True` (aiokafka default).
    Combined with the log-and-skip error policy, this guarantees the partition
    does not stall on a single bad message or transient publish failure.
    """

    def __init__(
        self,
        *,
        consumer: _Consumer,
        producer: _Producer,
        output_topic: str,
        buffer: HostBuffer,
        window_seconds: int,
        now: Callable[[], datetime] = _default_now,
    ) -> None:
        self._consumer = consumer
        self._producer = producer
        self._output_topic = output_topic
        self._buffer = buffer
        self._window_seconds = window_seconds
        self._now = now

    async def run(self) -> None:
        async for raw_message in self._consumer:
            event = self._extract_event(raw_message)
            if event is None:
                continue
            self._buffer.add(event)
            counterparts = self._find_counterparts(event)
            if not counterparts:
                continue
            correlation = self._build_correlation(event, counterparts)
            await self._safe_publish(correlation)

    @staticmethod
    def _extract_event(message: Any) -> CanonicalEvent | None:
        # Real aiokafka messages have a `.value` attribute (bytes); fakes in
        # tests yield CanonicalEvent instances directly. Accept both.
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

    def _find_counterparts(self, event: CanonicalEvent) -> list[CanonicalEvent]:
        if event.event_type.startswith("file."):
            target_predicate = lambda e: e.event_type.startswith("network.")  # noqa: E731
        elif event.event_type.startswith("network."):
            target_predicate = lambda e: e.event_type.startswith("file.")  # noqa: E731
        else:
            return []
        # Exclude the just-added event itself by event_id (it could match its
        # own predicate if predicates ever overlap; not in v1, but defensive).
        return [
            e for e in self._buffer.recent(event.host_id, target_predicate)
            if e.event_id != event.event_id
        ]

    def _build_correlation(
        self,
        triggering: CanonicalEvent,
        co_occurring: list[CanonicalEvent],
    ) -> CorrelatedEvent:
        return CorrelatedEvent(
            correlation_id=uuid4(),
            correlation_type="file_with_network",
            correlated_at=self._now(),
            window_seconds=self._window_seconds,
            host_id=triggering.host_id,
            triggering_event=triggering,
            co_occurring_events=co_occurring,
        )

    async def _safe_publish(self, event: CorrelatedEvent) -> None:
        try:
            await self._producer.send_and_wait(
                self._output_topic,
                value=event.model_dump_json().encode("utf-8"),
                key=event.host_id.encode("utf-8"),
            )
        except Exception as exc:  # noqa: BLE001 - any Kafka error must not crash the loop
            log.warning(
                "publish failed (%s); skipping correlation %s", exc, event.correlation_id
            )
```

### Step 4: Run tests, confirm 6 pass

```bash
pytest --import-mode=importlib data-plane/correlator/tests/test_engine.py -v
```

Expected: **6 passed**.

### Step 5: Run full correlator suite

```bash
pytest --import-mode=importlib data-plane/correlator/tests -v
```

Expected: 5 buffer + 5 config + 6 engine = **16 passed**.

### Step 6: Stage

```bash
git add data-plane/correlator/src/correlator/engine.py \
        data-plane/correlator/tests/test_engine.py
```

> Suggested commit: `feat(correlator): add CorrelationEngine with bidirectional matching and producer-error guard`

---

## Task 6: Entry point + Dockerfile

**Files:**
- Create: `data-plane/correlator/src/correlator/__main__.py`
- Create: `data-plane/correlator/Dockerfile`
- Create: `data-plane/correlator/.dockerignore`

### Step 1: Implement `__main__.py`

```python
# data-plane/correlator/src/correlator/__main__.py
from __future__ import annotations

import asyncio
import logging

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from correlator.buffer import HostBuffer
from correlator.config import CorrelatorConfig
from correlator.engine import CorrelationEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("correlator")


async def _run() -> None:
    cfg = CorrelatorConfig.from_env()

    # auto_offset_reset="latest": on a fresh restart, skip the historical
    # backlog. v1 is a walking skeleton / live demo. Production should
    # reconsider this — see plan v2.
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
        "starting correlation-engine in=%s out=%s window=%ds",
        cfg.input_topic, cfg.output_topic, cfg.window_seconds,
    )

    # Nested try/finally so we clean up only what we successfully started.
    await consumer.start()
    try:
        await producer.start()
        try:
            engine = CorrelationEngine(
                consumer=consumer,
                producer=producer,
                output_topic=cfg.output_topic,
                buffer=HostBuffer(window_seconds=cfg.window_seconds),
                window_seconds=cfg.window_seconds,
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
# data-plane/correlator/Dockerfile
# Build context must be data-plane/ (one level up) so we can COPY both schemas/
# and correlator/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY correlator /app/correlator
RUN pip install /app/correlator

CMD ["intellifim-correlator"]
```

### Step 4: Sanity-check the entry point imports

```bash
python -c "from correlator.__main__ import main; print(main)"
```

Expected: `<function main at 0x...>`.

### Step 5: Build the image

```bash
docker build -f data-plane/correlator/Dockerfile -t intellifim-correlator:dev data-plane
```

Expected: build succeeds; image size ~150-250 MB.

### Step 6: Sanity-check image runs (will exit fast — no Kafka)

```bash
docker run --rm \
  -e KAFKA_BOOTSTRAP=does-not-exist:9092 \
  intellifim-correlator:dev || true
```

Expected: container starts, logs `starting correlation-engine in=events.normalized out=events.correlated window=60s`, then errors trying to reach Kafka.

### Step 7: Stage

```bash
git add data-plane/correlator/src/correlator/__main__.py \
        data-plane/correlator/Dockerfile \
        data-plane/correlator/.dockerignore
```

> Suggested commit: `feat(correlator): add Docker entry point and image`

---

## Task 7: Add `events.correlated` topic to `create-topics.sh`

**Files:**
- Modify: `data-plane/scripts/create-topics.sh`

### Step 1: Edit the script

The current script ends with the `events.normalized` topic creation followed by `echo "all topics created"`. Insert a new `create_topic` call AFTER `events.normalized` and BEFORE `echo "all topics created"`. Use Edit tool with anchor:

```bash
# Old:
# Canonical topic
create_topic events.normalized 6 $((14 * 24 * 60 * 60 * 1000))

echo "all topics created"
```

Replace with:

```bash
# Canonical topic
create_topic events.normalized 6 $((14 * 24 * 60 * 60 * 1000))

# Correlated topic
create_topic events.correlated 6 $((14 * 24 * 60 * 60 * 1000))

echo "all topics created"
```

### Step 2: Stage

```bash
git add data-plane/scripts/create-topics.sh
```

> Suggested commit: `feat(scripts): add events.correlated topic to create-topics.sh`

---

## Task 8: Wire `correlation-engine` into Compose

**Files:**
- Modify: `data-plane/docker-compose.yml`

### Step 1: Append the new service

After the last `normalizer-zeek-files` service block and BEFORE the `volumes:` block, append:

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

### Step 2: Verify Compose validates

```bash
cd data-plane
docker compose --env-file .env.dataplane config -q
```

Expected: no output (success).

### Step 3: Bring up the new service alongside the existing stack

```bash
docker compose --env-file .env.dataplane up -d
```

Wait for the stack to settle (~2-3 min for Wazuh to be healthy):

```bash
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 60
```

### Step 4: Confirm the correlator is running

```bash
docker ps --filter name=correlation-engine --format '{{.Status}}'
docker logs correlation-engine 2>&1 | tail -5
```

Expected: container `Up`; logs show `starting correlation-engine in=events.normalized out=events.correlated window=60s`.

### Step 5: Bring down (KEEP volumes)

```bash
docker compose --env-file .env.dataplane down
```

### Step 6: Stage

```bash
git add data-plane/docker-compose.yml
```

> Suggested commit: `feat(compose): wire correlation-engine into the data-plane stack`

---

## Task 9: `tail-correlated.py` consumer

**Files:**
- Create: `data-plane/scripts/tail-correlated.py`

### Step 1: Write the script

```python
#!/usr/bin/env python3
# data-plane/scripts/tail-correlated.py
"""Subscribe to events.correlated and pretty-print correlations.

Usage:
    pip install -e data-plane/schemas
    pip install aiokafka
    python data-plane/scripts/tail-correlated.py [--bootstrap localhost:9094]
"""
from __future__ import annotations

import argparse
import asyncio
import json

from aiokafka import AIOKafkaConsumer

from intellifim_schemas import CorrelatedEvent


async def _tail(bootstrap: str) -> None:
    consumer = AIOKafkaConsumer(
        "events.correlated",
        bootstrap_servers=bootstrap,
        group_id=None,
        auto_offset_reset="latest",
    )
    await consumer.start()
    try:
        async for msg in consumer:
            try:
                ce = CorrelatedEvent.model_validate_json(msg.value)
            except Exception as exc:  # noqa: BLE001
                print(f"INVALID: {exc}\n  raw={msg.value[:200]!r}")
                continue
            line = json.dumps(
                {
                    "ts": ce.correlated_at.isoformat(),
                    "host": ce.host_id,
                    "type": ce.correlation_type,
                    "trigger": {
                        "event_type": ce.triggering_event.event_type,
                        "source": ce.triggering_event.source,
                    },
                    "co_occurring": [
                        {"event_type": e.event_type, "source": e.source}
                        for e in ce.co_occurring_events
                    ],
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

### Step 2: Make it executable

```bash
chmod +x data-plane/scripts/tail-correlated.py
```

### Step 3: Smoke-test it

Bring up the full stack:

```bash
cd data-plane
docker compose --env-file .env.dataplane up -d
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 90
```

Run the tail script in the background, then trigger correlations via seed-test-traffic.sh:

```bash
source /home/aditya/Documents/IntelliFIM/.venv/bin/activate
python /home/aditya/Documents/IntelliFIM/data-plane/scripts/tail-correlated.py --bootstrap localhost:9094 > /tmp/tail-correlated.log 2>&1 &
TAIL_PID=$!
sleep 5
./scripts/seed-test-traffic.sh
sleep 30
kill $TAIL_PID 2>/dev/null || true
echo "---tail output---"
cat /tmp/tail-correlated.log
```

Expected: at least one JSON line in the output showing a correlation between a `file.*` triggering event and at least one `network.*` co-occurring event (or vice versa) on the same host.

If empty, troubleshoot:
- `docker logs correlation-engine --tail 30` — is it consuming from `events.normalized`?
- `docker exec kafka /opt/bitnami/kafka/bin/kafka-consumer-groups.sh --bootstrap-server kafka:9092 --describe --group correlation-engine` — is LAG dropping?
- Did `seed-test-traffic.sh` actually produce both file and network events on the same host? (`tail-normalized.py` should show them.)

### Step 4: Cleanup

```bash
rm -f /tmp/tail-correlated.log
find /home/aditya/Documents/IntelliFIM/data-plane/monitored -maxdepth 1 -name 'seed-*' -type d -exec rm -rf {} + 2>/dev/null
docker compose --env-file .env.dataplane down
```

### Step 5: Stage

```bash
git add data-plane/scripts/tail-correlated.py
```

> Suggested commit: `feat(scripts): add tail-correlated.py consumer for events.correlated`

---

## Task 10: README + final smoke test + open PR

**Files:**
- Modify: `data-plane/README.md` (add a "Correlation engine" section + update service count)

### Step 1: Update `data-plane/README.md`

Find the "What's in the box" section and update the service count from `15 services` to `16 services`. Then add `correlation-engine` to the Normalizers/Bus area:

In the section that lists services, after the **Bus:** line and before **Normalizers:**, add:

```markdown
- **Correlation:** `correlation-engine` (per-host file ↔ network time-window join, see [correlator/](correlator/))
```

Append a new section after "Generate test traffic":

```markdown
## See correlations

The correlation engine joins file and network events from the same host
within ±60 s and publishes matches on `events.correlated`. Tail it:

```bash
python scripts/tail-correlated.py --bootstrap localhost:9094
```

Trigger a guaranteed correlation by running `seed-test-traffic.sh` (which
emits both FIM and network events for the same host) — at least one
`CorrelatedEvent` should print within ~30 s.
```

Append to "Definition of done (v1)" section, after item 5:

```markdown
6. `python scripts/tail-correlated.py` prints at least one correlation
   after running `./scripts/seed-test-traffic.sh`.
```

### Step 2: Final fresh-checkout smoke test

Wipe everything and follow the README from scratch:

```bash
cd /home/aditya/Documents/IntelliFIM/data-plane
docker compose --env-file .env.dataplane down -v 2>/dev/null || true
docker rmi intellifim-normalizer:dev intellifim-correlator:dev 2>/dev/null || true

# README's bring-up steps (with the new correlator image build)
docker build -f normalizers/Dockerfile -t intellifim-normalizer:dev .
docker build -f correlator/Dockerfile -t intellifim-correlator:dev .
docker compose --env-file .env.dataplane up -d
until docker exec kafka /opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1; do sleep 3; done
./scripts/create-topics.sh
sleep 90
```

Verify all 6 DoD items:

```bash
# DoD #1: services healthy
docker compose --env-file .env.dataplane ps

# DoD #2-#3: FIM + zeek events on events.normalized
echo "smoke-correlator-$(date +%s)" > monitored/smoke.txt
sleep 30
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka:9092 --topic events.normalized \
  --from-beginning --max-messages 50 --timeout-ms 30000 > /tmp/normalized.txt 2>/dev/null
echo "normalized: $(wc -l < /tmp/normalized.txt) lines"
grep -c '"source":"wazuh.fim"' /tmp/normalized.txt
grep -c '"source":"zeek' /tmp/normalized.txt

# DoD #4: pcap replay
./scripts/replay-pcap.sh pcaps/http_get_basic.pcap
sleep 10

# DoD #5: unit tests
cd /home/aditya/Documents/IntelliFIM
source .venv/bin/activate
pytest --import-mode=importlib \
  data-plane/schemas/tests \
  data-plane/normalizers/tests \
  data-plane/correlator/tests
# Expected: ~78 passed (20 schemas + 36 normalizers + 16 correlator + extras)

# DoD #6: correlations
cd /home/aditya/Documents/IntelliFIM/data-plane
./scripts/seed-test-traffic.sh
sleep 30
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka:9092 --topic events.correlated \
  --from-beginning --max-messages 5 --timeout-ms 30000 > /tmp/correlated.txt 2>/dev/null
echo "correlations: $(wc -l < /tmp/correlated.txt) lines"
grep -c '"correlation_type":"file_with_network"' /tmp/correlated.txt
```

Expected: all 6 DoD items pass; at least one `file_with_network` correlation lands.

### Step 3: Cleanup smoke artifacts

```bash
rm -f /home/aditya/Documents/IntelliFIM/data-plane/monitored/smoke.txt
rm -f /tmp/normalized.txt /tmp/correlated.txt
find /home/aditya/Documents/IntelliFIM/data-plane/monitored -maxdepth 1 -name 'seed-*' -type d -exec rm -rf {} + 2>/dev/null
docker compose --env-file .env.dataplane down
```

### Step 4: Stage

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/README.md
```

> Suggested commit: `docs(data-plane): document correlation engine`

### Step 5: User opens PR

After all task commits are pushed:

```bash
git push -u origin feat/correlation-engine-v1
gh pr create --title "feat: correlation engine v1 (walking skeleton)" --body "$(cat <<'EOF'
## Summary
Implements correlation engine v1 per [docs/superpowers/specs/2026-05-04-correlation-engine-v1-design.md](docs/superpowers/specs/2026-05-04-correlation-engine-v1-design.md).

- Adds `CorrelatedEvent` schema (intellifim-schemas 0.1.0 → 0.2.0).
- New `intellifim-correlator` Python package: `HostBuffer` + `CorrelationEngine`.
- Single Compose service `correlation-engine` consuming `events.normalized`, producing `events.correlated`.
- Bidirectional file ↔ network matching within ±60 s on the same host.
- `tail-correlated.py` consumer.

## Test plan
- [x] `pytest --import-mode=importlib data-plane/schemas/tests data-plane/normalizers/tests data-plane/correlator/tests` — green.
- [x] `seed-test-traffic.sh` produces at least one `file_with_network` correlation on `events.correlated`.
- [x] All 6 DoD items in `data-plane/README.md` pass on a fresh checkout.
EOF
)"
```

---

## Self-Review (already run by plan author)

**1. Spec coverage**
- §1-2 (purpose, scope) → reflected in plan opening.
- §5 (architecture) → Tasks 3 (buffer), 5 (engine), 6 (entry point), 8 (Compose).
- §6 (CorrelatedEvent schema) → Task 1.
- §7 (repo layout) → file map at top + every task touches the right paths.
- §8 (engine contract) → Tasks 3 + 5.
- §9 (test strategy) → 16 unit tests across Tasks 1, 3, 4, 5.
- §10 (E2E smoke test) → Task 9 + Task 10.
- §11 (DoD) → Task 10 explicitly verifies all 6 items.
- §12 (migration path) → not implemented (it's about future work; no task needed).

**2. No placeholders**
No "TBD", "implement later", "add error handling", or skeleton tests. Every code block is complete.

**3. Type/method consistency**
- `HostBuffer.__init__` signature: `(window_seconds, now=...)` — used identically in Tasks 3, 5, 6.
- `CorrelationEngine.__init__` signature: `(consumer, producer, output_topic, buffer, window_seconds, now=...)` — Tasks 5, 6.
- `CorrelatorConfig` field names: `bootstrap_servers, window_seconds, consumer_group, input_topic, output_topic` — Tasks 4, 6.
- Topic names `events.normalized` and `events.correlated` — Tasks 4, 6, 7, 8, 9.
- Consumer group `correlation-engine` — Tasks 4, 8.
- Schema package version `0.2.0` — Tasks 1, 2.
