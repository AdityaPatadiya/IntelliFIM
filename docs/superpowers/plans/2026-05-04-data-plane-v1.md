# Data Plane v1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the IntelliFIM data-plane walking skeleton — a Docker-Compose stack that ingests Wazuh FIM/auth events and Zeek conn/dns/http/files logs, normalizes them through six per-source Python services into a canonical event topic that downstream sub-projects can consume.

**Architecture:** Hybrid Kafka topic layout (six raw per-source topics + one `events.normalized` canonical topic). Each raw topic has its own normalizer service — small async Python workers built on a shared base loop, validated with Pydantic v2. Single-broker Kafka in KRaft mode. Single Wazuh manager + agent and single Zeek sensor for v1.

**Tech Stack:** Python 3.12, Pydantic v2, aiokafka, pytest + pytest-asyncio, Docker Compose, Wazuh 4.7.x, Zeek 6.x, Bitnami Kafka 3.7 (KRaft), Elastic Filebeat 8.x, Provectus kafka-ui.

**Reference spec:** [`docs/superpowers/specs/2026-05-04-data-plane-v1-design.md`](../specs/2026-05-04-data-plane-v1-design.md)

---

## File Map

This plan creates a top-level `data-plane/` directory with everything self-contained:

```
data-plane/
├── docker-compose.yml
├── .env.dataplane.example
├── README.md
├── wazuh/
│   ├── manager/ossec.conf
│   ├── manager/local_rules.xml
│   └── agent/ossec.conf
├── zeek/
│   └── local.zeek
├── filebeat/
│   ├── filebeat-wazuh.yml
│   └── filebeat-zeek.yml
├── monitored/                       # bind-mounted target for FIM testing
│   └── .keep
├── pcaps/
│   ├── README.md
│   └── http_get_basic.pcap
├── scripts/
│   ├── create-topics.sh
│   ├── seed-test-traffic.sh
│   ├── replay-pcap.sh
│   └── tail-normalized.py
├── schemas/
│   ├── pyproject.toml
│   ├── README.md
│   ├── src/intellifim_schemas/
│   │   ├── __init__.py
│   │   └── event.py
│   └── tests/
│       ├── __init__.py
│       └── test_event.py
└── normalizers/
    ├── Dockerfile
    ├── pyproject.toml
    ├── README.md
    ├── src/normalizers/
    │   ├── __init__.py
    │   ├── __main__.py
    │   ├── config.py
    │   ├── base.py
    │   ├── wazuh_fim.py
    │   ├── wazuh_auth.py
    │   ├── zeek_conn.py
    │   ├── zeek_dns.py
    │   ├── zeek_http.py
    │   └── zeek_files.py
    └── tests/
        ├── __init__.py
        ├── conftest.py
        ├── fixtures/
        │   ├── wazuh_fim_modify.json
        │   ├── wazuh_fim_create.json
        │   ├── wazuh_fim_delete.json
        │   ├── wazuh_auth_login_success.json
        │   ├── wazuh_auth_login_failed.json
        │   ├── wazuh_auth_sudo.json
        │   ├── zeek_conn.json
        │   ├── zeek_dns.json
        │   ├── zeek_http.json
        │   └── zeek_files.json
        ├── test_base.py
        ├── test_wazuh_fim.py
        ├── test_wazuh_auth.py
        ├── test_zeek_conn.py
        ├── test_zeek_dns.py
        ├── test_zeek_http.py
        └── test_zeek_files.py
```

Branch: create `feat/data-plane-v1` before Task 1 and merge to `main` only after Task 21.

---

## Phase 1 — Schemas Package

### Task 1: Bootstrap the `intellifim-schemas` package

**Files:**
- Create: `data-plane/schemas/pyproject.toml`
- Create: `data-plane/schemas/README.md`
- Create: `data-plane/schemas/src/intellifim_schemas/__init__.py`
- Create: `data-plane/schemas/tests/__init__.py`

- [ ] **Step 1: Create the pyproject.toml**

```toml
# data-plane/schemas/pyproject.toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "intellifim-schemas"
version = "0.1.0"
description = "Canonical event schema shared across all IntelliFIM sub-projects"
requires-python = ">=3.12"
dependencies = [
    "pydantic>=2.7,<3",
]

[project.optional-dependencies]
dev = [
    "pytest>=8,<9",
]

[tool.setuptools.packages.find]
where = ["src"]
```

- [ ] **Step 2: Create the package init**

```python
# data-plane/schemas/src/intellifim_schemas/__init__.py
from intellifim_schemas.event import CanonicalEvent, EventType, Source

__all__ = ["CanonicalEvent", "EventType", "Source"]
```

- [ ] **Step 3: Create the test package init (empty file)**

```python
# data-plane/schemas/tests/__init__.py
```

- [ ] **Step 4: Create a brief README**

```markdown
# intellifim-schemas

Canonical event schema for IntelliFIM. Imported by every sub-project that
produces or consumes events on the `events.normalized` Kafka topic.

Install in editable mode:

    pip install -e data-plane/schemas[dev]

Run tests:

    pytest data-plane/schemas/tests
```

- [ ] **Step 5: Commit**

```bash
git add data-plane/schemas
git commit -m "feat(schemas): bootstrap intellifim-schemas package"
```

---

### Task 2: Define `CanonicalEvent` model (TDD)

**Files:**
- Create: `data-plane/schemas/src/intellifim_schemas/event.py`
- Create: `data-plane/schemas/tests/test_event.py`

- [ ] **Step 1: Write the failing tests**

```python
# data-plane/schemas/tests/test_event.py
from datetime import datetime, timezone
from ipaddress import IPv4Address
from uuid import uuid4

import pytest
from pydantic import ValidationError

from intellifim_schemas import CanonicalEvent


def _minimal_event_dict() -> dict:
    return {
        "event_id": str(uuid4()),
        "event_type": "file.modified",
        "source": "wazuh.fim",
        "timestamp": datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc).isoformat(),
        "ingest_timestamp": datetime(2026, 5, 4, 12, 0, 1, tzinfo=timezone.utc).isoformat(),
        "host_id": "agent-001",
    }


# --- positive cases ---

def test_canonical_event_required_fields_only():
    event = CanonicalEvent.model_validate(_minimal_event_dict())
    assert event.event_type == "file.modified"
    assert event.source == "wazuh.fim"
    assert event.host_id == "agent-001"
    assert event.schema_version == "1.0.0"
    assert event.user is None
    assert event.raw == {}


def test_canonical_event_serialization_roundtrip():
    payload = _minimal_event_dict()
    payload.update({
        "user": "alice",
        "user_uid": 1001,
        "file_path": "/etc/shadow",
        "file_hash_sha256": "a" * 64,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 49152,
        "dst_port": 443,
        "protocol": "tcp",
        "raw": {"original": "wazuh-event"},
    })
    event = CanonicalEvent.model_validate(payload)
    serialized = event.model_dump_json()
    rebuilt = CanonicalEvent.model_validate_json(serialized)
    assert rebuilt == event
    assert rebuilt.src_ip == IPv4Address("10.0.0.1")


def test_canonical_event_accepts_zero_file_size_and_root_uid():
    """Empty files are valid (size=0). Root is valid (uid=0)."""
    payload = _minimal_event_dict()
    payload.update({"file_size_bytes": 0, "user_uid": 0})
    event = CanonicalEvent.model_validate(payload)
    assert event.file_size_bytes == 0
    assert event.user_uid == 0


# --- negative cases (enum / IP / required field) ---

def test_canonical_event_rejects_unknown_event_type():
    payload = _minimal_event_dict()
    payload["event_type"] = "file.weird"
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_unknown_source():
    payload = _minimal_event_dict()
    payload["source"] = "syslog.unknown"
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_invalid_ip():
    payload = _minimal_event_dict()
    payload["src_ip"] = "not-an-ip"
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_missing_required_field():
    payload = _minimal_event_dict()
    del payload["host_id"]
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


# --- negative cases (constraint pinning) ---

def test_canonical_event_rejects_unknown_field():
    """extra='forbid' is the contract — unknown fields must be rejected."""
    payload = _minimal_event_dict()
    payload["mystery_field"] = "boom"
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_negative_file_size():
    payload = _minimal_event_dict()
    payload["file_size_bytes"] = -1
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_negative_user_uid():
    payload = _minimal_event_dict()
    payload["user_uid"] = -1
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_invalid_pid():
    """PID 0 is the kernel scheduler; real processes start at 1."""
    payload = _minimal_event_dict()
    payload["process_pid"] = 0
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_port_out_of_range():
    for bad_port in (0, 65536, -1):
        payload = _minimal_event_dict()
        payload["src_port"] = bad_port
        with pytest.raises(ValidationError):
            CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_invalid_sha256():
    """Must be exactly 64 lowercase hex chars."""
    for bad_hash in ("hello", "a" * 63, "A" * 64, "g" * 64, "a" * 65):
        payload = _minimal_event_dict()
        payload["file_hash_sha256"] = bad_hash
        with pytest.raises(ValidationError):
            CanonicalEvent.model_validate(payload)


def test_canonical_event_rejects_naive_timestamp():
    """Timestamps must carry tzinfo to be unambiguous across hosts."""
    payload = _minimal_event_dict()
    payload["timestamp"] = datetime(2026, 5, 4, 12, 0, 0).isoformat()  # no tzinfo
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(payload)
```

- [ ] **Step 2: Install the package in editable mode**

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e data-plane/schemas[dev]
```

- [ ] **Step 3: Run tests and confirm they fail**

```bash
pytest data-plane/schemas/tests -v
```

Expected: all six tests fail with `ImportError: cannot import name 'CanonicalEvent'` or similar.

- [ ] **Step 4: Implement the model**

```python
# data-plane/schemas/src/intellifim_schemas/event.py
"""Canonical event schema for IntelliFIM.

This is the contract every downstream sub-project (correlation engine, ML
inference, scoring, dashboard, response orchestrator) imports. Type
constraints are deliberately strict: invalid values must be rejected at
the schema boundary rather than propagated downstream.
"""
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeInt,
    PositiveInt,
)

EventType = Literal[
    "file.modified",
    "file.created",
    "file.deleted",
    "file.read",
    "auth.login_success",
    "auth.login_failed",
    "auth.logout",
    "auth.sudo",
    "network.flow",
    "network.dns_query",
    "network.http_request",
    "network.file_transfer",
]

Source = Literal[
    "wazuh.fim",
    "wazuh.auth",
    "zeek.conn",
    "zeek.dns",
    "zeek.http",
    "zeek.files",
]

Port = Annotated[int, Field(ge=1, le=65535)]
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class CanonicalEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # identity
    event_id: UUID
    event_type: EventType
    source: Source
    schema_version: str = "1.0.0"

    # time (timezone-aware UTC required so cross-host correlation is unambiguous)
    timestamp: AwareDatetime
    ingest_timestamp: AwareDatetime

    # host
    host_id: str
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

    # passthrough — the unmodified source event, kept for debugging and XAI
    raw: dict[str, Any] = Field(default_factory=dict)
```

- [ ] **Step 5: Run tests and confirm all pass**

```bash
pytest data-plane/schemas/tests -v
```

Expected: 14 passed.

- [ ] **Step 6: Commit**

```bash
git add data-plane/schemas/src/intellifim_schemas/event.py data-plane/schemas/tests/test_event.py
git commit -m "feat(schemas): define CanonicalEvent Pydantic model with tests"
```

---

## Phase 2 — Normalizer Framework

### Task 3: Bootstrap the `normalizers` package

**Files:**
- Create: `data-plane/normalizers/pyproject.toml`
- Create: `data-plane/normalizers/README.md`
- Create: `data-plane/normalizers/src/normalizers/__init__.py`
- Create: `data-plane/normalizers/tests/__init__.py`
- Create: `data-plane/normalizers/tests/conftest.py`
- Create: `data-plane/normalizers/tests/fixtures/.keep`

- [ ] **Step 1: Create pyproject.toml**

```toml
# data-plane/normalizers/pyproject.toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "intellifim-normalizers"
version = "0.1.0"
description = "Per-source normalizer services that emit canonical events"
requires-python = ">=3.12"
dependencies = [
    "intellifim-schemas==0.1.0",
    "aiokafka>=0.10,<0.12",
    "pydantic>=2.7,<3",
]

[project.optional-dependencies]
dev = [
    "pytest>=8,<9",
    "pytest-asyncio>=0.23,<0.25",
]

[project.scripts]
intellifim-normalizer = "normalizers.__main__:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
```

- [ ] **Step 2: Create empty package init**

```python
# data-plane/normalizers/src/normalizers/__init__.py
```

- [ ] **Step 3: Create test package init and conftest**

```python
# data-plane/normalizers/tests/__init__.py
```

```python
# data-plane/normalizers/tests/conftest.py
import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def load_fixture():
    def _load(name: str) -> dict:
        path = FIXTURES_DIR / name
        return json.loads(path.read_text())

    return _load
```

- [ ] **Step 4: Create the fixtures dir keeper**

```bash
touch data-plane/normalizers/tests/fixtures/.keep
```

- [ ] **Step 5: Create README**

```markdown
# intellifim-normalizers

Per-source normalizer services. Each normalizer reads from one raw Kafka
topic, transforms events into the canonical schema from
`intellifim-schemas`, and writes to `events.normalized`.

The image is the same for all six normalizers; behaviour is selected via
the `NORMALIZER_SOURCE` environment variable (e.g. `wazuh.fim`).

Install for development:

    pip install -e data-plane/schemas
    pip install -e data-plane/normalizers[dev]

Run tests:

    pytest data-plane/normalizers/tests
```

- [ ] **Step 6: Install and verify import**

```bash
pip install -e data-plane/normalizers[dev]
python -c "import normalizers; print(normalizers.__file__)"
```

Expected: prints the path to the installed package.

- [ ] **Step 7: Commit**

```bash
git add data-plane/normalizers
git commit -m "feat(normalizers): bootstrap normalizers package"
```

---

### Task 4: Normalizer base loop (TDD)

The base loop is the only reusable piece. Each per-source normalizer plugs in a `transform(raw: dict) -> CanonicalEvent` function; the base owns consume/validate/produce/error-handling.

**Files:**
- Create: `data-plane/normalizers/src/normalizers/base.py`
- Create: `data-plane/normalizers/tests/test_base.py`

- [ ] **Step 1: Write the failing tests**

```python
# data-plane/normalizers/tests/test_base.py
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import pytest

from intellifim_schemas import CanonicalEvent
from normalizers.base import NormalizerLoop


class FakeConsumer:
    def __init__(self, messages: list[dict]):
        self._messages = list(messages)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._messages:
            raise StopAsyncIteration
        return self._messages.pop(0)


class FakeProducer:
    def __init__(self):
        self.published: list[tuple[str, bytes]] = []

    async def send_and_wait(self, topic: str, value: bytes, key: bytes | None = None):
        self.published.append((topic, value))


def _ok_transform(raw: dict) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="file.modified",
        source="wazuh.fim",
        timestamp=datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc),
        ingest_timestamp=datetime.now(tz=timezone.utc),
        host_id=raw["agent"]["id"],
        raw=raw,
    )


async def test_loop_transforms_and_publishes():
    consumer = FakeConsumer([{"agent": {"id": "agent-001"}, "syscheck": {"path": "/etc/shadow"}}])
    producer = FakeProducer()
    loop = NormalizerLoop(
        consumer=consumer,
        producer=producer,
        output_topic="events.normalized",
        transform=_ok_transform,
    )
    await loop.run()
    assert len(producer.published) == 1
    topic, value = producer.published[0]
    assert topic == "events.normalized"
    rebuilt = CanonicalEvent.model_validate_json(value)
    assert rebuilt.host_id == "agent-001"


async def test_loop_skips_transform_failure():
    consumer = FakeConsumer([
        {"agent": {"id": "agent-001"}},  # ok
        {"missing": "agent-key"},        # _broken_transform raises
        {"agent": {"id": "agent-002"}},  # ok
    ])
    producer = FakeProducer()

    def transform(raw: dict) -> CanonicalEvent:
        if "agent" not in raw:
            raise KeyError("agent")
        return _ok_transform(raw)

    loop = NormalizerLoop(
        consumer=consumer,
        producer=producer,
        output_topic="events.normalized",
        transform=transform,
    )
    await loop.run()
    assert len(producer.published) == 2  # broken one skipped, two survivors


async def test_loop_skips_validation_failure():
    consumer = FakeConsumer([{"agent": {"id": "agent-001"}}])
    producer = FakeProducer()

    def bad_transform(raw: dict) -> Any:
        # Returns a dict that can't be validated as CanonicalEvent — missing fields.
        return {"event_type": "file.modified"}

    loop = NormalizerLoop(
        consumer=consumer,
        producer=producer,
        output_topic="events.normalized",
        transform=bad_transform,
    )
    await loop.run()
    assert producer.published == []


async def test_loop_continues_after_producer_failure():
    """A transient producer error must NOT crash the loop.

    Real Kafka clients raise on broker disconnect / request timeout. The loop
    must log + skip and keep consuming so the partition does not stall.
    """
    consumer = FakeConsumer([
        {"agent": {"id": "agent-001"}},
        {"agent": {"id": "agent-002"}},
        {"agent": {"id": "agent-003"}},
    ])

    class FlakyProducer:
        def __init__(self) -> None:
            self.calls = 0
            self.published: list[tuple[str, bytes]] = []

        async def send_and_wait(self, topic: str, value: bytes, key: bytes | None = None) -> None:
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("simulated kafka outage")
            self.published.append((topic, value))

    producer = FlakyProducer()
    loop = NormalizerLoop(
        consumer=consumer,
        producer=producer,
        output_topic="events.normalized",
        transform=_ok_transform,
    )
    await loop.run()
    assert producer.calls == 3                 # all three attempted
    assert len(producer.published) == 2        # 1st + 3rd succeeded; 2nd was dropped
```

- [ ] **Step 2: Run tests and confirm they fail**

```bash
pytest data-plane/normalizers/tests/test_base.py -v
```

Expected: all three fail with `ImportError: cannot import name 'NormalizerLoop'`.

- [ ] **Step 3: Implement the base loop**

```python
# data-plane/normalizers/src/normalizers/base.py
from __future__ import annotations

import json
import logging
from typing import Any, Callable, Protocol

from pydantic import ValidationError

from intellifim_schemas import CanonicalEvent

log = logging.getLogger(__name__)

Transform = Callable[[dict], CanonicalEvent]


class _Consumer(Protocol):
    def __aiter__(self) -> "_Consumer": ...
    async def __anext__(self) -> Any: ...


class _Producer(Protocol):
    async def send_and_wait(
        self, topic: str, value: bytes, key: bytes | None = ...
    ) -> Any: ...


class NormalizerLoop:
    """Generic consume → transform → validate → produce loop.

    Per-source normalizers wire in a `transform` callable; the loop
    owns all the error handling and Kafka I/O so the source-specific
    code stays small and trivially testable.

    Offset-commit policy: this loop does NOT call `consumer.commit()`. The
    consumer is expected to be configured with `enable_auto_commit=True`
    (the aiokafka default). Together with the log-and-skip error policy,
    this means: a malformed or unpublishable message is skipped and its
    offset auto-committed; the partition does not stall.
    """

    def __init__(
        self,
        consumer: _Consumer,
        producer: _Producer,
        output_topic: str,
        transform: Transform,
    ) -> None:
        self._consumer = consumer
        self._producer = producer
        self._output_topic = output_topic
        self._transform = transform

    async def run(self) -> None:
        async for raw_message in self._consumer:
            payload = self._extract_payload(raw_message)
            if payload is None:
                continue
            event = self._safe_transform(payload)
            if event is None:
                continue
            await self._safe_publish(event)

    async def _safe_publish(self, event: CanonicalEvent) -> None:
        try:
            await self._producer.send_and_wait(
                self._output_topic,
                value=event.model_dump_json().encode("utf-8"),
                key=event.host_id.encode("utf-8"),
            )
        except Exception as exc:  # noqa: BLE001 - any Kafka error must not crash the loop
            log.warning("publish failed (%s); skipping event %s", exc, event.event_id)

    @staticmethod
    def _extract_payload(message: Any) -> dict | None:
        # Real aiokafka messages have a `.value` attribute (bytes); the
        # FakeConsumer in tests yields plain dicts. Accept both.
        if isinstance(message, dict):
            return message
        value = getattr(message, "value", None)
        if value is None:
            log.warning("dropping message with no value")
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            log.warning("dropping non-JSON message")
            return None

    def _safe_transform(self, raw: dict) -> CanonicalEvent | None:
        try:
            candidate = self._transform(raw)
        except Exception as exc:  # noqa: BLE001 - we want to skip ANY transform error
            log.warning("transform failed (%s); skipping event", exc)
            return None

        if not isinstance(candidate, CanonicalEvent):
            try:
                return CanonicalEvent.model_validate(candidate)
            except ValidationError as exc:
                log.warning("validation failed (%s); skipping event", exc)
                return None
        return candidate
```

- [ ] **Step 4: Run tests and confirm all pass**

```bash
pytest data-plane/normalizers/tests/test_base.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add data-plane/normalizers/src/normalizers/base.py data-plane/normalizers/tests/test_base.py
git commit -m "feat(normalizers): add reusable consume/transform/produce loop"
```

---

### Task 5: Config + entry point

**Files:**
- Create: `data-plane/normalizers/src/normalizers/config.py`
- Create: `data-plane/normalizers/src/normalizers/__main__.py`

- [ ] **Step 1: Implement config**

```python
# data-plane/normalizers/src/normalizers/config.py
from __future__ import annotations

import os
from dataclasses import dataclass

SOURCE_TO_INPUT_TOPIC = {
    "wazuh.fim": "wazuh.fim",
    "wazuh.auth": "wazuh.auth",
    "zeek.conn": "zeek.conn",
    "zeek.dns": "zeek.dns",
    "zeek.http": "zeek.http",
    "zeek.files": "zeek.files",
}

OUTPUT_TOPIC = "events.normalized"


@dataclass(frozen=True)
class NormalizerConfig:
    source: str
    input_topic: str
    output_topic: str
    bootstrap_servers: str
    consumer_group: str

    @classmethod
    def from_env(cls) -> "NormalizerConfig":
        source = os.environ["NORMALIZER_SOURCE"]
        if source not in SOURCE_TO_INPUT_TOPIC:
            raise ValueError(
                f"NORMALIZER_SOURCE={source!r} is not one of {sorted(SOURCE_TO_INPUT_TOPIC)}"
            )
        return cls(
            source=source,
            input_topic=SOURCE_TO_INPUT_TOPIC[source],
            output_topic=OUTPUT_TOPIC,
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092"),
            consumer_group=f"normalizer-{source.replace('.', '-')}",
        )
```

- [ ] **Step 2: Implement the entry point**

```python
# data-plane/normalizers/src/normalizers/__main__.py
from __future__ import annotations

import asyncio
import importlib
import logging

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from normalizers.base import NormalizerLoop
from normalizers.config import NormalizerConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("normalizers")


def _load_transform(source: str):
    # source "wazuh.fim" → module normalizers.wazuh_fim, function `transform`
    module_name = "normalizers." + source.replace(".", "_")
    module = importlib.import_module(module_name)
    return module.transform


async def _run() -> None:
    cfg = NormalizerConfig.from_env()
    transform = _load_transform(cfg.source)

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

    log.info("starting normalizer source=%s in=%s out=%s", cfg.source, cfg.input_topic, cfg.output_topic)

    # Nested try/finally so we clean up only what we successfully started.
    # If producer.start() raises, the outer finally still stops the consumer.
    await consumer.start()
    try:
        await producer.start()
        try:
            loop = NormalizerLoop(
                consumer=consumer,
                producer=producer,
                output_topic=cfg.output_topic,
                transform=transform,
            )
            await loop.run()
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

- [ ] **Step 3: Sanity-check the entry point's import path**

```bash
NORMALIZER_SOURCE=wazuh.fim python -c "from normalizers.config import NormalizerConfig; print(NormalizerConfig.from_env())"
```

Expected: prints `NormalizerConfig(source='wazuh.fim', input_topic='wazuh.fim', output_topic='events.normalized', ...)`.

- [ ] **Step 4: Commit**

```bash
git add data-plane/normalizers/src/normalizers/config.py data-plane/normalizers/src/normalizers/__main__.py
git commit -m "feat(normalizers): add config and Kafka entry point"
```

---

## Phase 3 — Per-source Normalizers

Each task in this phase follows the same shape:

1. Drop a captured raw JSON event into `tests/fixtures/`.
2. Write a failing test that maps that fixture to an expected `CanonicalEvent`.
3. Implement `transform(raw) -> CanonicalEvent`.
4. Run tests, commit.

Field mappings come from §4 of the spec doc.

### Task 6: `wazuh-fim` normalizer (with shared helpers)

This task introduces the first per-source normalizer. It also extracts a small shared `_helpers.py` module so that Tasks 7-11 don't duplicate timestamp parsing / int conversion / hash lowercasing.

**Files:**
- Create: `data-plane/normalizers/src/normalizers/_helpers.py` ← shared helpers
- Create: `data-plane/normalizers/tests/test_helpers.py` ← helper tests
- Create: `data-plane/normalizers/tests/fixtures/wazuh_fim_modify.json`
- Create: `data-plane/normalizers/tests/fixtures/wazuh_fim_create.json`
- Create: `data-plane/normalizers/tests/fixtures/wazuh_fim_delete.json`
- Create: `data-plane/normalizers/tests/test_wazuh_fim.py`
- Create: `data-plane/normalizers/src/normalizers/wazuh_fim.py`

#### Sub-phase A: shared helpers

- [ ] **Step A1: Write failing tests for `_helpers.py`**

```python
# data-plane/normalizers/tests/test_helpers.py
from datetime import datetime, timezone

import pytest

from normalizers._helpers import maybe_int, maybe_lower, parse_utc


# --- maybe_int ---

def test_maybe_int_passes_none_through():
    assert maybe_int(None) is None


def test_maybe_int_treats_empty_string_as_none():
    assert maybe_int("") is None


def test_maybe_int_converts_numeric_string():
    assert maybe_int("42") == 42


def test_maybe_int_passes_int_through():
    assert maybe_int(42) == 42


# --- maybe_lower ---

def test_maybe_lower_passes_none_through():
    assert maybe_lower(None) is None


def test_maybe_lower_lowercases_string():
    assert maybe_lower("ABC123") == "abc123"


# --- parse_utc ---

def test_parse_utc_normalises_utc_timestamp():
    result = parse_utc("2026-05-04T12:00:00.000+0000")
    assert result == datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc)


def test_parse_utc_converts_non_utc_offset_to_utc():
    """Tz-aware non-UTC input is converted to UTC, not preserved."""
    result = parse_utc("2026-05-04T17:30:00+05:30")
    assert result == datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc)


def test_parse_utc_rejects_naive_timestamp():
    """A tz-less input would silently use the system local time — refuse it."""
    with pytest.raises(ValueError, match="missing tz"):
        parse_utc("2026-05-04T12:00:00")
```

- [ ] **Step A2: Confirm tests fail**

```bash
source .venv/bin/activate
pytest data-plane/normalizers/tests/test_helpers.py -v
```

Expected: ImportError on `normalizers._helpers`.

- [ ] **Step A3: Implement `_helpers.py`**

```python
# data-plane/normalizers/src/normalizers/_helpers.py
"""Per-source normalizer helpers.

These three functions are shared by every per-source normalizer module.
Centralising them here ensures a single source of truth for the project
conventions: SHA-256 hashes are lowercase hex, timestamps are UTC
tz-aware, missing-or-empty integer fields collapse to None.
"""
from __future__ import annotations

from datetime import datetime, timezone


def maybe_int(value: str | int | None) -> int | None:
    """Convert string-or-int to int; treat None and "" as missing."""
    if value is None or value == "":
        return None
    return int(value)


def maybe_lower(value: str | None) -> str | None:
    """Lowercase the string, pass None through unchanged."""
    if value is None:
        return None
    return value.lower()


def parse_utc(value: str) -> datetime:
    """Parse an ISO 8601 timestamp string into a UTC tz-aware datetime.

    Refuses tz-less input — `astimezone()` on a naive datetime would
    silently apply the system local time of the normalizer container,
    which would corrupt cross-host correlation downstream.
    """
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp missing tz: {value!r}")
    return parsed.astimezone(timezone.utc)
```

- [ ] **Step A4: Run tests, confirm 9 pass**

```bash
pytest data-plane/normalizers/tests/test_helpers.py -v
```

Expected: 9 passed.

#### Sub-phase B: wazuh-fim normalizer

- [ ] **Step 1: Add the fixtures**

```json
// data-plane/normalizers/tests/fixtures/wazuh_fim_modify.json
{
  "timestamp": "2026-05-04T12:00:00.000+0000",
  "agent": {"id": "001", "name": "linux-endpoint-1"},
  "syscheck": {
    "path": "/etc/shadow",
    "event": "modified",
    "size_after": "1842",
    "sha256_after": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef561234",
    "audit": {
      "user": {"name": "alice", "id": "1001"},
      "process": {"name": "vim", "id": "4242"}
    }
  }
}
```

```json
// data-plane/normalizers/tests/fixtures/wazuh_fim_create.json
{
  "timestamp": "2026-05-04T12:00:01.000+0000",
  "agent": {"id": "001", "name": "linux-endpoint-1"},
  "syscheck": {
    "path": "/tmp/new-file.txt",
    "event": "added",
    "size_after": "12",
    "sha256_after": "0000000000000000000000000000000000000000000000000000000000000000",
    "audit": {
      "user": {"name": "alice", "id": "1001"},
      "process": {"name": "touch", "id": "4243"}
    }
  }
}
```

```json
// data-plane/normalizers/tests/fixtures/wazuh_fim_delete.json
{
  "timestamp": "2026-05-04T12:00:02.000+0000",
  "agent": {"id": "001", "name": "linux-endpoint-1"},
  "syscheck": {
    "path": "/tmp/old-file.txt",
    "event": "deleted",
    "audit": {
      "user": {"name": "alice", "id": "1001"},
      "process": {"name": "rm", "id": "4244"}
    }
  }
}
```

- [ ] **Step 2: Write the failing test**

```python
# data-plane/normalizers/tests/test_wazuh_fim.py
from datetime import timezone

from intellifim_schemas import CanonicalEvent

from normalizers.wazuh_fim import transform


def test_modify_event_maps_to_file_modified(load_fixture):
    raw = load_fixture("wazuh_fim_modify.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "file.modified"
    assert event.source == "wazuh.fim"
    assert event.host_id == "001"
    assert event.host_name == "linux-endpoint-1"
    assert event.user == "alice"
    assert event.user_uid == 1001
    assert event.process_name == "vim"
    assert event.process_pid == 4242
    assert event.file_path == "/etc/shadow"
    assert event.file_size_bytes == 1842
    assert event.file_hash_sha256 == "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef561234"
    assert event.raw == raw


def test_create_event_maps_to_file_created(load_fixture):
    raw = load_fixture("wazuh_fim_create.json")
    event = transform(raw)
    assert event.event_type == "file.created"
    assert event.file_path == "/tmp/new-file.txt"


def test_delete_event_maps_to_file_deleted(load_fixture):
    raw = load_fixture("wazuh_fim_delete.json")
    event = transform(raw)
    assert event.event_type == "file.deleted"
    assert event.file_size_bytes is None
    assert event.file_hash_sha256 is None


def test_timestamp_is_normalized_to_utc(load_fixture):
    """Convention: every canonical event carries a UTC tz-aware timestamp."""
    raw = load_fixture("wazuh_fim_modify.json")
    event = transform(raw)
    assert event.timestamp.tzinfo == timezone.utc
    assert event.timestamp.isoformat() == "2026-05-04T12:00:00+00:00"


def test_sha256_hash_is_lowercased(load_fixture):
    """Convention: SHA-256 hashes are lowercase hex (Sha256Hex schema constraint)."""
    raw = load_fixture("wazuh_fim_modify.json")
    raw["syscheck"]["sha256_after"] = "AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF561234"
    event = transform(raw)
    assert event.file_hash_sha256 == "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef561234"
```

- [ ] **Step 3: Confirm tests fail**

```bash
pytest data-plane/normalizers/tests/test_wazuh_fim.py -v
```

Expected: ImportError on `normalizers.wazuh_fim`.

- [ ] **Step 4: Implement the transform**

```python
# data-plane/normalizers/src/normalizers/wazuh_fim.py
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from intellifim_schemas import CanonicalEvent

from normalizers._helpers import maybe_int, maybe_lower, parse_utc

_EVENT_TYPE_MAP = {
    "added": "file.created",
    "modified": "file.modified",
    "deleted": "file.deleted",
}


def transform(raw: dict) -> CanonicalEvent:
    syscheck = raw["syscheck"]
    audit = syscheck.get("audit", {}) or {}
    user = audit.get("user", {}) or {}
    process = audit.get("process", {}) or {}
    agent = raw.get("agent", {}) or {}

    return CanonicalEvent(
        event_id=uuid4(),
        event_type=_EVENT_TYPE_MAP[syscheck["event"]],
        source="wazuh.fim",
        timestamp=parse_utc(raw["timestamp"]),
        ingest_timestamp=datetime.now(tz=timezone.utc),
        host_id=agent["id"],
        host_name=agent.get("name"),
        user=user.get("name"),
        user_uid=maybe_int(user.get("id")),
        process_name=process.get("name"),
        process_pid=maybe_int(process.get("id")),
        file_path=syscheck.get("path"),
        file_hash_sha256=maybe_lower(syscheck.get("sha256_after")),
        file_size_bytes=maybe_int(syscheck.get("size_after")),
        raw=raw,
    )
```

- [ ] **Step 5: Run tests, confirm pass**

```bash
pytest data-plane/normalizers/tests/test_wazuh_fim.py -v
```

Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add data-plane/normalizers/src/normalizers/wazuh_fim.py data-plane/normalizers/tests/test_wazuh_fim.py data-plane/normalizers/tests/fixtures/wazuh_fim_*.json
git commit -m "feat(normalizers): add wazuh-fim normalizer"
```

---

### Task 7: `wazuh-auth` normalizer

**Files:**
- Create: `data-plane/normalizers/tests/fixtures/wazuh_auth_login_success.json`
- Create: `data-plane/normalizers/tests/fixtures/wazuh_auth_login_failed.json`
- Create: `data-plane/normalizers/tests/fixtures/wazuh_auth_sudo.json`
- Create: `data-plane/normalizers/tests/test_wazuh_auth.py`
- Create: `data-plane/normalizers/src/normalizers/wazuh_auth.py`

- [ ] **Step 1: Add the fixtures**

```json
// data-plane/normalizers/tests/fixtures/wazuh_auth_login_success.json
{
  "timestamp": "2026-05-04T12:01:00.000+0000",
  "agent": {"id": "001", "name": "linux-endpoint-1"},
  "rule": {"id": "5501", "description": "PAM: Login session opened.", "groups": ["pam", "syslog", "authentication_success"]},
  "data": {
    "dstuser": "alice",
    "uid": "1001",
    "srcip": "10.0.0.42"
  }
}
```

```json
// data-plane/normalizers/tests/fixtures/wazuh_auth_login_failed.json
{
  "timestamp": "2026-05-04T12:02:00.000+0000",
  "agent": {"id": "001", "name": "linux-endpoint-1"},
  "rule": {"id": "5503", "description": "PAM: User login failed.", "groups": ["pam", "syslog", "authentication_failed"]},
  "data": {
    "dstuser": "alice",
    "srcip": "10.0.0.99"
  }
}
```

```json
// data-plane/normalizers/tests/fixtures/wazuh_auth_sudo.json
{
  "timestamp": "2026-05-04T12:03:00.000+0000",
  "agent": {"id": "001", "name": "linux-endpoint-1"},
  "rule": {"id": "5402", "description": "Successful sudo to ROOT executed.", "groups": ["syslog", "sudo"]},
  "data": {
    "dstuser": "root",
    "srcuser": "alice",
    "uid": "0",
    "command": "/usr/bin/cat /etc/shadow"
  }
}
```

- [ ] **Step 2: Write the failing test**

```python
# data-plane/normalizers/tests/test_wazuh_auth.py
from intellifim_schemas import CanonicalEvent

from normalizers.wazuh_auth import transform


def test_login_success_maps(load_fixture):
    raw = load_fixture("wazuh_auth_login_success.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "auth.login_success"
    assert event.source == "wazuh.auth"
    assert event.host_id == "001"
    assert event.user == "alice"
    assert event.user_uid == 1001
    assert str(event.src_ip) == "10.0.0.42"
    assert event.raw == raw


def test_login_failed_maps(load_fixture):
    raw = load_fixture("wazuh_auth_login_failed.json")
    event = transform(raw)
    assert event.event_type == "auth.login_failed"
    assert event.user == "alice"
    assert str(event.src_ip) == "10.0.0.99"
    assert event.user_uid is None  # not present in this event


def test_sudo_maps(load_fixture):
    raw = load_fixture("wazuh_auth_sudo.json")
    event = transform(raw)
    assert event.event_type == "auth.sudo"
    assert event.user == "alice"  # source user, not target
    assert event.user_uid == 0
```

- [ ] **Step 3: Confirm tests fail**

```bash
pytest data-plane/normalizers/tests/test_wazuh_auth.py -v
```

- [ ] **Step 4: Implement the transform**

```python
# data-plane/normalizers/src/normalizers/wazuh_auth.py
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from intellifim_schemas import CanonicalEvent

from normalizers._helpers import maybe_int, parse_utc

# Wazuh ships preconfigured rules for these. IDs may shift between minor
# versions; map by rule.groups membership for resilience.
_GROUP_TO_EVENT_TYPE = {
    "authentication_success": "auth.login_success",
    "authentication_failed": "auth.login_failed",
    "sudo": "auth.sudo",
    "logout": "auth.logout",
}


def _classify(rule: dict) -> str | None:
    for group in rule.get("groups", []):
        if group in _GROUP_TO_EVENT_TYPE:
            return _GROUP_TO_EVENT_TYPE[group]
    return None


def transform(raw: dict) -> CanonicalEvent:
    rule = raw.get("rule", {}) or {}
    data = raw.get("data", {}) or {}
    agent = raw.get("agent", {}) or {}

    event_type = _classify(rule)
    if event_type is None:
        raise ValueError(f"unrecognised auth rule groups: {rule.get('groups')}")

    # Sudo events: actor is srcuser (the invoker), not dstuser (root).
    if event_type == "auth.sudo":
        user = data.get("srcuser") or data.get("dstuser")
    else:
        user = data.get("dstuser")

    return CanonicalEvent(
        event_id=uuid4(),
        event_type=event_type,
        source="wazuh.auth",
        timestamp=parse_utc(raw["timestamp"]),
        ingest_timestamp=datetime.now(tz=timezone.utc),
        host_id=agent["id"],
        host_name=agent.get("name"),
        user=user,
        user_uid=maybe_int(data.get("uid")),
        src_ip=data.get("srcip"),
        raw=raw,
    )
```

- [ ] **Step 5: Run tests, confirm pass**

```bash
pytest data-plane/normalizers/tests/test_wazuh_auth.py -v
```

Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add data-plane/normalizers/src/normalizers/wazuh_auth.py data-plane/normalizers/tests/test_wazuh_auth.py data-plane/normalizers/tests/fixtures/wazuh_auth_*.json
git commit -m "feat(normalizers): add wazuh-auth normalizer"
```

---

### Task 8: `zeek-conn` normalizer

**Files:**
- Create: `data-plane/normalizers/tests/fixtures/zeek_conn.json`
- Create: `data-plane/normalizers/tests/test_zeek_conn.py`
- Create: `data-plane/normalizers/src/normalizers/zeek_conn.py`

- [ ] **Step 1: Add the fixture**

```json
// data-plane/normalizers/tests/fixtures/zeek_conn.json
{
  "ts": 1746374400.123,
  "uid": "CHhAvVGS1DHFjwGM9",
  "id.orig_h": "10.10.0.10",
  "id.orig_p": 49152,
  "id.resp_h": "10.10.0.20",
  "id.resp_p": 80,
  "proto": "tcp",
  "service": "http",
  "duration": 0.5,
  "orig_bytes": 200,
  "resp_bytes": 1500,
  "conn_state": "SF"
}
```

- [ ] **Step 2: Write the failing test**

```python
# data-plane/normalizers/tests/test_zeek_conn.py
from intellifim_schemas import CanonicalEvent

from normalizers.zeek_conn import transform


def test_conn_maps_to_network_flow(load_fixture):
    raw = load_fixture("zeek_conn.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "network.flow"
    assert event.source == "zeek.conn"
    assert event.host_id == "zeek-sensor"
    assert str(event.src_ip) == "10.10.0.10"
    assert event.src_port == 49152
    assert str(event.dst_ip) == "10.10.0.20"
    assert event.dst_port == 80
    assert event.protocol == "tcp"
    assert event.raw == raw
```

- [ ] **Step 3: Confirm test fails**

```bash
pytest data-plane/normalizers/tests/test_zeek_conn.py -v
```

- [ ] **Step 4: Implement the transform**

```python
# data-plane/normalizers/src/normalizers/zeek_conn.py
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from intellifim_schemas import CanonicalEvent

ZEEK_HOST_ID = "zeek-sensor"


def _ts_to_datetime(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def transform(raw: dict) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="network.flow",
        source="zeek.conn",
        timestamp=_ts_to_datetime(raw["ts"]),
        ingest_timestamp=datetime.now(tz=timezone.utc),
        host_id=ZEEK_HOST_ID,
        src_ip=raw.get("id.orig_h"),
        src_port=raw.get("id.orig_p"),
        dst_ip=raw.get("id.resp_h"),
        dst_port=raw.get("id.resp_p"),
        protocol=raw.get("proto"),
        raw=raw,
    )
```

- [ ] **Step 5: Run tests, confirm pass**

```bash
pytest data-plane/normalizers/tests/test_zeek_conn.py -v
```

- [ ] **Step 6: Commit**

```bash
git add data-plane/normalizers/src/normalizers/zeek_conn.py data-plane/normalizers/tests/test_zeek_conn.py data-plane/normalizers/tests/fixtures/zeek_conn.json
git commit -m "feat(normalizers): add zeek-conn normalizer"
```

---

### Task 9: `zeek-dns` normalizer

**Files:**
- Create: `data-plane/normalizers/tests/fixtures/zeek_dns.json`
- Create: `data-plane/normalizers/tests/test_zeek_dns.py`
- Create: `data-plane/normalizers/src/normalizers/zeek_dns.py`

- [ ] **Step 1: Add the fixture**

```json
// data-plane/normalizers/tests/fixtures/zeek_dns.json
{
  "ts": 1746374410.456,
  "uid": "CHhAvVGS1DHFjwGM10",
  "id.orig_h": "10.10.0.10",
  "id.orig_p": 51234,
  "id.resp_h": "10.10.0.1",
  "id.resp_p": 53,
  "proto": "udp",
  "trans_id": 12345,
  "query": "example.com",
  "qtype_name": "A",
  "rcode_name": "NOERROR",
  "answers": ["93.184.216.34"]
}
```

- [ ] **Step 2: Write the failing test**

```python
# data-plane/normalizers/tests/test_zeek_dns.py
from intellifim_schemas import CanonicalEvent

from normalizers.zeek_dns import transform


def test_dns_maps_to_network_dns_query(load_fixture):
    raw = load_fixture("zeek_dns.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "network.dns_query"
    assert event.source == "zeek.dns"
    assert event.host_id == "zeek-sensor"
    assert str(event.src_ip) == "10.10.0.10"
    assert event.src_port == 51234
    assert str(event.dst_ip) == "10.10.0.1"
    assert event.dst_port == 53
    assert event.protocol == "dns"
    assert event.raw == raw
```

- [ ] **Step 3: Confirm test fails**

```bash
pytest data-plane/normalizers/tests/test_zeek_dns.py -v
```

- [ ] **Step 4: Implement the transform**

```python
# data-plane/normalizers/src/normalizers/zeek_dns.py
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from intellifim_schemas import CanonicalEvent

ZEEK_HOST_ID = "zeek-sensor"


def _ts_to_datetime(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def transform(raw: dict) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="network.dns_query",
        source="zeek.dns",
        timestamp=_ts_to_datetime(raw["ts"]),
        ingest_timestamp=datetime.now(tz=timezone.utc),
        host_id=ZEEK_HOST_ID,
        src_ip=raw.get("id.orig_h"),
        src_port=raw.get("id.orig_p"),
        dst_ip=raw.get("id.resp_h"),
        dst_port=raw.get("id.resp_p"),
        protocol="dns",
        raw=raw,
    )
```

- [ ] **Step 5: Run tests, confirm pass**

```bash
pytest data-plane/normalizers/tests/test_zeek_dns.py -v
```

- [ ] **Step 6: Commit**

```bash
git add data-plane/normalizers/src/normalizers/zeek_dns.py data-plane/normalizers/tests/test_zeek_dns.py data-plane/normalizers/tests/fixtures/zeek_dns.json
git commit -m "feat(normalizers): add zeek-dns normalizer"
```

---

### Task 10: `zeek-http` normalizer

**Files:**
- Create: `data-plane/normalizers/tests/fixtures/zeek_http.json`
- Create: `data-plane/normalizers/tests/test_zeek_http.py`
- Create: `data-plane/normalizers/src/normalizers/zeek_http.py`

- [ ] **Step 1: Add the fixture**

```json
// data-plane/normalizers/tests/fixtures/zeek_http.json
{
  "ts": 1746374420.789,
  "uid": "CHhAvVGS1DHFjwGM11",
  "id.orig_h": "10.10.0.10",
  "id.orig_p": 49160,
  "id.resp_h": "10.10.0.20",
  "id.resp_p": 80,
  "method": "GET",
  "host": "example.com",
  "uri": "/index.html",
  "user_agent": "curl/8.7.1",
  "status_code": 200
}
```

- [ ] **Step 2: Write the failing test**

```python
# data-plane/normalizers/tests/test_zeek_http.py
from intellifim_schemas import CanonicalEvent

from normalizers.zeek_http import transform


def test_http_maps_to_network_http_request(load_fixture):
    raw = load_fixture("zeek_http.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "network.http_request"
    assert event.source == "zeek.http"
    assert event.host_id == "zeek-sensor"
    assert str(event.src_ip) == "10.10.0.10"
    assert event.src_port == 49160
    assert str(event.dst_ip) == "10.10.0.20"
    assert event.dst_port == 80
    assert event.protocol == "http"
    assert event.raw == raw
```

- [ ] **Step 3: Confirm test fails**

```bash
pytest data-plane/normalizers/tests/test_zeek_http.py -v
```

- [ ] **Step 4: Implement the transform**

```python
# data-plane/normalizers/src/normalizers/zeek_http.py
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from intellifim_schemas import CanonicalEvent

ZEEK_HOST_ID = "zeek-sensor"


def _ts_to_datetime(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def transform(raw: dict) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="network.http_request",
        source="zeek.http",
        timestamp=_ts_to_datetime(raw["ts"]),
        ingest_timestamp=datetime.now(tz=timezone.utc),
        host_id=ZEEK_HOST_ID,
        src_ip=raw.get("id.orig_h"),
        src_port=raw.get("id.orig_p"),
        dst_ip=raw.get("id.resp_h"),
        dst_port=raw.get("id.resp_p"),
        protocol="http",
        raw=raw,
    )
```

- [ ] **Step 5: Run tests, confirm pass**

```bash
pytest data-plane/normalizers/tests/test_zeek_http.py -v
```

- [ ] **Step 6: Commit**

```bash
git add data-plane/normalizers/src/normalizers/zeek_http.py data-plane/normalizers/tests/test_zeek_http.py data-plane/normalizers/tests/fixtures/zeek_http.json
git commit -m "feat(normalizers): add zeek-http normalizer"
```

---

### Task 11: `zeek-files` normalizer

**Files:**
- Create: `data-plane/normalizers/tests/fixtures/zeek_files.json`
- Create: `data-plane/normalizers/tests/test_zeek_files.py`
- Create: `data-plane/normalizers/src/normalizers/zeek_files.py`

- [ ] **Step 1: Add the fixture**

```json
// data-plane/normalizers/tests/fixtures/zeek_files.json
{
  "ts": 1746374430.987,
  "fuid": "FxxxxYY1",
  "tx_hosts": ["10.10.0.20"],
  "rx_hosts": ["10.10.0.10"],
  "conn_uids": ["CHhAvVGS1DHFjwGM12"],
  "source": "HTTP",
  "depth": 0,
  "analyzers": ["SHA256"],
  "mime_type": "text/html",
  "filename": "index.html",
  "duration": 0.12,
  "seen_bytes": 1500,
  "total_bytes": 1500,
  "missing_bytes": 0,
  "overflow_bytes": 0,
  "sha256": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef561234"
}
```

- [ ] **Step 2: Write the failing test**

```python
# data-plane/normalizers/tests/test_zeek_files.py
from intellifim_schemas import CanonicalEvent

from normalizers.zeek_files import transform


def test_files_maps_to_network_file_transfer(load_fixture):
    raw = load_fixture("zeek_files.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "network.file_transfer"
    assert event.source == "zeek.files"
    assert event.host_id == "zeek-sensor"
    assert str(event.src_ip) == "10.10.0.20"   # tx_hosts[0]
    assert str(event.dst_ip) == "10.10.0.10"   # rx_hosts[0]
    assert event.file_path == "index.html"
    assert event.file_size_bytes == 1500
    assert event.file_hash_sha256 == "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef561234"
    assert event.raw == raw
```

- [ ] **Step 3: Confirm test fails**

```bash
pytest data-plane/normalizers/tests/test_zeek_files.py -v
```

- [ ] **Step 4: Implement the transform**

```python
# data-plane/normalizers/src/normalizers/zeek_files.py
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from intellifim_schemas import CanonicalEvent

ZEEK_HOST_ID = "zeek-sensor"


def _ts_to_datetime(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _first(items: list | None) -> str | None:
    if not items:
        return None
    return items[0]


def transform(raw: dict) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        event_type="network.file_transfer",
        source="zeek.files",
        timestamp=_ts_to_datetime(raw["ts"]),
        ingest_timestamp=datetime.now(tz=timezone.utc),
        host_id=ZEEK_HOST_ID,
        src_ip=_first(raw.get("tx_hosts")),
        dst_ip=_first(raw.get("rx_hosts")),
        file_path=raw.get("filename"),
        file_hash_sha256=raw.get("sha256"),
        file_size_bytes=raw.get("seen_bytes"),
        raw=raw,
    )
```

- [ ] **Step 5: Run tests, confirm pass**

```bash
pytest data-plane/normalizers/tests/test_zeek_files.py -v
```

- [ ] **Step 6: Run the full normalizer test suite**

```bash
pytest data-plane/normalizers/tests -v
```

Expected: all tests pass (3 base + 3 wazuh-fim + 3 wazuh-auth + 1 zeek-conn + 1 zeek-dns + 1 zeek-http + 1 zeek-files = 13).

- [ ] **Step 7: Commit**

```bash
git add data-plane/normalizers/src/normalizers/zeek_files.py data-plane/normalizers/tests/test_zeek_files.py data-plane/normalizers/tests/fixtures/zeek_files.json
git commit -m "feat(normalizers): add zeek-files normalizer"
```

---

## Phase 4 — Container Image

### Task 12: Normalizer Dockerfile

One image runs all six normalizers; the source is selected at container start via `NORMALIZER_SOURCE`.

**Files:**
- Create: `data-plane/normalizers/Dockerfile`
- Create: `data-plane/normalizers/.dockerignore`

- [ ] **Step 1: Add `.dockerignore`**

```
__pycache__
.pytest_cache
.venv
*.egg-info
tests
```

- [ ] **Step 2: Add the Dockerfile**

```dockerfile
# data-plane/normalizers/Dockerfile
# Build context must be the data-plane/ directory so we can COPY both
# schemas/ and normalizers/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install schemas first (its source rarely changes), then normalizers.
COPY schemas /app/schemas
RUN pip install /app/schemas

COPY normalizers /app/normalizers
RUN pip install /app/normalizers

# Source is selected at runtime; image is identical for all six.
CMD ["intellifim-normalizer"]
```

- [ ] **Step 3: Build the image**

```bash
docker build -f data-plane/normalizers/Dockerfile -t intellifim-normalizer:dev data-plane
```

Expected: build completes; final image is ~150-200MB.

- [ ] **Step 4: Sanity-check the image runs (will exit fast — no Kafka yet)**

```bash
docker run --rm -e NORMALIZER_SOURCE=wazuh.fim -e KAFKA_BOOTSTRAP=does-not-exist:9092 intellifim-normalizer:dev || true
```

Expected: container starts, logs `starting normalizer source=wazuh.fim ...`, then fails to reach Kafka (which is fine — proves the entry point and config wiring work).

- [ ] **Step 5: Commit**

```bash
git add data-plane/normalizers/Dockerfile data-plane/normalizers/.dockerignore
git commit -m "feat(normalizers): add Dockerfile (single image for all six normalizers)"
```

---

## Phase 5 — Compose Stack

The Compose stack is brought up bottom-up. After each task in this phase, the stack should be incrementally larger and runnable.

### Task 13: Kafka, kafka-ui, and topic creation

**Files:**
- Create: `data-plane/docker-compose.yml`
- Create: `data-plane/.env.dataplane.example`
- Create: `data-plane/scripts/create-topics.sh`

- [ ] **Step 1: Add `.env.dataplane.example`**

```bash
# data-plane/.env.dataplane.example
# Copy to .env.dataplane and adjust as needed.

# Host port mappings (change if you have a clash on your dev machine).
KAFKA_UI_HOST_PORT=8080

# Bind-mount source for the FIM monitored directory. Must exist on host
# and be writable. For dev, leave at the default (./monitored).
FIM_MONITORED_HOST_DIR=./monitored
```

- [ ] **Step 2: Add the Compose file (Kafka + UI only for now)**

```yaml
# data-plane/docker-compose.yml
name: intellifim-dataplane

networks:
  bus:
    driver: bridge
  victims:
    driver: bridge

services:
  kafka:
    image: bitnami/kafka:3.7.0
    container_name: kafka
    networks: [bus]
    environment:
      # KRaft mode — no Zookeeper.
      KAFKA_CFG_NODE_ID: "1"
      KAFKA_CFG_PROCESS_ROLES: "controller,broker"
      KAFKA_CFG_CONTROLLER_QUORUM_VOTERS: "1@kafka:9093"
      KAFKA_CFG_LISTENERS: "PLAINTEXT://:9092,CONTROLLER://:9093"
      KAFKA_CFG_ADVERTISED_LISTENERS: "PLAINTEXT://kafka:9092"
      KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP: "CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT"
      KAFKA_CFG_CONTROLLER_LISTENER_NAMES: "CONTROLLER"
      KAFKA_CFG_INTER_BROKER_LISTENER_NAME: "PLAINTEXT"
      KAFKA_CFG_AUTO_CREATE_TOPICS_ENABLE: "false"
      ALLOW_PLAINTEXT_LISTENER: "yes"
    healthcheck:
      test: ["CMD-SHELL", "/opt/bitnami/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 >/dev/null 2>&1"]
      interval: 5s
      timeout: 5s
      retries: 20
    volumes:
      - kafka_data:/bitnami/kafka

  kafka-ui:
    image: provectuslabs/kafka-ui:v0.7.2
    container_name: kafka-ui
    networks: [bus]
    depends_on:
      kafka:
        condition: service_healthy
    environment:
      KAFKA_CLUSTERS_0_NAME: "intellifim-dataplane"
      KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS: "kafka:9092"
    ports:
      - "${KAFKA_UI_HOST_PORT:-8080}:8080"

volumes:
  kafka_data:
```

- [ ] **Step 3: Add the topic creation script**

```bash
# data-plane/scripts/create-topics.sh
#!/usr/bin/env bash
set -euo pipefail

KAFKA_CONTAINER="${KAFKA_CONTAINER:-kafka}"

create_topic() {
  local name=$1
  local partitions=$2
  local retention_ms=$3
  echo "creating topic ${name} (partitions=${partitions}, retention=${retention_ms}ms)"
  docker exec "${KAFKA_CONTAINER}" /opt/bitnami/kafka/bin/kafka-topics.sh \
    --bootstrap-server kafka:9092 \
    --create --if-not-exists \
    --topic "${name}" \
    --partitions "${partitions}" \
    --replication-factor 1 \
    --config "retention.ms=${retention_ms}"
}

# Per-source raw topics
create_topic wazuh.fim   3 $((7 * 24 * 60 * 60 * 1000))
create_topic wazuh.auth  3 $((7 * 24 * 60 * 60 * 1000))
create_topic zeek.conn   3 $((3 * 24 * 60 * 60 * 1000))
create_topic zeek.dns    3 $((3 * 24 * 60 * 60 * 1000))
create_topic zeek.http   3 $((3 * 24 * 60 * 60 * 1000))
create_topic zeek.files  3 $((7 * 24 * 60 * 60 * 1000))

# Canonical topic
create_topic events.normalized 6 $((14 * 24 * 60 * 60 * 1000))

echo "all topics created"
```

```bash
chmod +x data-plane/scripts/create-topics.sh
```

- [ ] **Step 4: Bring Kafka up**

```bash
cd data-plane
cp .env.dataplane.example .env.dataplane
mkdir -p monitored
docker compose --env-file .env.dataplane up -d kafka kafka-ui
```

Wait until `docker compose ps` shows kafka as `healthy` (~30 s).

- [ ] **Step 5: Create topics and verify**

```bash
./scripts/create-topics.sh
docker exec kafka /opt/bitnami/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --list
```

Expected output (order may vary):
```
events.normalized
wazuh.auth
wazuh.fim
zeek.conn
zeek.dns
zeek.files
zeek.http
```

- [ ] **Step 6: Open kafka-ui in a browser** at `http://localhost:8080` and confirm all 7 topics are listed under the `intellifim-dataplane` cluster.

- [ ] **Step 7: Bring it down**

```bash
docker compose --env-file .env.dataplane down
```

- [ ] **Step 8: Commit**

```bash
git add data-plane/docker-compose.yml data-plane/.env.dataplane.example data-plane/scripts/create-topics.sh data-plane/monitored/.keep
git commit -m "feat(compose): add Kafka (KRaft) + kafka-ui + topic creation script"
```

---

### Task 14: Wazuh manager + agent

**Files:**
- Create: `data-plane/wazuh/manager/ossec.conf`
- Create: `data-plane/wazuh/manager/local_rules.xml`
- Create: `data-plane/wazuh/agent/ossec.conf`
- Modify: `data-plane/docker-compose.yml`

- [ ] **Step 1: Add the manager `ossec.conf`** (minimal: receive agents, write `alerts.json`, ship FIM and authentication groups)

```xml
<!-- data-plane/wazuh/manager/ossec.conf -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
  </alerts>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <force>
      <enabled>yes</enabled>
      <key_mismatch>yes</key_mismatch>
      <disconnected_time enabled="yes">1h</disconnected_time>
      <after_registration_time>1h</after_registration_time>
    </force>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>
</ossec_config>
```

- [ ] **Step 2: Add an empty `local_rules.xml`** (placeholder for any custom rules later)

```xml
<!-- data-plane/wazuh/manager/local_rules.xml -->
<group name="local,">
  <!-- Add custom rules here as needed. -->
</group>
```

- [ ] **Step 3: Add the agent `ossec.conf`** (FIM watching `/data/monitored`, plus auditd/syslog forwarding for auth events)

```xml
<!-- data-plane/wazuh/agent/ossec.conf -->
<ossec_config>
  <client>
    <server>
      <address>wazuh-manager</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>linux-endpoint</config-profile>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>wazuh-manager</manager_address>
      <port>1515</port>
      <agent_name>linux-endpoint-1</agent_name>
    </enrollment>
  </client>

  <syscheck>
    <disabled>no</disabled>
    <frequency>30</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore>no</auto_ignore>
    <directories check_all="yes" realtime="yes" report_changes="yes" whodata="yes">/data/monitored</directories>
  </syscheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</ossec_config>
```

- [ ] **Step 4: Add the two services to Compose** (extend the existing `services:` block)

```yaml
# Append inside services: in data-plane/docker-compose.yml
  wazuh-manager:
    image: wazuh/wazuh-manager:4.7.5
    container_name: wazuh-manager
    networks: [bus]
    hostname: wazuh-manager
    volumes:
      - ./wazuh/manager/ossec.conf:/wazuh-config-mount/etc/ossec.conf:ro
      - ./wazuh/manager/local_rules.xml:/wazuh-config-mount/etc/rules/local_rules.xml:ro
      - wazuh_manager_data:/var/ossec/data
      - wazuh_manager_logs:/var/ossec/logs
      - wazuh_manager_queue:/var/ossec/queue
    healthcheck:
      test: ["CMD-SHELL", "test -f /var/ossec/logs/alerts/alerts.json"]
      interval: 10s
      timeout: 5s
      retries: 30
      start_period: 60s

  wazuh-agent:
    image: wazuh/wazuh-agent:4.7.5
    container_name: wazuh-agent
    networks: [bus, victims]
    hostname: linux-endpoint-1
    depends_on:
      wazuh-manager:
        condition: service_started
    environment:
      WAZUH_MANAGER: "wazuh-manager"
      WAZUH_AGENT_NAME: "linux-endpoint-1"
      WAZUH_REGISTRATION_SERVER: "wazuh-manager"
    volumes:
      - ./wazuh/agent/ossec.conf:/var/ossec/etc/ossec.conf:ro
      - ${FIM_MONITORED_HOST_DIR:-./monitored}:/data/monitored
      - wazuh_agent_state:/var/ossec/queue
```

Add to the `volumes:` block at the bottom:

```yaml
volumes:
  kafka_data:
  wazuh_manager_data:
  wazuh_manager_logs:
  wazuh_manager_queue:
  wazuh_agent_state:
```

- [ ] **Step 5: Bring up the new services**

```bash
cd data-plane
docker compose --env-file .env.dataplane up -d kafka kafka-ui wazuh-manager wazuh-agent
```

Wait ~90s for first-run enrollment.

- [ ] **Step 6: Confirm the agent registered**

```bash
docker exec wazuh-manager /var/ossec/bin/agent_control -lc
```

Expected: a line listing `linux-endpoint-1` as `Active`.

- [ ] **Step 7: Trigger a FIM event and verify it lands in `alerts.json`**

```bash
echo "hello" > data-plane/monitored/test.txt
sleep 10
docker exec wazuh-manager tail -n 20 /var/ossec/logs/alerts/alerts.json | grep -E '"path":"/data/monitored/test.txt"'
```

Expected: a JSON alert containing the file path.

- [ ] **Step 8: Bring down**

```bash
docker compose --env-file .env.dataplane down
```

- [ ] **Step 9: Commit**

```bash
git add data-plane/wazuh data-plane/docker-compose.yml
git commit -m "feat(compose): add Wazuh manager + agent with FIM and auth monitoring"
```

---

### Task 15: Zeek sensor + victim containers

**Files:**
- Create: `data-plane/zeek/local.zeek`
- Modify: `data-plane/docker-compose.yml`

- [ ] **Step 1: Add the Zeek site script**

```zeek
# data-plane/zeek/local.zeek
# Enable JSON output for the four logs we care about in v1.
@load policy/tuning/json-logs

# Reduce noise: ignore stats / capture_loss / weird unless explicitly wanted.
redef Log::default_logdir = "/var/log/zeek";
```

- [ ] **Step 2: Append zeek-sensor and victim containers to Compose**

```yaml
# Append inside services: in data-plane/docker-compose.yml
  zeek-sensor:
    image: zeek/zeek:6.0.4
    container_name: zeek-sensor
    networks: [bus, victims]
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./zeek/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek:ro
      - zeek_logs:/var/log/zeek
    command: >
      sh -c "mkdir -p /var/log/zeek &&
             zeek -i eth1 -C local 'Site::local_nets += {10.10.0.0/24}' &&
             tail -F /var/log/zeek/conn.log"

  victim-server:
    image: nginx:1.27-alpine
    container_name: victim-server
    networks: [victims]
    hostname: victim-server

  victim-client:
    image: curlimages/curl:8.7.1
    container_name: victim-client
    networks: [victims]
    depends_on:
      - victim-server
    entrypoint: >
      sh -c "while true; do
               curl -s http://victim-server/ -o /dev/null;
               curl -s http://victim-server/index.html -o /dev/null;
               sleep 5;
             done"
```

Add to `volumes:`:

```yaml
  zeek_logs:
```

- [ ] **Step 3: Bring up the new services**

```bash
cd data-plane
docker compose --env-file .env.dataplane up -d zeek-sensor victim-server victim-client
```

Give Zeek 30 s to start writing logs.

- [ ] **Step 4: Verify Zeek is producing JSON logs**

```bash
docker exec zeek-sensor ls /var/log/zeek
docker exec zeek-sensor head -n 3 /var/log/zeek/conn.log
```

Expected: `conn.log`, `dns.log`, `http.log`, etc. exist; `conn.log` lines look like JSON objects with `ts`, `id.orig_h`, `id.resp_h`.

- [ ] **Step 5: Bring down**

```bash
docker compose --env-file .env.dataplane down
```

- [ ] **Step 6: Commit**

```bash
git add data-plane/zeek data-plane/docker-compose.yml
git commit -m "feat(compose): add Zeek sensor + victim containers for live test traffic"
```

---

### Task 16: Filebeat shippers

**Files:**
- Create: `data-plane/filebeat/filebeat-wazuh.yml`
- Create: `data-plane/filebeat/filebeat-zeek.yml`
- Modify: `data-plane/docker-compose.yml`

- [ ] **Step 1: Add filebeat-wazuh config**

```yaml
# data-plane/filebeat/filebeat-wazuh.yml
filebeat.inputs:
  - type: filestream
    id: wazuh-alerts
    paths:
      - /var/ossec/logs/alerts/alerts.json
    parsers:
      - ndjson:
          target: ""
          add_error_key: true

processors:
  - drop_fields:
      fields: ["host", "agent.ephemeral_id", "agent.id", "agent.name", "agent.type", "agent.version", "ecs", "input", "log", "@version"]
      ignore_missing: true

output.kafka:
  hosts: ["kafka:9092"]
  topics:
    # Route by rule.groups membership: anything with "syscheck" → wazuh.fim,
    # anything in the auth groups → wazuh.auth.
    - topic: "wazuh.fim"
      when:
        contains:
          rule.groups: "syscheck"
    - topic: "wazuh.auth"
      when:
        or:
          - contains: { rule.groups: "authentication_success" }
          - contains: { rule.groups: "authentication_failed" }
          - contains: { rule.groups: "sudo" }
          - contains: { rule.groups: "logout" }
  required_acks: 1
  partition.hash:
    hash: ["agent.id"]
  codec.json:
    pretty: false
```

- [ ] **Step 2: Add filebeat-zeek config**

```yaml
# data-plane/filebeat/filebeat-zeek.yml
filebeat.inputs:
  - type: filestream
    id: zeek-conn
    paths: ["/var/log/zeek/conn.log"]
    parsers: [{ ndjson: { target: "", add_error_key: true } }]
    fields: { _topic: "zeek.conn" }
    fields_under_root: true
  - type: filestream
    id: zeek-dns
    paths: ["/var/log/zeek/dns.log"]
    parsers: [{ ndjson: { target: "", add_error_key: true } }]
    fields: { _topic: "zeek.dns" }
    fields_under_root: true
  - type: filestream
    id: zeek-http
    paths: ["/var/log/zeek/http.log"]
    parsers: [{ ndjson: { target: "", add_error_key: true } }]
    fields: { _topic: "zeek.http" }
    fields_under_root: true
  - type: filestream
    id: zeek-files
    paths: ["/var/log/zeek/files.log"]
    parsers: [{ ndjson: { target: "", add_error_key: true } }]
    fields: { _topic: "zeek.files" }
    fields_under_root: true

processors:
  - drop_fields:
      fields: ["host", "agent", "ecs", "input", "log", "@version", "@timestamp"]
      ignore_missing: true

output.kafka:
  hosts: ["kafka:9092"]
  topic: "%{[_topic]}"
  required_acks: 1
  codec.json:
    pretty: false
```

- [ ] **Step 3: Append filebeat services to Compose**

```yaml
# Append inside services: in data-plane/docker-compose.yml
  filebeat-wazuh:
    image: elastic/filebeat:8.13.4
    container_name: filebeat-wazuh
    user: root
    networks: [bus]
    depends_on:
      kafka:
        condition: service_healthy
      wazuh-manager:
        condition: service_healthy
    volumes:
      - ./filebeat/filebeat-wazuh.yml:/usr/share/filebeat/filebeat.yml:ro
      - wazuh_manager_logs:/var/ossec/logs:ro
    command: ["filebeat", "-e", "--strict.perms=false"]

  filebeat-zeek:
    image: elastic/filebeat:8.13.4
    container_name: filebeat-zeek
    user: root
    networks: [bus]
    depends_on:
      kafka:
        condition: service_healthy
      zeek-sensor:
        condition: service_started
    volumes:
      - ./filebeat/filebeat-zeek.yml:/usr/share/filebeat/filebeat.yml:ro
      - zeek_logs:/var/log/zeek:ro
    command: ["filebeat", "-e", "--strict.perms=false"]
```

- [ ] **Step 4: Bring the full stack up**

```bash
cd data-plane
docker compose --env-file .env.dataplane up -d
./scripts/create-topics.sh
```

- [ ] **Step 5: Trigger events and verify they reach raw topics**

```bash
echo "trigger-fim-$(date +%s)" > monitored/trigger.txt
# Give Filebeat a moment to ship.
sleep 15
# Read one message from wazuh.fim
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka:9092 --topic wazuh.fim --from-beginning --max-messages 1 --timeout-ms 30000
```

Expected: at least one JSON message containing the file path.

```bash
# Read one message from zeek.conn (victim-client is generating traffic continuously)
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka:9092 --topic zeek.conn --from-beginning --max-messages 1 --timeout-ms 30000
```

Expected: a JSON message with `id.orig_h` / `id.resp_h` between the two victim containers.

- [ ] **Step 6: Browse `kafka-ui` at http://localhost:8080**, select the `wazuh.fim` and `zeek.conn` topics, and confirm messages are flowing.

- [ ] **Step 7: Bring down**

```bash
docker compose --env-file .env.dataplane down
```

- [ ] **Step 8: Commit**

```bash
git add data-plane/filebeat data-plane/docker-compose.yml
git commit -m "feat(compose): ship Wazuh and Zeek logs to per-source Kafka topics via Filebeat"
```

---

### Task 17: Wire normalizers into Compose

**Files:**
- Modify: `data-plane/docker-compose.yml`

- [ ] **Step 1: Append the six normalizer services to Compose**

```yaml
# Append inside services: in data-plane/docker-compose.yml
  normalizer-wazuh-fim:
    image: intellifim-normalizer:dev
    container_name: normalizer-wazuh-fim
    networks: [bus]
    depends_on:
      kafka:
        condition: service_healthy
    environment:
      NORMALIZER_SOURCE: "wazuh.fim"
      KAFKA_BOOTSTRAP: "kafka:9092"

  normalizer-wazuh-auth:
    image: intellifim-normalizer:dev
    container_name: normalizer-wazuh-auth
    networks: [bus]
    depends_on:
      kafka:
        condition: service_healthy
    environment:
      NORMALIZER_SOURCE: "wazuh.auth"
      KAFKA_BOOTSTRAP: "kafka:9092"

  normalizer-zeek-conn:
    image: intellifim-normalizer:dev
    container_name: normalizer-zeek-conn
    networks: [bus]
    depends_on:
      kafka:
        condition: service_healthy
    environment:
      NORMALIZER_SOURCE: "zeek.conn"
      KAFKA_BOOTSTRAP: "kafka:9092"

  normalizer-zeek-dns:
    image: intellifim-normalizer:dev
    container_name: normalizer-zeek-dns
    networks: [bus]
    depends_on:
      kafka:
        condition: service_healthy
    environment:
      NORMALIZER_SOURCE: "zeek.dns"
      KAFKA_BOOTSTRAP: "kafka:9092"

  normalizer-zeek-http:
    image: intellifim-normalizer:dev
    container_name: normalizer-zeek-http
    networks: [bus]
    depends_on:
      kafka:
        condition: service_healthy
    environment:
      NORMALIZER_SOURCE: "zeek.http"
      KAFKA_BOOTSTRAP: "kafka:9092"

  normalizer-zeek-files:
    image: intellifim-normalizer:dev
    container_name: normalizer-zeek-files
    networks: [bus]
    depends_on:
      kafka:
        condition: service_healthy
    environment:
      NORMALIZER_SOURCE: "zeek.files"
      KAFKA_BOOTSTRAP: "kafka:9092"
```

- [ ] **Step 2: Rebuild image (if not already done in Task 12)**

```bash
docker build -f data-plane/normalizers/Dockerfile -t intellifim-normalizer:dev data-plane
```

- [ ] **Step 3: Bring full stack up**

```bash
cd data-plane
docker compose --env-file .env.dataplane up -d
./scripts/create-topics.sh
```

- [ ] **Step 4: Confirm normalizers are running and consuming**

```bash
docker compose --env-file .env.dataplane ps | grep normalizer
docker logs normalizer-zeek-conn 2>&1 | tail -n 5
```

Expected: 6 normalizer containers in `Up` state. Logs show "starting normalizer source=zeek.conn ...".

- [ ] **Step 5: End-to-end smoke test**

```bash
# Trigger a FIM event
echo "smoke-$(date +%s)" > monitored/smoke.txt
sleep 15
# Read from events.normalized
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka:9092 --topic events.normalized --from-beginning --max-messages 5 --timeout-ms 60000
```

Expected: at least one canonical event with `"event_type": "file.created"` or `"file.modified"` and `"source": "wazuh.fim"`. Should also see `"source": "zeek.conn"` events from the victim traffic.

- [ ] **Step 6: Bring down**

```bash
docker compose --env-file .env.dataplane down
```

- [ ] **Step 7: Commit**

```bash
git add data-plane/docker-compose.yml
git commit -m "feat(compose): wire six normalizers into the data-plane stack"
```

---

## Phase 6 — Test Utilities & Documentation

### Task 18: `tail-normalized.py` consumer

**Files:**
- Create: `data-plane/scripts/tail-normalized.py`

- [ ] **Step 1: Write the script**

```python
#!/usr/bin/env python3
# data-plane/scripts/tail-normalized.py
"""Subscribe to events.normalized and pretty-print canonical events.

Usage:
    pip install -e data-plane/schemas
    pip install aiokafka
    python data-plane/scripts/tail-normalized.py [--bootstrap localhost:9094]

The default bootstrap address assumes you're running the data-plane via
docker compose and have exposed Kafka on localhost:9094 (see README for
how to do that). When run inside the Compose network, pass --bootstrap
kafka:9092.
"""
from __future__ import annotations

import argparse
import asyncio
import json

from aiokafka import AIOKafkaConsumer

from intellifim_schemas import CanonicalEvent


async def _tail(bootstrap: str) -> None:
    consumer = AIOKafkaConsumer(
        "events.normalized",
        bootstrap_servers=bootstrap,
        group_id=None,  # don't commit offsets — this is a one-shot tail
        auto_offset_reset="latest",
    )
    await consumer.start()
    try:
        async for msg in consumer:
            try:
                event = CanonicalEvent.model_validate_json(msg.value)
            except Exception as exc:  # noqa: BLE001
                print(f"INVALID: {exc}\n  raw={msg.value[:200]!r}")
                continue
            line = json.dumps(
                {
                    "ts": event.timestamp.isoformat(),
                    "type": event.event_type,
                    "source": event.source,
                    "host": event.host_id,
                    "user": event.user,
                    "file": event.file_path,
                    "src": str(event.src_ip) if event.src_ip else None,
                    "dst": str(event.dst_ip) if event.dst_ip else None,
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

- [ ] **Step 2: Make it executable**

```bash
chmod +x data-plane/scripts/tail-normalized.py
```

- [ ] **Step 3: Expose Kafka on a host port for tools running outside Compose**

In `data-plane/docker-compose.yml`, modify the `kafka` service: add a second listener and a host port mapping.

Replace the `KAFKA_CFG_LISTENERS` and `KAFKA_CFG_ADVERTISED_LISTENERS` env vars with:

```yaml
      KAFKA_CFG_LISTENERS: "PLAINTEXT://:9092,CONTROLLER://:9093,EXTERNAL://:9094"
      KAFKA_CFG_ADVERTISED_LISTENERS: "PLAINTEXT://kafka:9092,EXTERNAL://localhost:9094"
      KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP: "CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,EXTERNAL:PLAINTEXT"
```

Add a port mapping under the `kafka` service:

```yaml
    ports:
      - "9094:9094"
```

- [ ] **Step 4: Test the script end-to-end**

```bash
cd data-plane
docker compose --env-file .env.dataplane up -d
./scripts/create-topics.sh
# In a second terminal:
python scripts/tail-normalized.py --bootstrap localhost:9094 &
TAIL_PID=$!
# In a third terminal (or the original):
echo "tail-test-$(date +%s)" > monitored/tail-test.txt
sleep 20
kill $TAIL_PID 2>/dev/null || true
docker compose --env-file .env.dataplane down
```

Expected: the tail script prints at least one JSON line per canonical event (FIM event from the touch + ongoing zeek.conn events from the victim traffic).

- [ ] **Step 5: Commit**

```bash
git add data-plane/scripts/tail-normalized.py data-plane/docker-compose.yml
git commit -m "feat(scripts): add tail-normalized.py and expose Kafka on host port 9094"
```

---

### Task 19: `seed-test-traffic.sh`

A one-shot script that produces a deterministic burst of FIM and network events for demos and smoke tests.

**Files:**
- Create: `data-plane/scripts/seed-test-traffic.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# data-plane/scripts/seed-test-traffic.sh
# Produces a small, deterministic burst of FIM and network events
# against an already-running data-plane stack.
set -euo pipefail

MONITORED_DIR="${MONITORED_DIR:-./monitored}"

if [ ! -d "${MONITORED_DIR}" ]; then
  echo "monitored dir ${MONITORED_DIR} does not exist" >&2
  exit 1
fi

stamp=$(date +%s)
echo "seeding FIM events under ${MONITORED_DIR}/seed-${stamp}/"
mkdir -p "${MONITORED_DIR}/seed-${stamp}"
echo "alpha"  > "${MONITORED_DIR}/seed-${stamp}/a.txt"
echo "bravo"  > "${MONITORED_DIR}/seed-${stamp}/b.txt"
echo "charlie modified" > "${MONITORED_DIR}/seed-${stamp}/a.txt"
rm "${MONITORED_DIR}/seed-${stamp}/b.txt"

echo "seeding network events through victim-client → victim-server"
docker exec victim-client sh -c '
  for path in / /seed-1 /seed-2 /seed-3; do
    curl -s -o /dev/null "http://victim-server${path}" || true
  done
' || echo "(victim-client not running — skipping network seed)"

echo "done. wait ~15s, then check events.normalized."
```

```bash
chmod +x data-plane/scripts/seed-test-traffic.sh
```

- [ ] **Step 2: Verify**

```bash
cd data-plane
docker compose --env-file .env.dataplane up -d
./scripts/create-topics.sh
sleep 30  # let the stack settle
./scripts/seed-test-traffic.sh
sleep 20
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka:9092 --topic events.normalized \
  --from-beginning --max-messages 10 --timeout-ms 30000 \
  | grep -c '"source"'
docker compose --env-file .env.dataplane down
```

Expected: count is at least 5 (FIM events + a few network flow events).

- [ ] **Step 3: Commit**

```bash
git add data-plane/scripts/seed-test-traffic.sh
git commit -m "feat(scripts): add seed-test-traffic.sh for deterministic event bursts"
```

---

### Task 20: `replay-pcap.sh` + curated pcap

**Files:**
- Create: `data-plane/pcaps/README.md`
- Create: `data-plane/pcaps/http_get_basic.pcap` (binary; instructions below to capture)
- Create: `data-plane/scripts/replay-pcap.sh`

- [ ] **Step 1: Capture a small reference pcap**

Bring the stack up and capture a single HTTP GET against the victim server:

```bash
cd data-plane
docker compose --env-file .env.dataplane up -d zeek-sensor victim-server victim-client
sleep 15
docker exec zeek-sensor sh -c "apt-get update -qq && apt-get install -y -qq tcpdump >/dev/null"
docker exec zeek-sensor sh -c "timeout 10 tcpdump -i eth1 -w /tmp/http_get_basic.pcap host victim-server and tcp port 80" || true
docker cp zeek-sensor:/tmp/http_get_basic.pcap pcaps/http_get_basic.pcap
docker compose --env-file .env.dataplane down
```

Expected: `pcaps/http_get_basic.pcap` exists and is non-empty (a few KB).

- [ ] **Step 2: Add the pcaps README**

```markdown
# Curated PCAPs

These captures are used by `scripts/replay-pcap.sh` to inject deterministic
network traffic at the Zeek sensor.

| File | Description | Expected canonical events |
|---|---|---|
| `http_get_basic.pcap` | Single HTTP GET from victim-client to victim-server. | One `network.flow` (zeek.conn), one `network.http_request` (zeek.http), possibly one `network.file_transfer` (zeek.files). |

## Capturing a new pcap

1. Bring up `zeek-sensor` and the victim containers.
2. `docker exec zeek-sensor tcpdump -i eth1 -w /tmp/<name>.pcap <bpf-filter>`
3. Generate the traffic in another shell.
4. `docker cp zeek-sensor:/tmp/<name>.pcap pcaps/<name>.pcap`
5. Add the file to this table.
```

- [ ] **Step 3: Add the replay script**

```bash
#!/usr/bin/env bash
# data-plane/scripts/replay-pcap.sh
# Replay a pcap into the Zeek sensor's monitored network.
#
# Usage:
#   scripts/replay-pcap.sh pcaps/http_get_basic.pcap
#
# The pcap is copied into the zeek-sensor container, replayed via
# tcpreplay onto the same interface Zeek is listening on, then deleted.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <pcap-file>" >&2
  exit 1
fi

pcap="$1"
if [ ! -f "${pcap}" ]; then
  echo "pcap not found: ${pcap}" >&2
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q '^zeek-sensor$'; then
  echo "zeek-sensor container is not running" >&2
  exit 1
fi

echo "ensuring tcpreplay is available inside zeek-sensor"
docker exec zeek-sensor sh -c "command -v tcpreplay >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq tcpreplay >/dev/null)"

echo "copying ${pcap} → zeek-sensor:/tmp/replay.pcap"
docker cp "${pcap}" zeek-sensor:/tmp/replay.pcap

echo "replaying onto eth1"
docker exec zeek-sensor tcpreplay -i eth1 -K /tmp/replay.pcap

docker exec zeek-sensor rm -f /tmp/replay.pcap
echo "done. Zeek should produce logs within a second; canonical events follow within ~15s."
```

```bash
chmod +x data-plane/scripts/replay-pcap.sh
```

- [ ] **Step 4: Verify replay end-to-end**

```bash
cd data-plane
docker compose --env-file .env.dataplane up -d
./scripts/create-topics.sh
sleep 30
./scripts/replay-pcap.sh pcaps/http_get_basic.pcap
sleep 20
docker exec kafka /opt/bitnami/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka:9092 --topic events.normalized \
  --from-beginning --max-messages 20 --timeout-ms 30000 \
  | grep -c '"source":"zeek'
docker compose --env-file .env.dataplane down
```

Expected: count is at least 1 (one zeek.conn / zeek.http event from the replay).

- [ ] **Step 5: Commit**

```bash
git add data-plane/pcaps data-plane/scripts/replay-pcap.sh
git commit -m "feat(scripts): add replay-pcap.sh and reference http_get_basic.pcap"
```

---

### Task 21: README

**Files:**
- Create: `data-plane/README.md`

- [ ] **Step 1: Write the README**

```markdown
# IntelliFIM Data Plane (v1 — walking skeleton)

Self-contained Docker Compose stack that delivers validated, canonical
security events from a Linux endpoint and a network sensor into the
`events.normalized` Kafka topic. This is the foundation every other
IntelliFIM sub-project (correlation, ML, scoring, dashboard) consumes.

See [`docs/superpowers/specs/2026-05-04-data-plane-v1-design.md`](../docs/superpowers/specs/2026-05-04-data-plane-v1-design.md)
for the full design. v2 (Schema Registry, observability, secrets) and
v3 (HA Kafka, K8s, multi-agent) are explicit follow-ups.

## What's in the box

13 services on Docker Compose:

- **Sources:** `wazuh-manager`, `wazuh-agent`, `zeek-sensor`
- **Shipping:** `filebeat-wazuh`, `filebeat-zeek`
- **Bus:** `kafka` (single broker, KRaft mode)
- **Normalizers:** `normalizer-wazuh-fim`, `normalizer-wazuh-auth`,
  `normalizer-zeek-conn`, `normalizer-zeek-dns`, `normalizer-zeek-http`,
  `normalizer-zeek-files`
- **Dev tooling:** `kafka-ui`, `victim-server`, `victim-client`

## Prerequisites

- Docker Engine ≥ 24 with Compose v2
- ~4 GB free RAM, ~5 GB disk
- Python 3.12 (only if you want to run `tail-normalized.py` from the host)

## Bring up the stack

```bash
cd data-plane

# 1. One-time: prepare env file and the FIM monitored dir.
cp .env.dataplane.example .env.dataplane
mkdir -p monitored

# 2. Build the normalizer image.
docker build -f normalizers/Dockerfile -t intellifim-normalizer:dev .

# 3. Start everything.
docker compose --env-file .env.dataplane up -d

# 4. Create Kafka topics (idempotent — safe to re-run).
./scripts/create-topics.sh
```

Wait ~90 seconds for Wazuh agent enrollment and Zeek to start writing logs.

## See events flow

### Browser

Open [http://localhost:8080](http://localhost:8080) for `kafka-ui`.
Topics → `events.normalized` → Messages.

### Terminal

```bash
# Install the schema package once
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

## Consume canonical events from a downstream service

The canonical schema lives in the `intellifim-schemas` package. Any
sub-project that consumes events should depend on it directly:

```python
# pyproject.toml
[project]
dependencies = [
    "intellifim-schemas==0.1.0",
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

## Tear down

```bash
docker compose --env-file .env.dataplane down       # keep volumes
docker compose --env-file .env.dataplane down -v    # also wipe Kafka data, Wazuh state
```

## Running the unit tests

```bash
pip install -e schemas[dev]
pip install -e normalizers[dev]
pytest schemas/tests normalizers/tests -v
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
5. `pytest schemas/tests normalizers/tests` is green.
```

- [ ] **Step 2: Final smoke test against the README's instructions**

Follow the "Bring up the stack" steps verbatim from a clean state:

```bash
cd data-plane
docker compose --env-file .env.dataplane down -v 2>/dev/null || true
docker rmi intellifim-normalizer:dev 2>/dev/null || true
# Now follow the README from "Bring up the stack" through "Tail canonical events"
```

Expected: every command in the README works; canonical events appear within 60 s of bring-up.

- [ ] **Step 3: Commit**

```bash
git add data-plane/README.md
git commit -m "docs(data-plane): add README covering bring-up, demo, and consumer integration"
```

- [ ] **Step 4: Open the PR**

```bash
git push -u origin feat/data-plane-v1
gh pr create --title "feat: data-plane v1 (walking skeleton)" --body "$(cat <<'EOF'
## Summary
Implements the data-plane v1 walking skeleton per
[docs/superpowers/specs/2026-05-04-data-plane-v1-design.md](docs/superpowers/specs/2026-05-04-data-plane-v1-design.md).

- `intellifim-schemas` Python package: `CanonicalEvent` Pydantic v2 model.
- `intellifim-normalizers` Python package: shared base loop + six per-source normalizers.
- Single Dockerfile shared by all six normalizer services.
- Docker Compose stack: Kafka (KRaft), kafka-ui, Wazuh manager + agent, Zeek sensor + victim containers, two Filebeat shippers, six normalizers.
- Test utilities: `tail-normalized.py`, `seed-test-traffic.sh`, `replay-pcap.sh` + reference pcap.

## Test plan
- [ ] `pytest data-plane/schemas/tests data-plane/normalizers/tests -v` — all green.
- [ ] `cd data-plane && docker compose up -d && ./scripts/create-topics.sh` succeeds.
- [ ] `echo x > monitored/x.txt` → canonical `file.modified` event visible on `events.normalized` within 5 s.
- [ ] `./scripts/seed-test-traffic.sh` produces both FIM and network events.
- [ ] `./scripts/replay-pcap.sh pcaps/http_get_basic.pcap` produces zeek.* events.
EOF
)"
```

Expected: PR created with link printed.

---

## Self-review checklist (already run)

- **Spec coverage:** every section of the spec has at least one task —
  containers (13–17), schema (2), normalizers (4–11), test traffic (15, 19, 20),
  Definition-of-Done items (covered by 21 step 2).
- **No placeholders:** every step has concrete code, paths, and commands.
- **Type/method consistency:** `CanonicalEvent` field names in Task 2 match
  every reference in Tasks 4–11 and `tail-normalized.py` in Task 18.
  `NORMALIZER_SOURCE` env var name is identical in Tasks 5, 12, 17.
  Topic names match across Tasks 5 (`SOURCE_TO_INPUT_TOPIC`), 13
  (`create-topics.sh`), 16 (Filebeat config), 17 (normalizer compose env).
