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
