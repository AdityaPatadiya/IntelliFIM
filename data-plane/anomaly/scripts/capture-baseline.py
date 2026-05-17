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
    loop = asyncio.get_running_loop()
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
