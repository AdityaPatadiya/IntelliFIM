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
