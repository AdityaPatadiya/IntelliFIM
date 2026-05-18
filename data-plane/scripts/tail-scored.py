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
