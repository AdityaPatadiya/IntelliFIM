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
