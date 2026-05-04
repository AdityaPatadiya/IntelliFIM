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
