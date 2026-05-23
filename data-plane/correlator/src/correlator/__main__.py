from __future__ import annotations

import asyncio
import logging
import os

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from prometheus_client import start_http_server

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

    # Start metrics HTTP server (bound to all interfaces inside container; published
    # only via 127.0.0.1 in compose). Spun up before the consume loop so Prometheus
    # can scrape immediately on container start.
    metrics_port = int(os.environ.get("METRICS_PORT", "9100"))
    start_http_server(metrics_port)

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
