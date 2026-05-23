from __future__ import annotations

import asyncio
import logging
import os

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from prometheus_client import start_http_server

from policy.config import PolicyConfig
from policy.engine import PolicyEngine
from policy.opa_client import OpaClient
from policy.redis_store import RedisScoreStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("policy")


async def _run() -> None:
    cfg = PolicyConfig.from_env()

    # Start metrics HTTP server (bound to all interfaces inside container; published
    # only via 127.0.0.1 in compose). Spun up before the consume loop so Prometheus
    # can scrape immediately on container start.
    metrics_port = int(os.environ.get("METRICS_PORT", "9102"))
    start_http_server(metrics_port)

    # auto_offset_reset="latest": skip historical backlog on fresh restart.
    # v1 walking-skeleton / live demo. v2 should reconsider.
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
        "starting policy-engine in=%s out=%s opa=%s redis=%s window=%ds",
        cfg.input_topic, cfg.output_topic, cfg.opa_url, cfg.redis_url, cfg.window_seconds,
    )

    # Nested try/finally so we clean up only what we successfully started.
    await consumer.start()
    try:
        await producer.start()
        try:
            opa = OpaClient(cfg.opa_url)
            store = RedisScoreStore(cfg.redis_url)
            try:
                engine = PolicyEngine(
                    consumer=consumer,
                    producer=producer,
                    output_topic=cfg.output_topic,
                    opa=opa,
                    store=store,
                    window_seconds=cfg.window_seconds,
                )
                await engine.run()
            finally:
                await store.aclose()
                await opa.aclose()
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
