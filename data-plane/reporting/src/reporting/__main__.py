"""Reporting service entry point.

Pattern: nested try/finally over store / orchestrator / consumer; uvicorn
Server runs in the same event loop as the Kafka consumer task. Lifespan
matches the orchestrator's aiohttp+aiokafka co-resident pattern.

`intellifim-reporting` (console_scripts entry in pyproject.toml) invokes
`main()`.
"""
from __future__ import annotations

import asyncio
import logging

import uvicorn

from reporting.api import build_app
from reporting.config import ReportingConfig
from reporting.consumer import KafkaScoreConsumer
from reporting.orchestrator_client import OrchestratorClient
from reporting.store import ReportingStore


logger = logging.getLogger(__name__)


async def _run(cfg: ReportingConfig) -> None:
    store = ReportingStore(db_path=cfg.db_path, reports_dir=cfg.reports_dir)
    await store.init_schema()
    try:
        orchestrator = OrchestratorClient(base_url=cfg.orchestrator_url)
        try:
            consumer = KafkaScoreConsumer(
                store=store,
                bootstrap=cfg.kafka_bootstrap,
                topic=cfg.kafka_topic,
                group_id=cfg.kafka_group_id,
            )
            await consumer.start()
            try:
                app = build_app(
                    store=store,
                    orchestrator=orchestrator,
                    jwt_secret=cfg.jwt_secret,
                    jwt_ttl_seconds=cfg.jwt_ttl_seconds,
                    cors_origins=cfg.cors_origins,
                )
                server_config = uvicorn.Config(
                    app,
                    host=cfg.bind_host,
                    port=cfg.port,
                    log_level="info",
                    access_log=False,
                    loop="asyncio",
                )
                server = uvicorn.Server(server_config)

                consumer_task = asyncio.create_task(
                    consumer.run(), name="kafka-score-consumer"
                )

                logger.info(
                    "reporting service listening: %s:%s | jwt=enabled | "
                    "kafka=%s topic=%s",
                    cfg.bind_host, cfg.port, cfg.kafka_bootstrap, cfg.kafka_topic,
                )

                try:
                    await server.serve()
                finally:
                    consumer_task.cancel()
                    try:
                        await consumer_task
                    except asyncio.CancelledError:
                        pass
            finally:
                await consumer.stop()
        finally:
            await orchestrator.aclose()
    finally:
        await store.aclose()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )
    cfg = ReportingConfig.from_env()
    asyncio.run(_run(cfg))


if __name__ == "__main__":
    main()
