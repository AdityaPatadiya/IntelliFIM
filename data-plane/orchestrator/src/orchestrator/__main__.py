from __future__ import annotations

import asyncio
import logging

from aiohttp import web
from aiokafka import AIOKafkaConsumer

from orchestrator.api import build_api
from orchestrator.config import OrchestratorConfig
from orchestrator.engine import OrchestratorEngine
from orchestrator.store import ApprovalStore
from orchestrator.wazuh_client import WazuhClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("orchestrator")


async def _run() -> None:
    cfg = OrchestratorConfig.from_env()

    log.info(
        "starting response-orchestrator in=%s database_url=%s api=%s:%d wazuh=%s tiers=%.1f/%.1f jwt=enabled",
        cfg.input_topic, cfg.database_url, cfg.api_host, cfg.api_port,
        cfg.wazuh_manager_url, cfg.tier_low_threshold, cfg.tier_high_threshold,
    )
    log.info("connecting to Wazuh Manager with TLS verification disabled (dev only)")

    store = ApprovalStore(database_url=cfg.database_url)
    await store.init_schema()
    try:
        wazuh = WazuhClient(
            cfg.wazuh_manager_url, cfg.wazuh_api_user, cfg.wazuh_api_password,
        )
        try:
            consumer = AIOKafkaConsumer(
                cfg.input_topic,
                bootstrap_servers=cfg.bootstrap_servers,
                group_id=cfg.consumer_group,
                enable_auto_commit=True,
                auto_offset_reset="latest",
            )
            await consumer.start()
            try:
                api_app = build_api(
                    store=store, wazuh=wazuh,
                    jwt_secret=cfg.jwt_secret,
                    cors_origins=cfg.cors_origins,
                )
                runner = web.AppRunner(api_app)
                await runner.setup()
                site = web.TCPSite(runner, cfg.api_host, cfg.api_port)
                await site.start()
                try:
                    engine = OrchestratorEngine(
                        consumer=consumer,
                        store=store,
                        tier_low=cfg.tier_low_threshold,
                        tier_high=cfg.tier_high_threshold,
                    )
                    await engine.run()
                finally:
                    await runner.cleanup()
            finally:
                await consumer.stop()
        finally:
            await wazuh.aclose()
    finally:
        await store.aclose()


def main() -> None:
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        log.info("shutdown requested")


if __name__ == "__main__":
    main()
