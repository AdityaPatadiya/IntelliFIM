from __future__ import annotations

import asyncio
import importlib
import logging

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from normalizers.base import NormalizerLoop
from normalizers.config import NormalizerConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("normalizers")


def _load_transform(source: str):
    # source "wazuh.fim" → module normalizers.wazuh_fim, function `transform`
    module_name = "normalizers." + source.replace(".", "_")
    module = importlib.import_module(module_name)
    return module.transform


async def _run() -> None:
    cfg = NormalizerConfig.from_env()
    transform = _load_transform(cfg.source)

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

    log.info("starting normalizer source=%s in=%s out=%s", cfg.source, cfg.input_topic, cfg.output_topic)

    # Nested try/finally so we clean up only what we successfully started.
    # If producer.start() raises, the outer finally still stops the consumer.
    await consumer.start()
    try:
        await producer.start()
        try:
            loop = NormalizerLoop(
                consumer=consumer,
                producer=producer,
                output_topic=cfg.output_topic,
                transform=transform,
            )
            await loop.run()
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
