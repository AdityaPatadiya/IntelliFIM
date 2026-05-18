from __future__ import annotations

import asyncio
import logging
import pickle
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from anomaly.config import AnomalyConfig
from anomaly.engine import AnomalyEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("anomaly")


def _load_model(path: str) -> tuple[Any, list[str], str]:
    """Load the pickled training bundle. Fail-fast if missing or malformed —
    an inference service without a model is meaningless."""
    with open(path, "rb") as f:
        bundle = pickle.load(f)
    return bundle["model"], bundle["feature_names"], bundle["model_version"]


async def _run() -> None:
    cfg = AnomalyConfig.from_env()
    model, feature_names, model_version = _load_model(cfg.model_path)

    # auto_offset_reset="latest": on a fresh restart, skip the historical
    # backlog. v1 is a walking skeleton / live demo. Production should
    # reconsider — see plan v2.
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
        "starting anomaly-detector in=%s out=%s model=%s threshold=%.3f",
        cfg.input_topic, cfg.output_topic, model_version, cfg.threshold,
    )

    # Nested try/finally so we clean up only what we successfully started.
    await consumer.start()
    try:
        await producer.start()
        try:
            engine = AnomalyEngine(
                consumer=consumer,
                producer=producer,
                output_topic=cfg.output_topic,
                model=model,
                feature_names=feature_names,
                model_version=model_version,
                threshold=cfg.threshold,
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
