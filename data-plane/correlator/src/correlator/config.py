from __future__ import annotations

import os
from dataclasses import dataclass

INPUT_TOPIC = "events.normalized"
OUTPUT_TOPIC = "events.correlated"


@dataclass(frozen=True)
class CorrelatorConfig:
    bootstrap_servers: str
    window_seconds: int
    consumer_group: str
    input_topic: str = INPUT_TOPIC
    output_topic: str = OUTPUT_TOPIC

    @classmethod
    def from_env(cls) -> "CorrelatorConfig":
        window_str = os.environ.get("CORRELATION_WINDOW_SECONDS", "60")
        try:
            window = int(window_str)
        except ValueError as exc:
            raise ValueError(
                f"CORRELATION_WINDOW_SECONDS must be a positive integer, got {window_str!r}"
            ) from exc
        if window <= 0:
            raise ValueError(
                f"CORRELATION_WINDOW_SECONDS must be a positive integer, got {window}"
            )
        return cls(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092"),
            window_seconds=window,
            consumer_group=os.environ.get("CONSUMER_GROUP", "correlation-engine"),
        )
