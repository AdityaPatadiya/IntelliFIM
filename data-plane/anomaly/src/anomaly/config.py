from __future__ import annotations

import os
from dataclasses import dataclass

INPUT_TOPIC = "events.normalized"
OUTPUT_TOPIC = "events.scored"


@dataclass(frozen=True)
class AnomalyConfig:
    bootstrap_servers: str
    consumer_group: str
    threshold: float
    model_path: str
    input_topic: str = INPUT_TOPIC
    output_topic: str = OUTPUT_TOPIC

    @classmethod
    def from_env(cls) -> "AnomalyConfig":
        raw = os.environ.get("ANOMALY_THRESHOLD", "0.5")
        try:
            threshold = float(raw)
        except ValueError as exc:
            raise ValueError(
                f"ANOMALY_THRESHOLD must be a float in [0,1], got {raw!r}"
            ) from exc
        if not (0.0 <= threshold <= 1.0):
            raise ValueError(
                f"ANOMALY_THRESHOLD must be in [0,1], got {threshold}"
            )
        return cls(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092"),
            consumer_group=os.environ.get("CONSUMER_GROUP", "anomaly-detector"),
            threshold=threshold,
            model_path=os.environ.get("MODEL_PATH", "/app/model.pkl"),
        )
