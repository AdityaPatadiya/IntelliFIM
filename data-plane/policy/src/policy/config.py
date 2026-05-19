from __future__ import annotations

import os
from dataclasses import dataclass

INPUT_TOPIC = "events.scored"
OUTPUT_TOPIC = "threat.scores"


@dataclass(frozen=True)
class PolicyConfig:
    bootstrap_servers: str
    consumer_group: str
    opa_url: str
    redis_url: str
    window_seconds: int
    input_topic: str = INPUT_TOPIC
    output_topic: str = OUTPUT_TOPIC

    @classmethod
    def from_env(cls) -> "PolicyConfig":
        raw = os.environ.get("THREAT_SCORE_WINDOW_SECONDS", "300")
        try:
            window = int(raw)
        except ValueError as exc:
            raise ValueError(
                f"THREAT_SCORE_WINDOW_SECONDS must be a positive integer, got {raw!r}"
            ) from exc
        if window <= 0:
            raise ValueError(
                f"THREAT_SCORE_WINDOW_SECONDS must be a positive integer, got {window}"
            )
        return cls(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092"),
            consumer_group=os.environ.get("CONSUMER_GROUP", "policy-engine"),
            opa_url=os.environ.get("OPA_URL", "http://opa:8181"),
            redis_url=os.environ.get("REDIS_URL", "redis://redis:6379/0"),
            window_seconds=window,
        )
