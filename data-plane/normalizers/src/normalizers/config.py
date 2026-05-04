from __future__ import annotations

import os
from dataclasses import dataclass

SOURCE_TO_INPUT_TOPIC = {
    "wazuh.fim": "wazuh.fim",
    "wazuh.auth": "wazuh.auth",
    "zeek.conn": "zeek.conn",
    "zeek.dns": "zeek.dns",
    "zeek.http": "zeek.http",
    "zeek.files": "zeek.files",
}

OUTPUT_TOPIC = "events.normalized"


@dataclass(frozen=True)
class NormalizerConfig:
    source: str
    input_topic: str
    output_topic: str
    bootstrap_servers: str
    consumer_group: str

    @classmethod
    def from_env(cls) -> "NormalizerConfig":
        source = os.environ["NORMALIZER_SOURCE"]
        if source not in SOURCE_TO_INPUT_TOPIC:
            raise ValueError(
                f"NORMALIZER_SOURCE={source!r} is not one of {sorted(SOURCE_TO_INPUT_TOPIC)}"
            )
        return cls(
            source=source,
            input_topic=SOURCE_TO_INPUT_TOPIC[source],
            output_topic=OUTPUT_TOPIC,
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092"),
            consumer_group=f"normalizer-{source.replace('.', '-')}",
        )
