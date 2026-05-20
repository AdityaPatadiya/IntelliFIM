# data-plane/orchestrator/src/orchestrator/config.py
from __future__ import annotations

import os
from dataclasses import dataclass

INPUT_TOPIC = "threat.scores"


@dataclass(frozen=True)
class OrchestratorConfig:
    bootstrap_servers: str
    consumer_group: str
    db_path: str
    api_host: str
    api_port: int
    wazuh_manager_url: str
    wazuh_api_user: str
    wazuh_api_password: str
    tier_low_threshold: float
    tier_high_threshold: float
    jwt_secret: str
    cors_origins: list[str]
    input_topic: str = INPUT_TOPIC

    @classmethod
    def from_env(cls) -> "OrchestratorConfig":
        api_port = _parse_port(os.environ.get("API_PORT", "8200"))
        low = _parse_threshold(os.environ.get("TIER_LOW_THRESHOLD", "30"), "TIER_LOW_THRESHOLD")
        high = _parse_threshold(os.environ.get("TIER_HIGH_THRESHOLD", "70"), "TIER_HIGH_THRESHOLD")
        if low <= 0:
            raise ValueError(f"TIER_LOW_THRESHOLD must be > 0, got {low}")
        if high > 100:
            raise ValueError(f"TIER_HIGH_THRESHOLD must be <= 100, got {high}")
        if low >= high:
            raise ValueError(
                f"TIER_LOW_THRESHOLD ({low}) must be < TIER_HIGH_THRESHOLD ({high})"
            )
        jwt_secret = os.environ.get("JWT_SECRET")
        if not jwt_secret:
            raise ValueError("JWT_SECRET env var is required (no default)")
        cors_raw = os.environ.get(
            "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        )
        cors_origins = [s.strip() for s in cors_raw.split(",") if s.strip()]
        return cls(
            bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092"),
            consumer_group=os.environ.get("CONSUMER_GROUP", "response-orchestrator"),
            db_path=os.environ.get("DB_PATH", "/data/approvals.db"),
            api_host=os.environ.get("API_HOST", "0.0.0.0"),
            api_port=api_port,
            wazuh_manager_url=os.environ.get("WAZUH_MANAGER_URL", "https://wazuh-manager:55000"),
            wazuh_api_user=os.environ.get("WAZUH_API_USER", "wazuh"),
            wazuh_api_password=os.environ.get("WAZUH_API_PASSWORD", "wazuh"),
            tier_low_threshold=low,
            tier_high_threshold=high,
            jwt_secret=jwt_secret,
            cors_origins=cors_origins,
        )


def _parse_port(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"API_PORT must be a positive integer 1-65535, got {raw!r}") from exc
    if port < 1 or port > 65535:
        raise ValueError(f"API_PORT must be 1-65535, got {port}")
    return port


def _parse_threshold(raw: str, name: str) -> float:
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc
