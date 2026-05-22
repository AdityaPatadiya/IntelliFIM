"""Env-var parser for the reporting service.

Fail-fast on missing required fields; conservative defaults for the rest.
URL validation is intentionally cheap — full URL parsing is httpx's job.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


class ReportingConfigError(ValueError):
    """Raised when env-var parsing fails."""


def _int_env(name: str, default: str) -> int:
    raw = os.environ.get(name) or default
    try:
        return int(raw)
    except ValueError as e:
        raise ReportingConfigError(
            f"{name} must be an integer, got {raw!r}"
        ) from e


@dataclass(frozen=True)
class ReportingConfig:
    jwt_secret: str
    kafka_bootstrap: str
    orchestrator_url: str
    db_path: str
    reports_dir: str
    bind_host: str
    port: int
    jwt_ttl_seconds: int
    cors_origins: tuple[str, ...]
    kafka_topic: str
    kafka_group_id: str

    @classmethod
    def from_env(cls) -> "ReportingConfig":
        for k in ("JWT_SECRET", "KAFKA_BOOTSTRAP", "ORCHESTRATOR_URL"):
            if not os.environ.get(k):
                raise ReportingConfigError(f"missing required env var: {k}")

        orchestrator_url = os.environ["ORCHESTRATOR_URL"]
        parsed = urlparse(orchestrator_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ReportingConfigError(
                f"ORCHESTRATOR_URL must be an http(s) URL with a host; got {orchestrator_url!r}"
            )

        cors = os.environ.get("CORS_ORIGINS", "http://localhost:5173")
        cors_origins = tuple(o.strip() for o in cors.split(",") if o.strip())

        return cls(
            jwt_secret=os.environ["JWT_SECRET"],
            kafka_bootstrap=os.environ["KAFKA_BOOTSTRAP"],
            orchestrator_url=orchestrator_url,
            db_path=os.environ.get("DB_PATH", "/data/reporting.db"),
            reports_dir=os.environ.get("REPORTS_DIR", "/data/reports"),
            bind_host=os.environ.get("BIND_HOST", "0.0.0.0"),
            port=_int_env("PORT", "8300"),
            jwt_ttl_seconds=_int_env("JWT_TTL_SECONDS", str(8 * 60 * 60)),
            cors_origins=cors_origins,
            kafka_topic=os.environ.get("KAFKA_TOPIC", "threat.scores"),
            kafka_group_id=os.environ.get("KAFKA_GROUP_ID", "intellifim-reporting"),
        )
