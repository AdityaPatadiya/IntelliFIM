from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthBackendConfig:
    database_url: str
    api_host: str
    api_port: int
    jwt_secret: str
    jwt_ttl_seconds: int
    cors_origins: list[str]
    admin_username: str
    admin_email: str
    admin_password: str

    @classmethod
    def from_env(cls) -> "AuthBackendConfig":
        jwt_secret = os.environ.get("JWT_SECRET")
        if not jwt_secret:
            raise ValueError("JWT_SECRET env var is required (no default)")
        database_url = os.environ.get("DATABASE_URL")
        if not database_url:
            raise ValueError("DATABASE_URL env var is required (no default)")
        admin_email = os.environ.get("ADMIN_EMAIL")
        if not admin_email:
            raise ValueError("ADMIN_EMAIL env var is required (no default)")
        admin_password = os.environ.get("ADMIN_PASSWORD")
        if not admin_password:
            raise ValueError("ADMIN_PASSWORD env var is required (no default)")
        cors_raw = os.environ.get(
            "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        )
        return cls(
            database_url=database_url,
            api_host=os.environ.get("API_HOST", "0.0.0.0"),
            api_port=int(os.environ.get("API_PORT", "8000")),
            jwt_secret=jwt_secret,
            jwt_ttl_seconds=int(os.environ.get("JWT_TTL_SECONDS", "28800")),
            cors_origins=[s.strip() for s in cors_raw.split(",") if s.strip()],
            admin_username=os.environ.get("ADMIN_USERNAME", "admin"),
            admin_email=admin_email,
            admin_password=admin_password,
        )
