from __future__ import annotations

import asyncio
import logging

import uvicorn

from auth_backend.api import build_app, seed_admin_if_missing
from auth_backend.config import AuthBackendConfig
from auth_backend.store import UsersStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("auth_backend")


async def _bootstrap(cfg: AuthBackendConfig) -> tuple[UsersStore, "uvicorn.Server"]:
    store = UsersStore(database_url=cfg.database_url)
    await store.init_schema()
    await seed_admin_if_missing(
        store=store, username=cfg.admin_username,
        email=cfg.admin_email, password=cfg.admin_password,
    )
    app = build_app(
        store=store,
        jwt_secret=cfg.jwt_secret,
        jwt_ttl_seconds=cfg.jwt_ttl_seconds,
        cors_origins=cfg.cors_origins,
    )
    config = uvicorn.Config(
        app=app, host=cfg.api_host, port=cfg.api_port,
        log_level="info", access_log=False,
    )
    server = uvicorn.Server(config)
    return store, server


async def _run() -> None:
    cfg = AuthBackendConfig.from_env()
    log.info(
        "starting auth-backend database_url=%s api=%s:%d jwt_ttl=%ds cors=%s",
        cfg.database_url, cfg.api_host, cfg.api_port,
        cfg.jwt_ttl_seconds, cfg.cors_origins,
    )
    store, server = await _bootstrap(cfg)
    try:
        await server.serve()
    finally:
        await store.aclose()


def main() -> None:
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        log.info("shutdown requested")


if __name__ == "__main__":
    main()
