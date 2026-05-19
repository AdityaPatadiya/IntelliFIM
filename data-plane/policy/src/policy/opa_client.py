"""Async HTTP client for OPA's REST API.

Returns the OPA decision dict on success, or None (logged) on any failure
mode (transport error, timeout, 4xx, 5xx, malformed response). The engine
treats None as 'skip this event' — never crash the loop.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from intellifim_schemas import ScoredEvent

log = logging.getLogger(__name__)

_QUERY_PATH = "/v1/data/intellifim/policy/decision"


class OpaClient:
    def __init__(self, opa_url: str, *, timeout_seconds: float = 2.0) -> None:
        self._url = opa_url.rstrip("/") + _QUERY_PATH
        self._client = httpx.AsyncClient(timeout=timeout_seconds)

    async def query(self, event: ScoredEvent) -> dict[str, Any] | None:
        body = {"input": {"event": event.model_dump(mode="json")}}
        try:
            response = await self._client.post(self._url, json=body)
        except httpx.RequestError as exc:
            log.warning("OPA query failed (%s)", exc)
            return None
        if response.status_code != 200:
            log.warning(
                "OPA returned status=%d body=%s", response.status_code, response.text[:200]
            )
            return None
        try:
            payload = response.json()
        except Exception as exc:  # noqa: BLE001 - any parse failure is a skip
            log.warning("OPA returned non-JSON body (%s)", exc)
            return None
        result = payload.get("result")
        if not isinstance(result, dict):
            log.warning("OPA response missing/invalid 'result' key: %s", payload)
            return None
        return result

    async def aclose(self) -> None:
        await self._client.aclose()
