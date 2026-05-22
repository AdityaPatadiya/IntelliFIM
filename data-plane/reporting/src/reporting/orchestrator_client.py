"""HTTP client wrapper for the response-orchestrator /approvals API.

Single shared httpx.AsyncClient instance per process. `aclose()` discipline
matches OpaClient + RedisScoreStore from sub-project #4.
"""
from __future__ import annotations

from typing import Any

import httpx


class OrchestratorError(RuntimeError):
    """Raised when the orchestrator returns a non-2xx or is unreachable."""

    def __init__(self, message: str, *, status: int) -> None:
        super().__init__(message)
        self.status = status


class OrchestratorClient:
    def __init__(self, base_url: str, *, timeout: float = 5.0) -> None:
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def list_approvals(self, *, jwt: str) -> list[dict[str, Any]]:
        """Fetch all approvals (no server-side filter in v1).

        Forwards the caller's Bearer token verbatim so the orchestrator's
        existing JWT middleware + RBAC sees the actual requesting user.
        """
        try:
            response = await self._client.get(
                "/approvals",
                headers={"Authorization": f"Bearer {jwt}"},
            )
        except httpx.RequestError as e:
            raise OrchestratorError(
                f"could not reach response-orchestrator: {e}", status=502
            ) from e
        if response.status_code >= 500:
            raise OrchestratorError(
                f"orchestrator returned {response.status_code}",
                status=response.status_code,
            )
        if response.status_code >= 400:
            raise OrchestratorError(
                f"orchestrator rejected request: {response.status_code} {response.text}",
                status=response.status_code,
            )
        data = response.json()
        # Orchestrator wraps the list under "approvals"; tolerate a bare list too.
        if isinstance(data, dict) and isinstance(data.get("approvals"), list):
            return data["approvals"]
        if isinstance(data, list):
            return data
        raise OrchestratorError(
            f"unexpected /approvals body shape: {type(data).__name__}", status=502
        )
