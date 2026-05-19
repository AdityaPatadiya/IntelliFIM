"""Async HTTP client for the Wazuh Manager REST API.

Authenticates with the manager and dispatches Active Response commands.
Failure surfaces as WazuhDispatchError (NOT swallowed) so the orchestrator's
/approve handler can mark the row state=FAILED + capture error_message.

v1 uses verify=False (self-signed dev cert). v2 swaps to a real cert.
"""
from __future__ import annotations

import json
import logging

import httpx

log = logging.getLogger(__name__)

_AUTH_PATH = "/security/user/authenticate"
_AR_PATH = "/active-response"


class WazuhDispatchError(Exception):
    """Raised when the Wazuh Manager cannot accept or process an AR command."""


class WazuhClient:
    def __init__(
        self,
        manager_url: str,
        user: str,
        password: str,
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._base = manager_url.rstrip("/")
        self._user = user
        self._password = password
        # verify=False is intentional for v1 (dev self-signed cert);
        # surfaced as INFO log at startup in __main__.py.
        self._client = httpx.AsyncClient(timeout=timeout_seconds, verify=False)
        self._token: str | None = None

    async def authenticate(self) -> None:
        try:
            response = await self._client.post(
                f"{self._base}{_AUTH_PATH}",
                auth=(self._user, self._password),
            )
        except httpx.RequestError as exc:
            raise WazuhDispatchError(f"authenticate transport failure: {exc}") from exc
        if response.status_code != 200:
            raise WazuhDispatchError(
                f"authenticate returned {response.status_code}: {response.text[:200]}"
            )
        try:
            self._token = response.json()["data"]["token"]
        except (KeyError, TypeError, ValueError) as exc:
            raise WazuhDispatchError(f"authenticate response malformed: {exc}") from exc

    async def run_active_response(
        self,
        *,
        agent_id: str,
        command: str,
        arguments: list[str],
    ) -> None:
        if self._token is None:
            await self.authenticate()
        # Wazuh 4.x API contract: agent target via query string, body carries
        # the command (with `!` prefix for custom AR) + arguments + empty alert.
        body = {
            "command": command,
            "arguments": arguments,
            "alert": {},
        }
        response = await self._put_ar(agent_id, body)
        if response.status_code == 401:
            # Re-auth once and retry
            await self.authenticate()
            response = await self._put_ar(agent_id, body)
            if response.status_code == 401:
                raise WazuhDispatchError(
                    f"AR dispatch: two consecutive 401s; body={response.text[:200]}"
                )
        if response.status_code >= 500:
            raise WazuhDispatchError(
                f"AR dispatch returned {response.status_code}: {response.text[:200]}"
            )
        if response.status_code >= 400:
            raise WazuhDispatchError(
                f"AR dispatch rejected with {response.status_code}: {response.text[:200]}"
            )

    async def _put_ar(self, agent_id: str, body: dict) -> httpx.Response:
        try:
            return await self._client.put(
                f"{self._base}{_AR_PATH}",
                params={"agents_list": agent_id},
                content=json.dumps(body, separators=(",", ":")),
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
            )
        except httpx.RequestError as exc:
            raise WazuhDispatchError(f"AR dispatch transport failure: {exc}") from exc

    async def aclose(self) -> None:
        await self._client.aclose()
