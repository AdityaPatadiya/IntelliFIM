import httpx
import pytest
import respx

from orchestrator.wazuh_client import WazuhClient, WazuhDispatchError


_MGR = "https://wazuh-manager:55000"
_AUTH_PATH = "/security/user/authenticate"
_AR_PATH = "/active-response"


async def test_authenticate_caches_jwt():
    with respx.mock(base_url=_MGR) as router:
        router.post(_AUTH_PATH).respond(200, json={"data": {"token": "TOKEN-123"}})
        client = WazuhClient(_MGR, "wazuh", "wazuh")
        try:
            await client.authenticate()
            assert client._token == "TOKEN-123"  # noqa: SLF001
        finally:
            await client.aclose()


async def test_run_active_response_sends_correct_json():
    with respx.mock(base_url=_MGR) as router:
        router.post(_AUTH_PATH).respond(200, json={"data": {"token": "T"}})
        ar_route = router.put(_AR_PATH).respond(200, json={"data": {}, "error": 0})
        client = WazuhClient(_MGR, "wazuh", "wazuh")
        try:
            await client.run_active_response(
                agent_id="001", command="!quarantine0",
                arguments=["-", '{"update_id":"abc"}'],
            )
            assert ar_route.called
            sent = ar_route.calls.last.request
            body = sent.content.decode("utf-8")
            assert '"command":"!quarantine0"' in body
            assert '"alert":{}' in body
            # agents_list is in the query string, not the body
            assert "agents_list=001" in str(sent.url)
            assert sent.headers["authorization"] == "Bearer T"
        finally:
            await client.aclose()


async def test_run_active_response_refreshes_jwt_on_401_once():
    with respx.mock(base_url=_MGR) as router:
        # Two auth responses with different tokens
        auth_route = router.post(_AUTH_PATH)
        auth_route.side_effect = [
            httpx.Response(200, json={"data": {"token": "OLD"}}),
            httpx.Response(200, json={"data": {"token": "NEW"}}),
        ]
        # First AR returns 401, second AR returns 200
        ar_route = router.put(_AR_PATH)
        ar_route.side_effect = [
            httpx.Response(401, json={"title": "Unauthorized"}),
            httpx.Response(200, json={"data": {}, "error": 0}),
        ]
        client = WazuhClient(_MGR, "wazuh", "wazuh")
        try:
            await client.run_active_response(agent_id="001", command="quarantine0", arguments=[])
            assert ar_route.call_count == 2
            assert auth_route.call_count == 2
            # Second AR call used the refreshed token
            assert ar_route.calls.last.request.headers["authorization"] == "Bearer NEW"
        finally:
            await client.aclose()


async def test_run_active_response_raises_after_two_401s():
    with respx.mock(base_url=_MGR) as router:
        router.post(_AUTH_PATH).respond(200, json={"data": {"token": "T"}})
        router.put(_AR_PATH).respond(401, json={"title": "Unauthorized"})
        client = WazuhClient(_MGR, "wazuh", "wazuh")
        try:
            with pytest.raises(WazuhDispatchError, match="401"):
                await client.run_active_response(
                    agent_id="001", command="quarantine0", arguments=[],
                )
        finally:
            await client.aclose()


async def test_run_active_response_raises_on_transport_error():
    with respx.mock(base_url=_MGR) as router:
        router.post(_AUTH_PATH).respond(200, json={"data": {"token": "T"}})
        router.put(_AR_PATH).mock(side_effect=httpx.ConnectError("boom"))
        client = WazuhClient(_MGR, "wazuh", "wazuh")
        try:
            with pytest.raises(WazuhDispatchError, match="transport"):
                await client.run_active_response(
                    agent_id="001", command="quarantine0", arguments=[],
                )
        finally:
            await client.aclose()


async def test_run_active_response_raises_on_5xx():
    with respx.mock(base_url=_MGR) as router:
        router.post(_AUTH_PATH).respond(200, json={"data": {"token": "T"}})
        router.put(_AR_PATH).respond(503, json={"error": "down"})
        client = WazuhClient(_MGR, "wazuh", "wazuh")
        try:
            with pytest.raises(WazuhDispatchError, match="503"):
                await client.run_active_response(
                    agent_id="001", command="quarantine0", arguments=[],
                )
        finally:
            await client.aclose()
