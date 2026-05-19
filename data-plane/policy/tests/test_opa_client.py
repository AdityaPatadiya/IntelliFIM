import httpx
import respx

from policy.opa_client import OpaClient


_OPA_URL = "http://opa:8181"
_QUERY_PATH = "/v1/data/intellifim/policy/decision"


async def test_opa_client_happy_path(make_scored_event):
    event = make_scored_event(anomaly_score=0.85)
    with respx.mock(base_url=_OPA_URL) as router:
        router.post(_QUERY_PATH).respond(
            200, json={"result": {"score_delta": 25, "reason": "strong anomaly"}}
        )
        client = OpaClient(_OPA_URL)
        try:
            result = await client.query(event)
        finally:
            await client.aclose()
        assert result == {"score_delta": 25, "reason": "strong anomaly"}


async def test_opa_client_returns_none_on_timeout(make_scored_event):
    event = make_scored_event()
    with respx.mock(base_url=_OPA_URL) as router:
        router.post(_QUERY_PATH).mock(side_effect=httpx.TimeoutException("timed out"))
        client = OpaClient(_OPA_URL, timeout_seconds=0.5)
        try:
            assert await client.query(event) is None
        finally:
            await client.aclose()


async def test_opa_client_returns_none_on_4xx(make_scored_event):
    event = make_scored_event()
    with respx.mock(base_url=_OPA_URL) as router:
        router.post(_QUERY_PATH).respond(404, json={"error": "not found"})
        client = OpaClient(_OPA_URL)
        try:
            assert await client.query(event) is None
        finally:
            await client.aclose()


async def test_opa_client_returns_none_on_5xx(make_scored_event):
    event = make_scored_event()
    with respx.mock(base_url=_OPA_URL) as router:
        router.post(_QUERY_PATH).respond(500, json={"error": "server error"})
        client = OpaClient(_OPA_URL)
        try:
            assert await client.query(event) is None
        finally:
            await client.aclose()


async def test_opa_client_returns_none_on_malformed_response(make_scored_event):
    event = make_scored_event()
    with respx.mock(base_url=_OPA_URL) as router:
        # Missing the wrapping "result" key
        router.post(_QUERY_PATH).respond(200, json={"score_delta": 25})
        client = OpaClient(_OPA_URL)
        try:
            assert await client.query(event) is None
        finally:
            await client.aclose()


async def test_opa_client_returns_none_on_non_json_body(make_scored_event):
    event = make_scored_event()
    with respx.mock(base_url=_OPA_URL) as router:
        router.post(_QUERY_PATH).respond(
            200, content=b"<html>not json</html>",
            headers={"content-type": "text/html"},
        )
        client = OpaClient(_OPA_URL)
        try:
            assert await client.query(event) is None
        finally:
            await client.aclose()
