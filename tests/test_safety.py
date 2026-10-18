import asyncio
import json
from pathlib import Path

import httpx
import pytest

from guardfulai import (
    APIError,
    AsyncGuardfulAI,
    DatasetWrite,
    GuardfulAI,
    ProtocolError,
    RetryPolicy,
    TransportError,
)

POLICY = "00000000-0000-4000-8000-000000000101"
SUCCESS = json.loads((Path(__file__).parent / "fixtures/check-success.json").read_text())


def exercise(asynchronous, handler, operation="check"):
    options = dict(
        api_key="synthetic-key",
        base_url="https://service.example.test",
        transport=httpx.MockTransport(handler),
        retry_policy=RetryPolicy(max_attempts=3, base_delay=0, max_delay=0),
    )

    def call(client):
        if operation == "create":
            return client.create_dataset(DatasetWrite("Synthetic"))
        return client.check(POLICY, "PRIVATE_INPUT", idempotency_key="event:stable", version=1)

    async def run():
        async with AsyncGuardfulAI(**options) as client:
            return await call(client)

    if asynchronous:
        return asyncio.run(run())
    with GuardfulAI(**options) as client:
        return call(client)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("status", [429, 503, 504])
def test_bounded_retry_keeps_exact_request(asynchronous, status):
    seen = []

    def handler(request):
        seen.append(request)
        if len(seen) < 3:
            return httpx.Response(
                status,
                headers={"Retry-After": "999999"},
                json={"code": "temporarily_unavailable", "retryable": True},
            )
        return httpx.Response(200, json=SUCCESS)

    assert exercise(asynchronous, handler).status == "completed"
    assert len(seen) == 3
    assert len({r.content for r in seen}) == 1
    assert {r.headers["Idempotency-Key"] for r in seen} == {"event:stable"}
    assert all(r.url.query == b"" for r in seen)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("operation, attempts", [("check", 3), ("create", 1)])
def test_transport_failure_is_private_and_unkeyed_creation_never_retries(
    asynchronous, operation, attempts
):
    seen = []

    def handler(request):
        seen.append(request)
        raise httpx.ReadError("PRIVATE_INPUT synthetic-key", request=request)

    with pytest.raises(TransportError) as error:
        exercise(asynchronous, handler, operation)
    assert len(seen) == attempts
    assert "PRIVATE_INPUT" not in str(error.value)
    assert "synthetic-key" not in str(error.value)
    assert error.value.__suppress_context__


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("status", [401, 402, 403, 404, 409, 302])
def test_errors_do_not_retry_or_follow_redirects(asynchronous, status):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            status,
            headers={"Location": "https://other.example.test"},
            json={
                "code": "PRIVATE_INPUT contains customer text",
                "retryable": False,
                "body": "synthetic-key",
            },
        )

    with pytest.raises(APIError) as error:
        exercise(asynchronous, handler)
    assert len(seen) == 1
    assert "PRIVATE_INPUT" not in str(error.value)
    assert "synthetic-key" not in repr(error.value)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("payload", [b"not JSON PRIVATE_INPUT", b"[]", b'{"decision":"allow"}'])
def test_incomplete_responses_never_become_allow(asynchronous, payload):
    with pytest.raises(ProtocolError) as error:
        exercise(asynchronous, lambda request: httpx.Response(200, content=payload))
    assert "PRIVATE_INPUT" not in str(error.value)


def test_proxy_environment_is_ignored(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://invalid.example.test:1")
    monkeypatch.setenv("ALL_PROXY", "http://invalid.example.test:1")
    with GuardfulAI("synthetic-key") as client:
        assert not client._client._trust_env
        assert not client._client.follow_redirects
        assert not client._client._mounts
