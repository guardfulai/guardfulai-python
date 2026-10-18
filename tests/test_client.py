import asyncio
import json
from pathlib import Path

import httpx
import pytest

from guardfulai import (
    AsyncGuardfulAI,
    ConfigurationError,
    ConflictError,
    GuardfulAI,
    RetryPolicy,
    new_idempotency_key,
)

FIXTURES = Path(__file__).with_name("fixtures")


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


@pytest.mark.parametrize(
    "base_url",
    [
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com/path",
        "https://example.com?api_key=secret",
    ],
)
def test_safe_origin_and_auth_configuration(base_url):
    with pytest.raises(ConfigurationError):
        GuardfulAI("synthetic-key", base_url=base_url)
    with pytest.raises(ConfigurationError):
        GuardfulAI("contains whitespace")


def test_sync_retry_preserves_idempotency_and_maps_conflict():
    requests = []
    success = fixture("check-success.json")

    def handler(request):
        requests.append(request)
        assert request.url.query == b""
        assert request.headers["authorization"] == "Bearer synthetic-key"
        if len(requests) == 1:
            return httpx.Response(
                503,
                headers={"Retry-After": "0"},
                json={"schema_version": 1, "code": "runtime_unavailable", "retryable": True},
            )
        return httpx.Response(200, json=success)

    client = GuardfulAI(
        "synthetic-key",
        transport=httpx.MockTransport(handler),
        retry_policy=RetryPolicy(max_attempts=2, base_delay=0, max_delay=0),
    )
    result = client.check(
        "00000000-0000-4000-8000-000000000101",
        "Contact sam@example.test",
        idempotency_key="event:42",
        return_redacted_content=True,
    )
    assert result.redacted_content == "Contact [REDACTED]"
    assert [request.headers["idempotency-key"] for request in requests] == ["event:42"] * 2
    client.close()

    conflict = GuardfulAI(
        "synthetic-key",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                409,
                json={"schema_version": 1, "code": "idempotency_conflict", "retryable": False},
            )
        ),
    )
    with pytest.raises(ConflictError) as error:
        conflict.check(
            "00000000-0000-4000-8000-000000000101",
            "changed",
            idempotency_key="event:42",
        )
    assert error.value.code == "idempotency_conflict"
    conflict.close()


def test_async_recorded_response_and_polling():
    audit = fixture("audit-completed.json")

    async def run():
        async with AsyncGuardfulAI(
            "synthetic-key",
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=audit)),
        ) as client:
            value = await client.wait_for_audit(audit["id"], timeout=1, interval=0.01)
            assert value.state == "completed"
            assert value.completed_segments == 1

    asyncio.run(run())


def test_idempotency_helper_is_bounded_and_unique():
    first, second = new_idempotency_key("test"), new_idempotency_key("test")
    assert first != second
    assert len(first) <= 128 and first.startswith("test:")
    with pytest.raises(ConfigurationError):
        new_idempotency_key("not allowed")


@pytest.mark.parametrize("asynchronous", [False, True])
def test_retention_override_and_historical_input_roundtrip(asynchronous):
    seen = []
    original = {
        "content": "synthetic private 世界",
        "context": None,
        "direction": "input",
        "structured_fields": {"tier": 1},
    }
    success = fixture("check-success.json") | {
        "input": original,
        "input_state": "available",
        "input_retention": {
            "status": "retained",
            "retention_days": 30,
            "expires_at": "2026-11-10T00:00:00Z",
        },
    }

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=success)

    policy = "00000000-0000-4000-8000-000000000101"

    async def run():
        async with AsyncGuardfulAI(
            "synthetic-key", transport=httpx.MockTransport(handler)
        ) as client:
            checked = await client.check(
                policy,
                original["content"],
                idempotency_key="retention",
                input_retention_days=30,
                include_input=True,
            )
            return await client.get_scan(checked.scan_id, include_input=True)

    if asynchronous:
        value = asyncio.run(run())
    else:
        with GuardfulAI("synthetic-key", transport=httpx.MockTransport(handler)) as client:
            checked = client.check(
                policy,
                original["content"],
                idempotency_key="retention",
                input_retention_days=30,
                include_input=True,
            )
            value = client.get_scan(checked.scan_id, include_input=True)
    assert value.input == original and "synthetic private" not in repr(value)
    assert json.loads(seen[0].content)["input_retention_days"] == 30
    assert seen[1].url.params["include_input"] == "true"
