"""Custom SDK inputs exercise immutable publication and real local settlement."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from guardfulai import AsyncGuardfulAI, GuardfulAI


def fixture(name):
    return json.loads((Path(__file__).with_name("fixtures") / name).read_text())


RULE = {
    "rule_id": "refund",
    "kind": "structured",
    "condition": {
        "all_of": [{"field": "amount", "value_type": "number", "operator": "gt", "value": 500}],
        "unless": [{"field": "approved", "value_type": "boolean", "operator": "eq", "value": True}],
    },
}


@pytest.mark.parametrize("asynchronous", [False, True])
def test_payload_omission_and_typed_roundtrip(asynchronous):
    requests = []

    def handler(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=fixture("check-success.json"))

    options = {
        "idempotency_key": "roundtrip:1",
        "structured_fields": {"number": 1.5, "boolean": False, "empty": None, "text": "café"},
        "context": "context",
        "reporting": {"dataset_id": "00000000-0000-4000-8000-000000000002", "record_id": "row:1"},
    }
    if asynchronous:

        async def run():
            async with AsyncGuardfulAI(
                "synthetic", transport=httpx.MockTransport(handler)
            ) as client:
                await client.check("00000000-0000-4000-8000-000000000101", "text", **options)
                await client.check(
                    "00000000-0000-4000-8000-000000000101", "text", idempotency_key="legacy"
                )

        asyncio.run(run())
    else:
        with GuardfulAI("synthetic", transport=httpx.MockTransport(handler)) as client:
            client.check("00000000-0000-4000-8000-000000000101", "text", **options)
            client.check("00000000-0000-4000-8000-000000000101", "text", idempotency_key="legacy")
    assert requests[0]["structured_fields"] == options["structured_fields"]
    assert requests[0]["context"] == "context"
    assert requests[0]["reporting"] == options["reporting"]
    assert "reporting" not in requests[1]
    assert "structured_fields" not in requests[1] and "context" not in requests[1]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_publication_bodies_and_estimate_roundtrip(asynchronous):
    requests = []
    policy_id = "00000000-0000-4000-8000-000000000101"
    semantic = [{"policy_id": "promise", "text": "Do not promise an unapproved refund."}]

    def handler(request):
        requests.append(json.loads(request.content))
        if request.url.path.endswith("/estimate"):
            return httpx.Response(
                200,
                json={
                    "schema_version": 1,
                    "quote_id": "quote",
                    "scan_policy_id": policy_id,
                    "scan_policy_version": 2,
                    "units": 1,
                    "credits": 1,
                    "pricing_version": "credits-v1",
                    "expires_at": "2099-01-01T00:00:00Z",
                },
            )
        return httpx.Response(
            200,
            json={
                "scan_policy_id": policy_id,
                "organization_id": policy_id,
                "scan_policy_version": 2,
                "direction": "output",
                "checks": [],
                "processing_mode": "local_only",
            },
        )

    publication = dict(
        expected_version=1,
        direction="output",
        checks=[],
        custom_rules=[RULE],
        semantic_policies=semantic,
    )
    inputs = dict(
        version=2,
        direction="output",
        context="private",
        structured_fields={"amount": 750, "approved": False},
    )
    if asynchronous:

        async def run():
            async with AsyncGuardfulAI(
                "synthetic", transport=httpx.MockTransport(handler)
            ) as client:
                await client.publish_policy(policy_id, **publication)
                await client.estimate(policy_id, "text", **inputs)
                await client.publish_policy(
                    policy_id, expected_version=2, direction="output", checks=[]
                )
                await client.publish_policy(
                    policy_id, **(publication | {"custom_rules": [], "semantic_policies": []})
                )

        asyncio.run(run())
    else:
        with GuardfulAI("synthetic", transport=httpx.MockTransport(handler)) as client:
            client.publish_policy(policy_id, **publication)
            client.estimate(policy_id, "text", **inputs)
            client.publish_policy(policy_id, expected_version=2, direction="output", checks=[])
            client.publish_policy(
                policy_id, **(publication | {"custom_rules": [], "semantic_policies": []})
            )
    assert requests[0]["custom_rules"] == [RULE]
    assert requests[0]["semantic_policies"] == semantic
    assert requests[1]["structured_fields"] == inputs["structured_fields"]
    assert requests[1]["context"] == "private"
    assert "custom_rules" not in requests[2] and "semantic_policies" not in requests[2]
    assert requests[3]["custom_rules"] == [] and requests[3]["semantic_policies"] == []


@pytest.mark.parametrize("asynchronous", [False, True])
def test_audit_mapping_omission_and_roundtrip(asynchronous):
    requests = []
    policy_id = "00000000-0000-4000-8000-000000000101"

    def handler(request):
        requests.append(json.loads(request.content))
        return httpx.Response(201, json=fixture("audit-completed.json"))

    options = {
        "version": 1,
        "fields": [("text", "input")],
        "structured_fields": [{"source": "cost", "field": "amount", "value_type": "number"}],
        "context_field": "reference",
    }
    if asynchronous:

        async def run():
            async with AsyncGuardfulAI(
                "synthetic", transport=httpx.MockTransport(handler)
            ) as client:
                await client.create_audit(policy_id, policy_id, **options)
                await client.create_audit(policy_id, policy_id, fields=[("text", "input")])

        asyncio.run(run())
    else:
        with GuardfulAI("synthetic", transport=httpx.MockTransport(handler)) as client:
            client.create_audit(policy_id, policy_id, **options)
            client.create_audit(policy_id, policy_id, fields=[("text", "input")])
    assert requests[0]["structured_fields"] == options["structured_fields"]
    assert requests[0]["context_field"] == "reference"
    assert "structured_fields" not in requests[1] and "context_field" not in requests[1]
