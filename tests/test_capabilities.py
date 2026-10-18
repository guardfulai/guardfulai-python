import asyncio
import copy

import httpx
import pytest

from guardfulai import AsyncGuardfulAI, Capabilities, CheckTaxonomy, GuardfulAI, ProtocolError

FIXTURE = {
    "schema_version": 1,
    "catalog_version": "capabilities-v1",
    "risk_catalog_version": "risk-catalog-v5",
    "checks": [
        {
            "schema_version": 1,
            "key": "security.suspicious_unicode",
            "title": "Suspicious Unicode",
            "category": "prompt_attacks",
            "family": "rules",
            "available": True,
            "availability": "available",
            "review_only": True,
            "default_action": "review",
            "directions": ["input", "output"],
            "languages": ["en"],
            "countries": [],
            "spans": False,
            "check_catalog_version": "deterministic-v2",
            "runtime_bundle": "deterministic-rules-v2",
            "limitations": ["Original-text signal; no redaction spans or attack-prevention claim."],
        }
    ],
}

TAXONOMY_FIXTURE = {
    "schema_version": 1,
    "taxonomy_version": "protection-taxonomy-v1",
    "risk_catalog_version": "risk-catalog-v7",
    "check_catalog_version": "functional-v2",
    "categories": [
        {
            "schema_version": 1,
            "category_id": "ai_attacks",
            "name": "AI attacks",
            "description": "Attempts to manipulate an AI system.",
            "order": 1,
            "subcategories": [
                {
                    "schema_version": 1,
                    "subcategory_id": "hidden_obfuscated_text",
                    "name": "Hidden & obfuscated text",
                    "description": "Narrow text signals.",
                    "order": 1,
                    "checks": [
                        {
                            "schema_version": 1,
                            "check_id": "security.confusable_unicode",
                            "title": "Mixed-script confusables",
                            "directions": ["input", "output"],
                            "actions": ["monitor", "review", "block"],
                            "redaction_eligible": False,
                            "availability": "available",
                            "limitations": ["Narrow signal; not complete spoof detection."],
                        }
                    ],
                }
            ],
        }
    ],
}


def test_current_sync_and_async_catalog_and_legacy_reader():
    def handler(request):
        if request.url.path == "/v1/capabilities":
            return httpx.Response(200, json=FIXTURE)
        if request.url.path == "/v1/check-taxonomy":
            return httpx.Response(200, json=TAXONOMY_FIXTURE)
        assert request.url.path == "/v1/checks"
        return httpx.Response(
            200,
            json=[
                {
                    "key": "data.email",
                    "family": "rules",
                    "available": True,
                    "directions": ["input"],
                    "status": "development",
                }
            ],
        )

    with GuardfulAI("synthetic-key", transport=httpx.MockTransport(handler)) as client:
        current = client.get_capabilities()
        taxonomy = client.get_check_taxonomy()
        assert current.checks[0].review_only and not current.checks[0].spans
        assert current.catalog_version == "capabilities-v1"
        assert taxonomy.categories[0].subcategories[0].checks[0].check_id == (
            "security.confusable_unicode"
        )
        assert client.list_checks()[0].status == "development"

    async def exercise():
        async with AsyncGuardfulAI(
            "synthetic-key", transport=httpx.MockTransport(handler)
        ) as client:
            assert await client.get_capabilities() == current
            assert await client.get_check_taxonomy() == taxonomy
            assert (await client.list_checks())[0].status == "development"

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda item: item.update(catalog_version="unknown"),
        lambda item: item.update(checks=[]),
        lambda item: item.update(schema_version=True),
        lambda item: item["checks"][0].update(available="yes"),
        lambda item: item["checks"][0].update(availability="unavailable"),
        lambda item: item["checks"][0].update(default_action="block"),
        lambda item: item["checks"][0].update(directions=["unknown"]),
        lambda item: item["checks"].append(item["checks"][0]),
    ],
)
def test_new_catalog_rejects_unknown_or_inconsistent_protocol(mutate):
    invalid = copy.deepcopy(FIXTURE)
    mutate(invalid)
    with pytest.raises(ProtocolError):
        Capabilities.parse(invalid)


def test_taxonomy_rejects_unknown_version_and_duplicate_checks():
    invalid = copy.deepcopy(TAXONOMY_FIXTURE)
    invalid["risk_catalog_version"] = "risk-catalog-v8"
    with pytest.raises(ProtocolError):
        CheckTaxonomy.parse(invalid)
    invalid = copy.deepcopy(TAXONOMY_FIXTURE)
    invalid["categories"].append(copy.deepcopy(invalid["categories"][0]))
    with pytest.raises(ProtocolError):
        CheckTaxonomy.parse(invalid)
