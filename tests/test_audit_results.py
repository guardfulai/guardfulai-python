import asyncio
import copy
import json
from pathlib import Path

import httpx
import pytest

from guardfulai import AsyncGuardfulAI, AuditResult, GuardfulAI, ProtocolError

CASES = json.loads((Path(__file__).parent / "fixtures/custom-policy-results.json").read_text())


def segment(result=None, **changes):
    return {
        "schema_version": 1,
        "segment_id": "00000000-0000-4000-8000-000000000101",
        "row_ordinal": 1,
        "direction": "input",
        "segment_index": 0,
        "state": "completed",
        "reused": False,
        "metadata": {},
        "error_code": "",
        "result": result,
    } | changes


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_nested_custom_results_keep_the_complete_shared_boundary(case):
    # Supply the full wire envelope around the legacy automation semantic corpus.
    # Preserve its original fixtures, outcomes, IDs, reasons and action cases.
    value = copy.deepcopy(case["result"])
    value["usage"].setdefault("schema_version", 1)
    for finding in value["findings"]:
        for key, default in {
            "schema_version": 1,
            "score_kind": "rule_match",
            "score": None,
            "start": None,
            "end": None,
        }.items():
            finding.setdefault(key, default)
    if case["valid"]:
        result = AuditResult.parse(segment(value))
        assert result.result.decision == case["result"]["decision"]
    else:
        with pytest.raises(ProtocolError):
            AuditResult.parse(segment(value))


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": 2},
        {"schema_version": True},
        {"row_ordinal": 0},
        {"segment_index": -1},
        {"state": "invented"},
        {"direction": "invented"},
        {"reused": 1},
        {"metadata": "invalid"},
        {"result": []},
        {"state": "pending", "result": CASES[0]["result"]},
    ],
)
def test_invalid_segment_envelopes_never_become_results(change):
    with pytest.raises(ProtocolError):
        AuditResult.parse(segment(**change))


@pytest.mark.parametrize("asynchronous", [False, True])
def test_reader_keeps_unavailable_and_pending_results_and_cursor(asynchronous):
    def handler(request):
        assert request.url.path.endswith("/results")
        assert dict(request.url.params) == {"limit": "2", "cursor": "cursor:1"}
        return httpx.Response(
            200, json={"items": [segment(), segment(state="pending")], "next_cursor": "cursor:2"}
        )

    options = {"cursor": "cursor:1", "limit": 2}
    if asynchronous:

        async def run():
            async with AsyncGuardfulAI(
                "synthetic", transport=httpx.MockTransport(handler)
            ) as client:
                return await client.list_audit_results("audit", **options)

        page = asyncio.run(run())
    else:
        with GuardfulAI("synthetic", transport=httpx.MockTransport(handler)) as client:
            page = client.list_audit_results("audit", **options)
    assert page.next_cursor == "cursor:2"
    assert [row.state for row in page.items] == ["completed", "pending"]
    assert all(row.result is None for row in page.items)
