import json
from pathlib import Path

import pytest

from guardfulai import ProtocolError, ScanResult

CASES = json.loads((Path(__file__).parent / "fixtures/scan-results.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_scan_response_contract(case):
    if case["valid"]:
        assert ScanResult.parse(case["result"]).decision == "allow"
    else:
        with pytest.raises(ProtocolError):
            ScanResult.parse(case["result"])


def test_explicit_version_must_match_result():
    with pytest.raises(ProtocolError):
        ScanResult.parse(CASES[0]["result"], expected_version=2)


def test_estimate_rejects_wrong_pinned_version():
    import httpx

    from guardfulai import GuardfulAI

    value = {
        "schema_version": 1,
        "quote_id": "synthetic-quote",
        "scan_policy_id": "00000000-0000-4000-8000-000000000101",
        "scan_policy_version": 2,
        "units": 1,
        "credits": 1,
        "pricing_version": "credits-v1",
        "expires_at": "2026-09-20T00:00:00Z",
    }
    with GuardfulAI(
        base_url="http://localhost:8000",
        api_key="synthetic-key",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=value)),
    ) as client:
        with pytest.raises(ProtocolError):
            client.estimate(value["scan_policy_id"], "synthetic", version=1)
