"""SDK validates complete outcomes and keeps missing historical assessments absent."""

import copy
import json
from pathlib import Path

import pytest

from guardfulai import ProtocolError, ScanResult


def result():
    value = json.loads((Path(__file__).parent / "fixtures/check-success.json").read_text())
    value.update(
        checks_run=["custom.semantic_policy"],
        coverage=["custom.semantic_policy"],
        decision="review",
        safe_to_continue=False,
        flagged=True,
        redacted=False,
        redacted_content=None,
        findings=[
            {
                "schema_version": 1,
                "check_key": "custom.semantic_policy",
                "code": "policy_uncertain",
                "score_kind": "classifier_score",
                "score": None,
                "start": None,
                "end": None,
                "action": "review",
                "rule_id": "promise",
                "reason_code": "ambiguous",
            }
        ],
        semantic_assessments=[
            {
                "schema_version": 1,
                "policy_id": "clear",
                "outcome": "compliant",
                "reason_code": "no_match",
            },
            {
                "schema_version": 1,
                "policy_id": "promise",
                "outcome": "uncertain",
                "reason_code": "ambiguous",
            },
        ],
        semantic_coverage={"schema_version": 1, "expected": 2, "completed": 2},
    )
    return value


def test_sdk_complete_and_legacy_results():
    value = result()
    parsed = ScanResult.parse(value)
    assert parsed.semantic_coverage.expected == parsed.semantic_coverage.completed == 2
    assert parsed.semantic_assessments[0].outcome == "compliant"
    assert parsed.semantic_assessments[1].reason_code == "ambiguous"
    assert parsed.findings[0].rule_id == "promise" and parsed.findings[0].reason_code == "ambiguous"
    legacy = copy.deepcopy(value)
    del legacy["semantic_assessments"], legacy["semantic_coverage"]
    del legacy["findings"][0]["reason_code"]
    legacy["findings"][0]["action"] = "monitor"  # Legacy uncertainty still implies review.
    assert ScanResult.parse(legacy).semantic_assessments is None
    assert ScanResult.parse(legacy).semantic_coverage is None


@pytest.mark.parametrize(
    "change",
    [
        lambda v: v.pop("semantic_coverage"),
        lambda v: v.pop("semantic_assessments"),
        lambda v: v["semantic_coverage"].update(completed=1),
        lambda v: v["semantic_coverage"].update(expected=17),
        lambda v: v["semantic_coverage"].update(completed=True),
        lambda v: v["semantic_assessments"][1].update(policy_id="clear"),
        lambda v: v["semantic_assessments"][0].update(reason_code="policy_match"),
        lambda v: v["semantic_assessments"][0].update(reason_code="PRIVATE_REASONING"),
        lambda v: v["findings"][0].update(rule_id="clear"),
        lambda v: v["findings"][0].update(reason_code=None),
        lambda v: v["findings"][0].update(action="block"),
        lambda v: v.update(checks_run=["data.email"], coverage=["data.email"]),
    ],
)
def test_sdk_rejects_incomplete_or_unbounded_semantic_results(change):
    value = result()
    change(value)
    with pytest.raises(ProtocolError, match="invalid_completed_result") as error:
        ScanResult.parse(value)
    assert "PRIVATE" not in str(error.value)
