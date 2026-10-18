"""Content-free validation of the version-one scan wire contract.

Vendored identically in the SDK and Dify package; checked against the same corpus.
No detector, policy, or accounting implementation belongs here.
"""

from __future__ import annotations

import math
import re
from typing import Any
from uuid import UUID

PUBLIC_ERROR_CODES = frozenset(
    {
        "invalid_request",
        "invalid_api_key",
        "authentication_required",
        "permission_denied",
        "scope_required",
        "policy_scope_required",
        "forbidden",
        "not_found",
        "insufficient_credits",
        "rate_limited",
        "runtime_unavailable",
        "scan_failed",
        "idempotency_conflict",
        "idempotency_expired",
        "policy_body_unavailable",
        "policy_mismatch",
        "unsupported_check",
        "invalid_policy",
        "service_unavailable",
        "request_too_large",
        "request_in_progress",
        "quota_exceeded",
        "scope_denied",
        "dataset_basis_has_records",
        "dataset_management_requires_unrestricted_policy",
        "dataset_not_found",
        "dataset_record_field_invalid",
        "dataset_record_id_invalid",
        "dataset_record_identity_conflict",
        "dataset_run_identity_conflict",
        "dataset_run_not_found",
        "dataset_run_owned_by_audit",
        "dataset_run_required",
        "dataset_source_identity_conflict",
        "dataset_source_not_found",
        "report_catalog_unavailable",
        "report_category_invalid",
        "report_check_invalid",
        "report_date_only_requires_calendar_bucket",
        "report_provenance_limit_narrow_selection",
        "report_query_invalid",
        "report_series_limit_choose_coarser_bucket",
        "report_snapshot_requires_outer_transaction",
    }
)


def public_error_code(value: object) -> str:
    return value if isinstance(value, str) and value in PUBLIC_ERROR_CODES else "integration_error"


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("invalid_completed_result")


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value) and len(value) <= 256


def _integer(value: object, minimum: int = 1) -> bool:
    return type(value) is int and value >= minimum


_REASONS = {
    "compliant": {"no_match"},
    "violated": {"policy_match"},
    "uncertain": {"ambiguous", "insufficient_context", "conflicting_policy"},
}


def _opaque(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,47}", value) is not None


def _assessments(value: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    rows, coverage = value.get("semantic_assessments"), value.get("semantic_coverage")
    if rows is None and coverage is None:
        return {}  # Historical missing outcomes are not inferred from findings.
    if not isinstance(rows, list) or not isinstance(coverage, dict):
        raise ValueError("invalid_completed_result")
    _require(1 <= len(rows) <= 16)
    _require(type(coverage.get("schema_version")) is int and coverage["schema_version"] == 1)
    _require("custom.semantic_policy" in value["checks_run"])
    for key in ("expected", "completed"):
        _require(_integer(coverage.get(key)) and coverage[key] == len(rows))
    projected, seen, expected = [], set(), {}
    for row in rows:
        _require(isinstance(row, dict))
        _require(type(row.get("schema_version")) is int and row["schema_version"] == 1)
        _require(_opaque(row.get("policy_id")) and row["policy_id"] not in seen)
        outcome, reason = row.get("outcome"), row.get("reason_code")
        _require(isinstance(outcome, str) and outcome in _REASONS)
        _require(isinstance(reason, str) and reason in _REASONS[outcome])
        seen.add(row["policy_id"])
        projected.append(
            {key: row[key] for key in ("schema_version", "policy_id", "outcome", "reason_code")}
        )
        if outcome != "compliant":
            expected[row["policy_id"]] = row
    observed = [row for row in findings if row["check_key"] == "custom.semantic_policy"]
    _require(len(observed) == len(expected))
    found = set()
    for finding in observed:
        identity = finding.get("rule_id")
        _require(identity in expected and identity not in found)
        row = expected[identity]
        _require(finding["code"] == "policy_" + row["outcome"])
        _require(finding.get("reason_code") == row["reason_code"])
        _require(row["outcome"] != "uncertain" or finding["action"] == "review")
        found.add(identity)
    return {
        "semantic_assessments": projected,
        "semantic_coverage": {
            key: coverage[key] for key in ("schema_version", "expected", "completed")
        },
    }


def validate_scan(value: Any, expected_version: int | None = None) -> dict[str, Any]:
    """Validate before projecting; never expose response content in exceptions."""
    _require(isinstance(value, dict))
    _require(type(value.get("schema_version")) is int and value["schema_version"] == 1)
    _require(value.get("status") == "completed")
    decision = value.get("decision")
    _require(isinstance(decision, str) and decision in ("allow", "review", "block"))
    _require(type(value.get("safe_to_continue")) is bool)
    _require(value["safe_to_continue"] == (decision == "allow"))
    for field in ("flagged", "redacted", "replayed"):
        _require(type(value.get(field)) is bool)
    _require(isinstance(value.get("scan_id"), str))
    try:
        UUID(value["scan_id"])
    except (ValueError, AttributeError, TypeError):
        raise ValueError("invalid_completed_result") from None
    version = value.get("scan_policy_version")
    _require(_integer(version) and (expected_version is None or version == expected_version))
    _require(_text(value.get("runtime_bundle")))
    usage = value.get("usage")
    _require(isinstance(usage, dict))
    _require(type(usage.get("schema_version")) is int and usage["schema_version"] == 1)
    _require(_integer(usage.get("credits")) and _integer(usage.get("units")))
    _require(_text(usage.get("pricing_version")))
    for field in ("checks_run", "coverage"):
        _require(isinstance(value.get(field), list))
        _require(all(_text(item) for item in value[field]))
        _require(len(value[field]) == len(set(value[field])))
    _require(bool(value["checks_run"]) and set(value["checks_run"]) == set(value["coverage"]))
    findings = value.get("findings")
    _require(isinstance(findings, list) and value["flagged"] == bool(findings))
    projected = []
    for finding in findings:
        _require(isinstance(finding, dict))
        _require(type(finding.get("schema_version")) is int and finding["schema_version"] == 1)
        _require(_text(finding.get("check_key")) and _text(finding.get("code")))
        _require(finding["check_key"] in value["checks_run"])
        _require(
            finding.get("action")
            in ("monitor", "review", "block", "redact_and_allow", "redact_and_review")
        )
        _require(
            finding.get("score_kind")
            in ("rule_match", "classifier_score", "calibrated_probability")
        )
        score = finding.get("score")
        _require(
            score is None
            or (type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 1)
        )
        start, end = finding.get("start"), finding.get("end")
        _require(
            (start is None and end is None)
            or (_integer(start, 0) and _integer(end, 0) and end > start)
        )
        identity, reason = finding.get("rule_id"), finding.get("reason_code")
        _require(identity is None or _opaque(identity))
        if reason is not None:
            outcome = finding["code"].removeprefix("policy_")
            _require(finding["check_key"] == "custom.semantic_policy" and outcome in _REASONS)
            _require(isinstance(reason, str) and reason in _REASONS[outcome])
        projected.append(
            {
                key: finding.get(key)
                for key in (
                    "schema_version",
                    "check_key",
                    "code",
                    "action",
                    "score_kind",
                    "score",
                    "start",
                    "end",
                    "rule_id",
                    "reason_code",
                )
            }
        )
    actions = {finding["action"] for finding in projected}
    expected_decision = (
        "block"
        if "block" in actions
        else "review"
        if actions.intersection({"review", "redact_and_review"})
        or any(row["code"] in {"policy_uncertain", "guard_controversial"} for row in projected)
        else "allow"
    )
    _require(decision == expected_decision)
    _require(
        value["redacted"] == bool(actions.intersection({"redact_and_allow", "redact_and_review"}))
    )
    content = value.get("redacted_content")
    _require(content is None or isinstance(content, str))
    result = {
        key: value[key]
        for key in (
            "schema_version",
            "scan_id",
            "status",
            "decision",
            "safe_to_continue",
            "flagged",
            "redacted",
            "checks_run",
            "coverage",
            "scan_policy_version",
            "runtime_bundle",
            "replayed",
        )
    }
    result.update(
        findings=projected,
        usage={
            key: usage[key] for key in ("schema_version", "units", "credits", "pricing_version")
        },
        redacted_content=content,
    )
    if "input" in value:
        original = value["input"]
        _require(isinstance(original, dict) and isinstance(original.get("content"), str))
        _require(
            len(original["content"]) <= 20_000 and original.get("direction") in {"input", "output"}
        )
        _require(original.get("context") is None or isinstance(original["context"], str))
        _require(
            original.get("structured_fields") is None
            or isinstance(original["structured_fields"], dict)
        )
        result["input"] = {
            key: original.get(key)
            for key in ("content", "context", "direction", "structured_fields")
        }
    if "input_state" in value:
        _require(
            value["input_state"]
            in {"available", "hidden", "not_retained", "expired", "unavailable"}
        )
        result["input_state"] = value["input_state"]
    if "input_retention" in value:
        retention = value["input_retention"]
        _require(
            isinstance(retention, dict)
            and retention.get("status") in {"retained", "not_retained", "expired", "unavailable"}
        )
        _require(retention.get("retention_days") in {None, 0, 1, 7, 30})
        _require(retention.get("expires_at") is None or isinstance(retention["expires_at"], str))
        result["input_retention"] = {
            key: retention.get(key) for key in ("status", "expires_at", "retention_days")
        }
    result.update(_assessments(value, projected))
    return result
