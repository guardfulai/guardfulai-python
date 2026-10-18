"""Content-free reporting input validation, vendored identically by Dify.

Uses only the standard library. It does not scan, persist content or select a policy.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

RECORD_PATTERN = r"[A-Za-z0-9_.:-]{1,128}"
DIMENSION_PATTERN = r"[a-z][a-z0-9_]{0,47}"
SOURCE_KINDS = (
    "upload",
    "paste",
    "example",
    "sheets",
    "api",
    "n8n",
    "zapier",
    "dify",
    "mcp",
    "standalone",
    "historical",
)


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("reporting_input_invalid")


def identifier(value: object) -> str:
    require(isinstance(value, (str, UUID)))
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("reporting_input_invalid") from None


def text(value: object, maximum: int, *, minimum: int = 0, pattern: str | None = None) -> str:
    require(isinstance(value, str))
    assert isinstance(value, str)
    require(minimum <= len(value) <= maximum)
    require(pattern is None or re.fullmatch(pattern, value) is not None)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError("reporting_input_invalid") from None
    return value


def timestamp(value: object, *, date_only: bool = False) -> str:
    if date_only:
        if type(value) is date:
            return value.isoformat()
        require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is not None)
        try:
            return date.fromisoformat(str(value)).isoformat()
        except ValueError:
            raise ValueError("reporting_input_invalid") from None
    if not isinstance(value, datetime):
        require(isinstance(value, str) and re.match(r"\d{4}-\d{2}-\d{2}T", value) is not None)
        try:
            value = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("reporting_input_invalid") from None
    require(value.tzinfo is not None and value.utcoffset() is not None)
    return value.isoformat()


def timezone_name(value: object) -> str:
    zone = text(value, 64, minimum=1)
    try:
        ZoneInfo(zone)
    except (ValueError, ZoneInfoNotFoundError):
        raise ValueError("reporting_input_invalid") from None
    return zone


def dimensions(value: object) -> dict[str, str]:
    require(isinstance(value, dict) and len(value) <= 8)
    assert isinstance(value, dict)
    result = {text(k, 48, pattern=DIMENSION_PATTERN): text(v, 160) for k, v in value.items()}
    require(len(json.dumps(result, ensure_ascii=False).encode("utf-8")) <= 2000)
    return result


def object_fields(value: object, allowed: set[str]) -> dict[str, Any]:
    require(isinstance(value, dict))
    assert isinstance(value, dict)
    require(set(value) <= allowed | {"schema_version"})
    require(type(value.get("schema_version", 1)) is int and value.get("schema_version", 1) == 1)
    return {k: v for k, v in value.items() if k != "schema_version" and v is not None}


def validate_reporting(value: object) -> dict[str, Any]:
    if isinstance(value, dict) and "event_time_invalid" in value:
        require(type(value["event_time_invalid"]) is bool)
    data = object_fields(
        value,
        {
            "dataset_id",
            "run_id",
            "record_id",
            "event_at",
            "event_date",
            "dimensions",
            "event_time_invalid",
        },
    )
    result: dict[str, Any] = {
        "dataset_id": identifier(data.get("dataset_id")),
        "record_id": text(data.get("record_id"), 128, minimum=1, pattern=RECORD_PATTERN),
    }
    if "run_id" in data:
        result["run_id"] = identifier(data["run_id"])
    require(not ("event_at" in data and "event_date" in data))
    if data.get("event_time_invalid"):
        require("event_at" not in data and "event_date" not in data)
        result["event_time_invalid"] = True
    for key in ("event_at", "event_date"):
        if key in data:
            result[key] = timestamp(data[key], date_only=key == "event_date")
    if "dimensions" in data:
        result["dimensions"] = dimensions(data["dimensions"])
    return result


def validate_audit_reporting(value: object) -> dict[str, Any]:
    data = object_fields(value, {"dataset_id", "run_id", "record_id_field", "source_kind"})
    result: dict[str, Any] = {"dataset_id": identifier(data.get("dataset_id"))}
    if "run_id" in data:
        result["run_id"] = identifier(data["run_id"])
    if "record_id_field" in data:
        result["record_id_field"] = text(data["record_id_field"], 128, minimum=1)
    if "source_kind" in data:
        require(data["source_kind"] in SOURCE_KINDS[:-2])
        result["source_kind"] = data["source_kind"]
    return result


def validate_date_mapping(value: object) -> dict[str, Any]:
    data = object_fields(value, {"field", "format", "timezone"})
    result = {"field": text(data.get("field"), 128, minimum=1), "format": data.get("format")}
    require(
        result["format"] in ("iso", "day_first", "month_first", "unix_seconds", "unix_milliseconds")
    )
    if "timezone" in data:
        result["timezone"] = timezone_name(data["timezone"])
    return result


def validate_report_query(value: object) -> dict[str, Any]:
    choices = {
        "time_basis": ("event", "received", "scanned"),
        "bucket": ("hour", "day", "week", "month"),
        "outcome": ("compliant", "violated", "uncertain"),
        "decision": ("allow", "review", "block"),
        "action": ("monitor", "review", "block", "redact_and_allow", "redact_and_review"),
        "direction": ("input", "output"),
        "review": ("unreviewed", "confirmed_issue", "false_positive", "accepted_exception"),
        "state": ("checked", "partial", "failed", "pending", "excluded", "unrun"),
        "group_by": (
            "category",
            "check",
            "decision",
            "action",
            "direction",
            "review",
            "dimension",
            "outcome",
        ),
        "order": ("received", "-received", "event", "-event", "record", "-record"),
    }
    result = object_fields(
        value,
        set(choices)
        | {
            "run_id",
            "start",
            "end",
            "timezone",
            "category",
            "check",
            "dimensions",
            "dimension",
            "page",
            "page_size",
            "policy_id",
            "policy_version",
            "rule_id",
        },
    )
    for key, options in choices.items():
        if key in result:
            require(result[key] in options)
    for key in ("page", "page_size"):
        if key in result:
            require(
                type(result[key]) is int
                and 1 <= result[key] <= (200 if key == "page_size" else 100_000)
            )
    if "run_id" in result:
        result["run_id"] = identifier(result["run_id"])
    for key in ("start", "end"):
        if key in result:
            result[key] = timestamp(result[key], date_only=True)
    require(not ("start" in result and "end" in result) or result["start"] < result["end"])
    if "timezone" in result:
        result["timezone"] = timezone_name(result["timezone"])
    if "dimensions" in result:
        result["dimensions"] = dimensions(result["dimensions"])
    for key in ("category", "dimension"):
        if key in result:
            result[key] = text(result[key], 48, pattern=DIMENSION_PATTERN)
    if "check" in result:
        result["check"] = text(
            result["check"], 256, pattern=r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+"
        )
    if "policy_id" in result:
        result["policy_id"] = identifier(result["policy_id"])
    if "policy_version" in result:
        require(
            "policy_id" in result
            and type(result["policy_version"]) is int
            and 1 <= result["policy_version"] <= 2147483647
        )
    if "rule_id" in result:
        result["rule_id"] = text(result["rule_id"], 48, minimum=1, pattern=DIMENSION_PATTERN)
        require(
            "policy_id" in result
            and result.get("check")
            in (
                "custom.phrase",
                "custom.keyword",
                "custom.regex",
                "custom.structured_rule",
                "custom.semantic_policy",
            )
        )
    if "outcome" in result:
        require(result.get("check") in (None, "custom.semantic_policy"))
    require((result.get("group_by") == "dimension") == ("dimension" in result))
    return result
