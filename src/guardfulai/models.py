"""Small immutable response models for the public version-one API."""

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from guardfulai.errors import ProtocolError
from guardfulai.response_validation import validate_scan

JSON = Mapping[str, Any]
T = TypeVar("T")


def _value(data: JSON, key: str, expected: type[T]) -> T:
    value = data.get(key)
    if not isinstance(value, expected) or (expected is int and type(value) is bool):
        raise ProtocolError(f"invalid response field: {key}")
    return value


def _optional(data: JSON, key: str, expected: type[T]) -> T | None:
    value = data.get(key)
    if value is not None and not isinstance(value, expected):
        raise ProtocolError(f"invalid response field: {key}")
    return value


def _uuid(data: JSON, key: str) -> UUID:
    try:
        return UUID(_value(data, key, str))
    except ValueError:
        raise ProtocolError(f"invalid response field: {key}") from None


def _datetime(data: JSON, key: str) -> datetime:
    try:
        return datetime.fromisoformat(_value(data, key, str).replace("Z", "+00:00"))
    except ValueError:
        raise ProtocolError(f"invalid response field: {key}") from None


def _objects(data: JSON, key: str) -> tuple[JSON, ...]:
    value = _value(data, key, list)
    if any(not isinstance(item, dict) for item in value):
        raise ProtocolError(f"invalid response field: {key}")
    return tuple(value)


@dataclass(frozen=True)
class Check:
    """Current status is available/unavailable; legacy status strings remain readable."""

    key: str
    family: str
    available: bool
    directions: tuple[str, ...]
    status: str

    @classmethod
    def parse(cls, data: JSON) -> "Check":
        return cls(
            _value(data, "key", str),
            _value(data, "family", str),
            _value(data, "available", bool),
            tuple(_value(data, "directions", list)),
            _value(data, "status", str),
        )


@dataclass(frozen=True)
class Capability:
    key: str
    title: str
    category: str
    family: str
    available: bool
    review_only: bool
    directions: tuple[str, ...]
    languages: tuple[str, ...]
    countries: tuple[str, ...]
    spans: bool
    check_catalog_version: str
    runtime_bundle: str
    limitations: tuple[str, ...]

    @classmethod
    def parse(cls, data: JSON) -> "Capability":
        available = _value(data, "available", bool)
        if (
            _value(data, "schema_version", int) != 1
            or data.get("default_action") != "review"
            or data.get("availability") != ("available" if available else "unavailable")
        ):
            raise ProtocolError("invalid capability version or availability")

        def strings(key: str) -> tuple[str, ...]:
            value = _value(data, key, list)
            if any(not isinstance(item, str) for item in value):
                raise ProtocolError("invalid capability list")
            return tuple(value)

        directions = strings("directions")
        if not directions or not set(directions) <= {"input", "output"}:
            raise ProtocolError("invalid capability directions")
        return cls(
            _value(data, "key", str),
            _value(data, "title", str),
            _value(data, "category", str),
            _value(data, "family", str),
            available,
            _value(data, "review_only", bool),
            directions,
            strings("languages"),
            strings("countries"),
            _value(data, "spans", bool),
            _value(data, "check_catalog_version", str),
            _value(data, "runtime_bundle", str),
            strings("limitations"),
        )


@dataclass(frozen=True)
class Capabilities:
    catalog_version: str
    risk_catalog_version: str
    checks: tuple[Capability, ...]

    @classmethod
    def parse(cls, data: JSON) -> "Capabilities":
        if (
            _value(data, "schema_version", int) != 1
            or data.get("catalog_version") != "capabilities-v1"
            or data.get("risk_catalog_version") != "risk-catalog-v5"
        ):
            raise ProtocolError("unsupported capability catalog version")
        checks = tuple(Capability.parse(item) for item in _objects(data, "checks"))
        if not checks or len({item.key for item in checks}) != len(checks):
            raise ProtocolError("duplicate capability")
        return cls("capabilities-v1", "risk-catalog-v5", checks)


def _strings(data: JSON, key: str) -> tuple[str, ...]:
    value = _value(data, key, list)
    if any(not isinstance(item, str) for item in value):
        raise ProtocolError(f"invalid response field: {key}")
    return tuple(value)


@dataclass(frozen=True)
class TaxonomyCheck:
    check_id: str
    title: str
    directions: tuple[str, ...]
    actions: tuple[str, ...]
    redaction_eligible: bool
    availability: str
    limitations: tuple[str, ...]

    @classmethod
    def parse(cls, data: JSON) -> "TaxonomyCheck":
        if _value(data, "schema_version", int) != 1:
            raise ProtocolError("unsupported taxonomy check version")
        directions = _strings(data, "directions")
        actions = _strings(data, "actions")
        availability = _value(data, "availability", str)
        limitations = _strings(data, "limitations")
        redaction_eligible = _value(data, "redaction_eligible", bool)
        has_redaction = any(action.startswith("redact_") for action in actions)
        if (
            not directions
            or not set(directions) <= {"input", "output"}
            or not actions
            or not set(actions)
            <= {"monitor", "review", "block", "redact_and_allow", "redact_and_review"}
            or availability not in {"available", "unavailable"}
            or not limitations
            or has_redaction != redaction_eligible
        ):
            raise ProtocolError("invalid taxonomy check metadata")
        return cls(
            _value(data, "check_id", str),
            _value(data, "title", str),
            directions,
            actions,
            redaction_eligible,
            availability,
            limitations,
        )


@dataclass(frozen=True)
class TaxonomySubcategory:
    subcategory_id: str
    name: str
    description: str
    order: int
    checks: tuple[TaxonomyCheck, ...]

    @classmethod
    def parse(cls, data: JSON) -> "TaxonomySubcategory":
        if _value(data, "schema_version", int) != 1:
            raise ProtocolError("unsupported taxonomy subcategory version")
        return cls(
            _value(data, "subcategory_id", str),
            _value(data, "name", str),
            _value(data, "description", str),
            _value(data, "order", int),
            tuple(TaxonomyCheck.parse(item) for item in _objects(data, "checks")),
        )


@dataclass(frozen=True)
class TaxonomyCategory:
    category_id: str
    name: str
    description: str
    order: int
    subcategories: tuple[TaxonomySubcategory, ...]

    @classmethod
    def parse(cls, data: JSON) -> "TaxonomyCategory":
        if _value(data, "schema_version", int) != 1:
            raise ProtocolError("unsupported taxonomy category version")
        return cls(
            _value(data, "category_id", str),
            _value(data, "name", str),
            _value(data, "description", str),
            _value(data, "order", int),
            tuple(TaxonomySubcategory.parse(item) for item in _objects(data, "subcategories")),
        )


@dataclass(frozen=True)
class CheckTaxonomy:
    taxonomy_version: str
    risk_catalog_version: str
    check_catalog_version: str
    categories: tuple[TaxonomyCategory, ...]

    @classmethod
    def parse(cls, data: JSON) -> "CheckTaxonomy":
        if (
            _value(data, "schema_version", int) != 1
            or data.get("taxonomy_version") != "protection-taxonomy-v1"
            or data.get("risk_catalog_version") != "risk-catalog-v7"
            or data.get("check_catalog_version") != "functional-v2"
        ):
            raise ProtocolError("unsupported check taxonomy version")
        categories = tuple(TaxonomyCategory.parse(item) for item in _objects(data, "categories"))
        category_ids = [item.category_id for item in categories]
        subcategory_ids = [
            item.subcategory_id for category in categories for item in category.subcategories
        ]
        checks = [
            check.check_id
            for category in categories
            for subcategory in category.subcategories
            for check in subcategory.checks
        ]
        if (
            not categories
            or category_ids != list(dict.fromkeys(category_ids))
            or subcategory_ids != list(dict.fromkeys(subcategory_ids))
            or checks != list(dict.fromkeys(checks))
            or [item.order for item in categories] != list(range(1, len(categories) + 1))
            or any(
                not category.subcategories
                or [item.order for item in category.subcategories]
                != list(range(1, len(category.subcategories) + 1))
                for category in categories
            )
        ):
            raise ProtocolError("invalid check taxonomy")
        return cls("protection-taxonomy-v1", "risk-catalog-v7", "functional-v2", categories)


@dataclass(frozen=True)
class Template:
    slug: str
    template_id: UUID
    version: int
    name: str
    direction: str
    checks: tuple[str, ...]
    available_checks: tuple[str, ...]
    credits_per_short_scan: int | None

    @classmethod
    def parse(cls, data: JSON) -> "Template":
        return cls(
            _value(data, "slug", str),
            _uuid(data, "template_id"),
            _value(data, "version", int),
            _value(data, "name", str),
            _value(data, "direction", str),
            tuple(_value(data, "checks", list)),
            tuple(_value(data, "available_checks", list)),
            _optional(data, "credits_per_short_scan", int),
        )


@dataclass(frozen=True)
class Policy:
    id: UUID
    name: str
    current_version: int

    @classmethod
    def parse(cls, data: JSON) -> "Policy":
        return cls(
            _uuid(data, "id"),
            _value(data, "name", str),
            _value(data, "current_version", int),
        )


@dataclass(frozen=True)
class PolicyVersion:
    scan_policy_id: UUID
    organization_id: UUID
    version: int
    direction: str
    checks: tuple[JSON, ...]
    processing_mode: str

    @classmethod
    def parse(cls, data: JSON) -> "PolicyVersion":
        return cls(
            _uuid(data, "scan_policy_id"),
            _uuid(data, "organization_id"),
            _value(data, "scan_policy_version", int),
            _value(data, "direction", str),
            _objects(data, "checks"),
            _value(data, "processing_mode", str),
        )


@dataclass(frozen=True)
class PriceQuote:
    quote_id: str
    scan_policy_id: UUID
    scan_policy_version: int
    units: int
    credits: int
    pricing_version: str
    expires_at: datetime

    @classmethod
    def parse(cls, data: JSON, *, expected_version: int | None = None) -> "PriceQuote":
        if _value(data, "schema_version", int) != 1:
            raise ProtocolError("invalid quote response")
        for field in ("scan_policy_version", "units", "credits"):
            if _value(data, field, int) < 1:
                raise ProtocolError("invalid quote response")
        if expected_version is not None and data["scan_policy_version"] != expected_version:
            raise ProtocolError("policy version mismatch")
        for field in ("quote_id", "pricing_version"):
            if not _value(data, field, str):
                raise ProtocolError("invalid quote response")
        return cls(
            _value(data, "quote_id", str),
            _uuid(data, "scan_policy_id"),
            _value(data, "scan_policy_version", int),
            _value(data, "units", int),
            _value(data, "credits", int),
            _value(data, "pricing_version", str),
            _datetime(data, "expires_at"),
        )


@dataclass(frozen=True)
class Finding:
    check_key: str
    code: str
    action: str
    start: int | None
    end: int | None
    rule_id: str | None = None
    reason_code: str | None = None

    @classmethod
    def parse(cls, data: JSON) -> "Finding":
        return cls(
            _value(data, "check_key", str),
            _value(data, "code", str),
            _value(data, "action", str),
            _optional(data, "start", int),
            _optional(data, "end", int),
            _optional(data, "rule_id", str),
            _optional(data, "reason_code", str),
        )


@dataclass(frozen=True)
class SemanticAssessment:
    policy_id: str
    outcome: str
    reason_code: str


@dataclass(frozen=True)
class SemanticCoverage:
    expected: int
    completed: int


@dataclass(frozen=True)
class ScanResult:
    scan_id: UUID
    decision: str
    safe_to_continue: bool
    flagged: bool
    redacted: bool
    redacted_content: str | None
    findings: tuple[Finding, ...]
    scan_policy_version: int
    credits: int
    replayed: bool
    input: JSON | None = dataclass_field(default=None, repr=False)
    input_retention: JSON | None = None
    input_state: str | None = None
    status: str = "completed"
    semantic_assessments: tuple[SemanticAssessment, ...] | None = None
    semantic_coverage: SemanticCoverage | None = None

    @classmethod
    def parse(cls, data: JSON, expected_version: int | None = None) -> "ScanResult":
        try:
            data = validate_scan(data, expected_version)
        except (ValueError, TypeError, KeyError, OverflowError):
            raise ProtocolError("invalid_completed_result") from None
        usage = _value(data, "usage", dict)
        return cls(
            scan_id=_uuid(data, "scan_id"),
            decision=_value(data, "decision", str),
            safe_to_continue=_value(data, "safe_to_continue", bool),
            flagged=_value(data, "flagged", bool),
            redacted=_value(data, "redacted", bool),
            redacted_content=_optional(data, "redacted_content", str),
            findings=tuple(Finding.parse(item) for item in _objects(data, "findings")),
            scan_policy_version=_value(data, "scan_policy_version", int),
            credits=_value(usage, "credits", int),
            replayed=_value(data, "replayed", bool),
            input=data.get("input"),
            input_retention=data.get("input_retention"),
            input_state=data.get("input_state"),
            status=_value(data, "status", str),
            semantic_assessments=tuple(
                SemanticAssessment(row["policy_id"], row["outcome"], row["reason_code"])
                for row in data["semantic_assessments"]
            )
            if "semantic_assessments" in data
            else None,
            semantic_coverage=SemanticCoverage(
                data["semantic_coverage"]["expected"], data["semantic_coverage"]["completed"]
            )
            if "semantic_coverage" in data
            else None,
        )


@dataclass(frozen=True)
class AuditResult:
    segment_id: UUID
    row_ordinal: int
    direction: str
    segment_index: int
    state: str
    reused: bool
    metadata: JSON
    error_code: str
    result: ScanResult | None

    input: JSON | None = dataclass_field(default=None, repr=False)
    input_retention: JSON | None = None
    input_state: str | None = None

    @classmethod
    def parse(cls, data: JSON) -> "AuditResult":
        if _value(data, "schema_version", int) != 1:
            raise ProtocolError("unsupported audit result schema")
        ordinal = _value(data, "row_ordinal", int)
        index = _value(data, "segment_index", int)
        direction = _value(data, "direction", str)
        state = _value(data, "state", str)
        if (
            ordinal < 1
            or index < 0
            or direction not in ("input", "output")
            or state not in ("pending", "running", "completed", "failed")
        ):
            raise ProtocolError("invalid audit segment")
        value = data.get("result")
        if value is not None and (not isinstance(value, dict) or state != "completed"):
            raise ProtocolError("invalid recorded audit result")
        return cls(
            _uuid(data, "segment_id"),
            ordinal,
            direction,
            index,
            state,
            _value(data, "reused", bool),
            dict(_value(data, "metadata", dict)),
            _value(data, "error_code", str),
            ScanResult.parse(value) if value is not None else None,
            input=_value(data, "input", dict) if data.get("input") is not None else None,
            input_retention=_value(data, "input_retention", dict)
            if data.get("input_retention") is not None
            else None,
            input_state=_value(data, "input_state", str)
            if data.get("input_state") is not None
            else None,
        )


@dataclass(frozen=True)
class AuditSource:
    id: UUID
    state: str
    format: str
    field_names: tuple[str, ...]
    row_count: int
    expires_at: datetime

    @classmethod
    def parse(cls, data: JSON) -> "AuditSource":
        return cls(
            _uuid(data, "id"),
            _value(data, "state", str),
            _value(data, "format", str),
            tuple(_value(data, "field_names", list)),
            _value(data, "row_count", int),
            _datetime(data, "expires_at"),
        )


@dataclass(frozen=True)
class Audit:
    id: UUID
    source_id: UUID
    scan_policy_id: UUID
    scan_policy_version: int
    state: str
    total_segments: int
    completed_segments: int
    failed_segments: int
    finding_count: int
    total_credits: int
    source_available: bool
    last_error_code: str
    dataset_id: UUID | None = None
    run_id: UUID | None = None
    dataset_name: str | None = None
    report_url: str | None = None

    @classmethod
    def parse(cls, data: JSON) -> "Audit":
        return cls(
            _uuid(data, "id"),
            _uuid(data, "source_id"),
            _uuid(data, "scan_policy_id"),
            _value(data, "scan_policy_version", int),
            _value(data, "state", str),
            _value(data, "total_segments", int),
            _value(data, "completed_segments", int),
            _value(data, "failed_segments", int),
            _value(data, "finding_count", int),
            _value(data, "total_credits", int),
            _value(data, "source_available", bool),
            _value(data, "last_error_code", str),
            _uuid(data, "dataset_id") if data.get("dataset_id") is not None else None,
            _uuid(data, "run_id") if data.get("run_id") is not None else None,
            _value(data, "dataset_name", str) if data.get("dataset_name") is not None else None,
            _value(data, "report_url", str) if data.get("report_url") is not None else None,
        )


@dataclass(frozen=True)
class AuditFinding:
    id: UUID
    check_key: str
    code: str
    action: str
    severity: str
    review_state: str
    row_ordinal: int
    direction: str
    metadata: JSON

    input: JSON | None = dataclass_field(default=None, repr=False)
    input_retention: JSON | None = None
    input_state: str | None = None

    @classmethod
    def parse(cls, data: JSON) -> "AuditFinding":
        return cls(
            _uuid(data, "id"),
            _value(data, "check_key", str),
            _value(data, "code", str),
            _value(data, "action", str),
            _value(data, "severity", str),
            _value(data, "review_state", str),
            _value(data, "row_ordinal", int),
            _value(data, "direction", str),
            _value(data, "metadata", dict),
            input=_value(data, "input", dict) if data.get("input") is not None else None,
            input_retention=_value(data, "input_retention", dict)
            if data.get("input_retention") is not None
            else None,
            input_state=_value(data, "input_state", str)
            if data.get("input_state") is not None
            else None,
        )


@dataclass(frozen=True)
class Page(Generic[T]):
    items: tuple[T, ...]
    next_cursor: str | None


@dataclass(frozen=True)
class UsageEntry:
    id: UUID
    kind: str
    quantity: int
    semantic_key: str
    created_at: datetime

    @classmethod
    def parse(cls, data: JSON) -> "UsageEntry":
        return cls(
            _uuid(data, "id"),
            _value(data, "kind", str),
            _value(data, "quantity", int),
            _value(data, "semantic_key", str),
            _datetime(data, "created_at"),
        )


@dataclass(frozen=True)
class Usage:
    balance: int
    reserved: int
    available: int
    consumed: int
    entries: Page[UsageEntry]

    @classmethod
    def parse(cls, data: JSON) -> "Usage":
        cursor = _optional(data, "next_cursor", str)
        return cls(
            _value(data, "balance", int),
            _value(data, "reserved", int),
            _value(data, "available", int),
            _value(data, "consumed", int),
            Page(tuple(UsageEntry.parse(item) for item in _objects(data, "items")), cursor),
        )
