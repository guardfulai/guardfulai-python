"""Typed, dependency-free dataset requests and content-free report responses."""

from __future__ import annotations

import math
import types
from collections.abc import Callable, Mapping
from dataclasses import MISSING, asdict, dataclass, field, fields, is_dataclass
from datetime import date, datetime
from typing import (
    Any,
    Generic,
    Literal,
    TypeVar,
    Union,
    cast,
    get_args,
    get_origin,
    get_type_hints,
)
from uuid import UUID

from guardfulai.errors import ConfigurationError, ProtocolError
from guardfulai.reporting_validation import (
    SOURCE_KINDS,
    identifier,
    object_fields,
    require,
    text,
    timestamp,
    timezone_name,
    validate_audit_reporting,
    validate_date_mapping,
    validate_report_query,
    validate_reporting,
)

T = TypeVar("T")
Basis = Literal["latest_run", "events"]
State = Literal["checked", "partial", "failed", "pending", "excluded", "unrun"]
Decision = Literal["allow", "review", "block"]


def payload(value: Any, validator: Callable[[object], dict[str, Any]]) -> dict[str, Any]:
    try:
        if is_dataclass(value) and not isinstance(value, type):
            value = asdict(value)
        elif isinstance(value, Mapping):
            value = dict(value)
        return validator(value)
    except (ValueError, TypeError, OverflowError):
        raise ConfigurationError("reporting_input_invalid") from None


def _dataset(value: object) -> dict[str, Any]:
    data = object_fields(
        value, {"name", "description", "tags", "reporting_basis", "timezone", "archived"}
    )
    data["name"] = text(data.get("name"), 120, minimum=1)
    require(bool(data["name"].strip()))
    data["description"] = text(data.get("description", ""), 1000)
    tags = data.get("tags", ())
    require(isinstance(tags, (tuple, list)) and len(tags) <= 12)
    data["tags"] = [text(tag, 40, minimum=1) for tag in tags]
    require(len(set(data["tags"])) == len(tags))
    require(data.get("reporting_basis", "latest_run") in ("latest_run", "events"))
    data["timezone"] = timezone_name(data.get("timezone", "UTC"))
    require(type(data.get("archived", False)) is bool)
    return data


def _run(value: object) -> dict[str, Any]:
    data = object_fields(
        value, {"external_id", "source_kind", "expected_records", "correspondence_key"}
    )
    for key in ("external_id", "correspondence_key"):
        if key == "external_id" or key in data:
            data[key] = text(data.get(key), 128, minimum=1, pattern=r"[A-Za-z0-9_.:-]+")
    require(data.get("source_kind") in SOURCE_KINDS)
    if "expected_records" in data:
        require(type(data["expected_records"]) is int and 0 <= data["expected_records"] <= 50_000)
    return data


def _destination(value: object) -> dict[str, Any]:
    data = object_fields(value, {"mode", "name", "dataset_id"})
    mode = data.get("mode", "new")
    require(mode in ("new", "existing", "standalone"))
    data["mode"] = mode
    require((mode == "existing") == ("dataset_id" in data))
    if "dataset_id" in data:
        data["dataset_id"] = identifier(data["dataset_id"])
    if "name" in data:
        require(mode == "new")
        data["name"] = text(data["name"], 120, minimum=1)
        require(bool(data["name"].strip()))
    return data


def _setup(value: object) -> dict[str, Any]:
    data = object_fields(
        value,
        {"external_id", "source_kind", "expected_records", "correspondence_key", "destination"},
    )
    destination = _destination(data.pop("destination", {}))
    return _run(data) | {"destination": destination}


class RequestModel:
    @staticmethod
    def validator(value: object) -> dict[str, Any]:
        raise NotImplementedError

    def to_payload(self) -> dict[str, Any]:
        return payload(self, type(self).validator)


@dataclass(frozen=True)
class ReportingContext(RequestModel):
    dataset_id: UUID | str
    record_id: str
    run_id: UUID | str | None = None
    event_at: datetime | str | None = None
    event_date: date | str | None = None
    dimensions: dict[str, str] = field(default_factory=dict, repr=False)
    event_time_invalid: bool = False
    validator = staticmethod(validate_reporting)


@dataclass(frozen=True)
class AuditReportingContext(RequestModel):
    dataset_id: UUID | str
    run_id: UUID | str | None = None
    record_id_field: str | None = None
    source_kind: str = "api"
    validator = staticmethod(validate_audit_reporting)


@dataclass(frozen=True)
class DateMapping(RequestModel):
    field: str
    format: Literal["iso", "day_first", "month_first", "unix_seconds", "unix_milliseconds"]
    timezone: str | None = None
    validator = staticmethod(validate_date_mapping)


@dataclass(frozen=True)
class DatasetWrite(RequestModel):
    name: str
    description: str = ""
    tags: tuple[str, ...] = ()
    reporting_basis: Basis = "latest_run"
    timezone: str = "UTC"
    archived: bool = False
    validator = staticmethod(_dataset)


@dataclass(frozen=True)
class DatasetRunWrite(RequestModel):
    external_id: str
    source_kind: str
    expected_records: int | None = None
    correspondence_key: str | None = None
    validator = staticmethod(_run)


@dataclass(frozen=True)
class DatasetDestination(RequestModel):
    mode: Literal["new", "existing", "standalone"] = "new"
    name: str | None = None
    dataset_id: UUID | str | None = None
    validator = staticmethod(_destination)


@dataclass(frozen=True)
class DatasetRunSetup(DatasetRunWrite):
    destination: DatasetDestination = field(default_factory=DatasetDestination)
    validator = staticmethod(_setup)


@dataclass(frozen=True)
class ReportQuery(RequestModel):
    run_id: UUID | str | None = None
    start: date | str | None = None
    end: date | str | None = None
    time_basis: Literal["event", "received", "scanned"] | None = None
    timezone: str = "UTC"
    bucket: Literal["hour", "day", "week", "month"] = "day"
    category: str | None = None
    check: str | None = None
    decision: Decision | None = None
    action: str | None = None
    direction: Literal["input", "output"] | None = None
    review: str | None = None
    state: State | None = None
    policy_id: UUID | str | None = None
    policy_version: int | None = None
    rule_id: str | None = None
    outcome: Literal["compliant", "violated", "uncertain"] | None = None
    dimensions: dict[str, str] = field(default_factory=dict, repr=False)
    group_by: str = "category"
    dimension: str | None = None
    order: str = "-received"
    page: int = 1
    page_size: int = 50
    validator = staticmethod(validate_report_query)


def _decode(kind: Any, value: Any) -> Any:
    if kind is Any:
        return value
    origin, args = get_origin(kind), get_args(kind)
    if origin in (types.UnionType, Union):
        for candidate in args:
            try:
                return _decode(candidate, value)
            except (ValueError, TypeError, ProtocolError):
                pass
        raise ValueError
    if kind is type(None):
        require(value is None)
    elif origin is Literal:
        require(value in args)
    elif origin is tuple:
        require(isinstance(value, list))
        return tuple(_decode(args[0], item) for item in value)
    elif origin is dict:
        require(isinstance(value, dict))
        return {_decode(args[0], k): _decode(args[1], v) for k, v in value.items()}
    elif kind is UUID:
        return UUID(identifier(value))
    elif kind is datetime:
        return datetime.fromisoformat(timestamp(value))
    elif kind is date:
        return date.fromisoformat(timestamp(value, date_only=True))
    elif isinstance(kind, type) and issubclass(kind, ResponseModel):
        return kind.parse(value)
    elif kind is float:
        require(type(value) in (int, float) and math.isfinite(value) and value >= 0)
        return float(value)
    else:
        require(type(value) is kind)
        if kind is int:
            require(value >= 0)
    return value


class ResponseModel:
    @classmethod
    def parse(cls: type[T], value: Mapping[str, Any]) -> T:
        try:
            require(isinstance(value, dict))
            require(
                type(value.get("schema_version", 1)) is int and value.get("schema_version", 1) == 1
            )
            hints = get_type_hints(cls)
            values = {}
            for item in fields(cast(Any, cls)):
                if item.name not in value and item.default is not MISSING:
                    continue
                values[item.name] = _decode(hints[item.name], value[item.name])
            result = cls(**values)
            cast(ResponseModel, result)._validate()
            return result
        except (ValueError, KeyError, TypeError, OverflowError):
            raise ProtocolError("invalid_reporting_response") from None

    def _validate(self) -> None:
        pass


@dataclass(frozen=True)
class Dataset(ResponseModel):
    id: UUID
    name: str
    description: str
    tags: tuple[str, ...]
    reporting_basis: Basis
    timezone: str
    archived: bool
    created_at: datetime
    updated_at: datetime
    latest_run_id: UUID | None
    last_received_at: datetime | None


@dataclass(frozen=True)
class DatasetRunReceipt(ResponseModel):
    dataset_id: UUID
    dataset_name: str
    run_id: UUID
    report_url: str

    def _validate(self) -> None:
        require(self.report_url == f"/app/datasets/{self.dataset_id}/?run_id={self.run_id}")


@dataclass(frozen=True)
class DatasetRun(ResponseModel):
    id: UUID
    dataset_id: UUID
    external_id: str
    source_kind: str
    expected_records: int | None
    correspondence_key: str | None
    created_at: datetime
    sample: bool
    state: str


@dataclass(frozen=True)
class NumberedPage(Generic[T]):
    items: tuple[T, ...]
    total: int
    page: int
    page_size: int

    @classmethod
    def parse(cls, value: Mapping[str, Any], key: str, item_type: type[T]) -> NumberedPage[T]:
        try:
            total, page, size = (_decode(int, value[k]) for k in ("total", "page", "page_size"))
            require(page >= 1 and 1 <= size <= 200 and isinstance(value[key], list))
            require(len(value[key]) <= size)
            return cls(
                tuple(cast(Any, item_type).parse(item) for item in value[key]), total, page, size
            )
        except (ValueError, KeyError, TypeError):
            raise ProtocolError("invalid_reporting_page") from None


@dataclass(frozen=True)
class ReportSelection(ResponseModel):
    dataset_id: UUID
    run_id: UUID | None
    basis: Basis
    query: dict[str, Any] = field(repr=False)
    cutoff: datetime
    policy_versions: tuple[str, ...]
    catalog_versions: tuple[str, ...]
    limitations: tuple[str, ...]

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> ReportSelection:
        # Queries contain heterogeneous JSON; validate with the request boundary.
        try:
            query = validate_report_query(value["query"])
            return cls(
                _decode(UUID, value["dataset_id"]),
                _decode(UUID | None, value["run_id"]),
                _decode(Basis, value["basis"]),
                query,
                _decode(datetime, value["cutoff"]),
                _decode(tuple[str, ...], value["policy_versions"]),
                _decode(tuple[str, ...], value["catalog_versions"]),
                _decode(tuple[str, ...], value["limitations"]),
            )
        except (ValueError, KeyError, TypeError):
            raise ProtocolError("invalid_reporting_selection") from None


@dataclass(frozen=True)
class ReportRate(ResponseModel):
    numerator: int
    denominator: int
    value: float | None

    def _validate(self) -> None:
        require(self.numerator <= self.denominator)
        require(self.value == (self.numerator / self.denominator if self.denominator else None))


@dataclass(frozen=True)
class ReportAssessments(ResponseModel):
    completed: int
    compliant: int
    violated: int
    uncertain: int
    uncertainty: ReportRate
    recorded_segments: int
    not_recorded_segments: int
    failed_segments: int
    pending_segments: int
    unrun_segments: int

    def _validate(self) -> None:
        require(self.completed == self.compliant + self.violated + self.uncertain)
        require(
            self.uncertainty.denominator == self.completed
            and self.uncertainty.numerator == self.uncertain
        )


@dataclass(frozen=True)
class ReportSummary(ResponseModel):
    selection: ReportSelection
    records: int
    checked: int
    partial: int
    failed: int
    pending: int
    excluded: int
    unrun: int
    flagged: ReportRate
    partial_flagged: int
    segments: int
    completed_segments: int
    findings: int
    undated: int
    invalid_dates: int
    consumed_credits: int
    reused_segments: int
    sample: bool
    assessments: ReportAssessments | None = None

    def _validate(self) -> None:
        require(
            self.records
            == sum(
                (self.checked, self.partial, self.failed, self.pending, self.excluded, self.unrun)
            )
        )
        require(self.flagged.denominator == self.checked and self.partial_flagged <= self.partial)
        require(self.reused_segments <= self.completed_segments <= self.segments)
        require(self.undated + self.invalid_dates <= self.records)


@dataclass(frozen=True)
class ReportBreakdown(ResponseModel):
    key: str
    label: str
    unit: Literal["records", "findings", "segments", "assessments"]
    count: int
    denominator: int | None
    available: bool


@dataclass(frozen=True)
class ReportBreakdowns(ResponseModel):
    selection: ReportSelection
    breakdowns: tuple[ReportBreakdown, ...]

    def _validate(self) -> None:
        require(len(self.breakdowns) <= 200)


@dataclass(frozen=True)
class ReportSeriesPoint(ResponseModel):
    bucket: str
    records: int
    checked: int
    flagged: int

    def _validate(self) -> None:
        require(self.flagged <= self.checked <= self.records)


@dataclass(frozen=True)
class ReportSeries(ResponseModel):
    selection: ReportSelection
    series: tuple[ReportSeriesPoint, ...]

    def _validate(self) -> None:
        require(len(self.series) <= 366)


@dataclass(frozen=True)
class ReportRecord(ResponseModel):
    input: dict[str, Any] | None = field(default=None, repr=False, kw_only=True)
    input_state: str | None = field(default=None, kw_only=True)
    input_retention: dict[str, Any] | None = field(default=None, kw_only=True)
    id: UUID
    run_id: UUID | None
    record_id: str
    state: State
    decision: Decision | None
    event_at: datetime | None
    event_date: date | None
    date_status: Literal["valid", "missing", "invalid", "unknown"]
    received_at: datetime
    scanned_at: datetime | None
    segments: int
    completed_segments: int
    finding_count: int
    categories: tuple[str, ...]
    review_supported: bool
    source_available: bool
    dimensions: dict[str, str] = field(repr=False)
    assessments: ReportAssessments | None = None


@dataclass(frozen=True)
class ReportRecordPage(ResponseModel):
    selection: ReportSelection
    total: int
    page: int
    page_size: int
    records: tuple[ReportRecord, ...]

    def _validate(self) -> None:
        require(self.page >= 1 and 1 <= self.page_size <= 200)
        require(len(self.records) <= self.page_size)
