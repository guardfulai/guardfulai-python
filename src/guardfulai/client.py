"""Safe fixed-origin sync and async clients with bounded retry behavior."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import secrets
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import httpx

from guardfulai.errors import (
    ERROR_TYPES,
    APIError,
    ConfigurationError,
    ErrorDetail,
    ProtocolError,
    TransportError,
)
from guardfulai.models import (
    Audit,
    AuditFinding,
    AuditResult,
    AuditSource,
    Capabilities,
    Check,
    CheckTaxonomy,
    Page,
    Policy,
    PolicyVersion,
    PriceQuote,
    ScanResult,
    Template,
    Usage,
)
from guardfulai.reporting import (
    AuditReportingContext,
    Dataset,
    DatasetDestination,
    DatasetRun,
    DatasetRunReceipt,
    DatasetRunSetup,
    DatasetRunWrite,
    DatasetWrite,
    DateMapping,
    NumberedPage,
    ReportBreakdowns,
    ReportingContext,
    ReportQuery,
    ReportRecordPage,
    ReportSeries,
    ReportSummary,
    payload,
)
from guardfulai.reporting_validation import (
    identifier,
    validate_audit_reporting,
    validate_date_mapping,
    validate_report_query,
    validate_reporting,
)
from guardfulai.response_validation import public_error_code

IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
RETRY_STATUSES = frozenset({429, 503, 504})
TERMINAL_AUDIT_STATES = frozenset(
    {"completed", "completed_with_errors", "failed", "canceled", "expired"}
)


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay: float = 0.1
    max_delay: float = 2.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 5:
            raise ConfigurationError("max_attempts must be between 1 and 5")
        if not 0 <= self.base_delay <= self.max_delay <= 10:
            raise ConfigurationError("retry delays are invalid")


StructuredFields = Mapping[str, str | int | float | bool | None]

DEFAULT_RETRY_POLICY = RetryPolicy()


def new_idempotency_key(prefix: str = "sdk") -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", prefix):
        raise ConfigurationError("idempotency prefix is invalid")
    return f"{prefix}:{secrets.token_hex(16)}"


def _idempotency_key(value: str) -> str:
    if not isinstance(value, str) or not IDEMPOTENCY_PATTERN.fullmatch(value):
        raise ConfigurationError("idempotency key is invalid")
    return value


def _origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        raise ConfigurationError("base_url must be a bare HTTPS or loopback HTTP origin") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigurationError("base_url must be a bare HTTPS or loopback HTTP origin")
    loopback = host == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if parsed.scheme == "http" and not loopback:
        raise ConfigurationError("plain HTTP is allowed only for loopback development")
    netloc = f"[{host}]:{port}" if ":" in host and port else f"[{host}]" if ":" in host else host
    if port and ":" not in host:
        netloc = f"{host}:{port}"
    return urlunsplit((parsed.scheme, netloc, "", "", ""))


def _api_key(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or any(c.isspace() for c in value)
    ):
        raise ConfigurationError("api_key is invalid")
    return value


def _json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except (ValueError, UnicodeError):
        raise ProtocolError("server returned invalid JSON") from None


def _object(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError("server returned an invalid object")
    return value


def _list(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ProtocolError("server returned an invalid list")
    return value


def _error(response: httpx.Response) -> APIError:
    code, retryable = "unexpected_http_status", response.status_code in RETRY_STATUSES
    try:
        value = response.json()
        if isinstance(value, dict):
            if isinstance(value.get("code"), str):
                code = public_error_code(value["code"])
            if isinstance(value.get("retryable"), bool):
                retryable = value["retryable"]
    except (ValueError, UnicodeError):
        pass
    detail = ErrorDetail(response.status_code, code, retryable)
    return ERROR_TYPES.get(response.status_code, APIError)(detail)


def _retry_delay(response: httpx.Response | None, policy: RetryPolicy, attempt: int) -> float:
    if response is not None:
        try:
            return min(policy.max_delay, max(0.0, float(response.headers["Retry-After"])))
        except (KeyError, TypeError, ValueError):
            pass
    return min(policy.max_delay, policy.base_delay * (2.0 ** (attempt - 1)))


def reporting_payload(value: ReportingContext | Mapping[str, Any]) -> dict[str, Any]:
    return payload(value, validate_reporting)


def audit_reporting_payload(value: AuditReportingContext | Mapping[str, Any]) -> dict[str, Any]:
    return payload(value, validate_audit_reporting)


def date_mapping_payload(value: DateMapping | Mapping[str, Any]) -> dict[str, Any]:
    return payload(value, validate_date_mapping)


def _dataset_path(dataset_id: UUID | str) -> str:
    try:
        return f"/v1/datasets/{identifier(dataset_id)}"
    except ValueError:
        raise ConfigurationError("dataset_id_invalid") from None


def _pages(page: int, page_size: int) -> dict[str, Any]:
    return payload({"page": page, "page_size": page_size}, validate_report_query)


def _report_query(query: ReportQuery | Mapping[str, Any] | None) -> dict[str, Any]:
    return payload(query if query is not None else {}, validate_report_query)


def _input_query(value: bool | None) -> dict[str, str]:
    if value is None:
        return {}
    if type(value) is not bool:
        raise ConfigurationError("include_input_invalid")
    return {"include_input": "true" if value else "false"}


class GuardfulAI:
    """Synchronous Guardful AI API client."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "http://127.0.0.1:8000",
        timeout: float | httpx.Timeout = 300.0,
        retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.retry_policy = retry_policy
        self._client = httpx.Client(
            base_url=_origin(base_url),
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {_api_key(api_key)}",
                "User-Agent": "guardfulai-python/0.1.0",
            },
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> GuardfulAI:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
        data: Mapping[str, str] | None = None,
        files: Mapping[str, tuple[str, bytes, str]] | None = None,
        params: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        retryable: bool = False,
    ) -> Any:
        headers = {}
        if idempotency_key is not None:
            headers["Idempotency-Key"] = _idempotency_key(idempotency_key)
        for attempt in range(1, self.retry_policy.max_attempts + 1):
            response = None
            try:
                response = self._client.request(
                    method,
                    path,
                    json=json,
                    data=data,
                    files=files,
                    params=params,
                    headers=headers,
                )
            except httpx.TransportError:
                if not retryable or attempt == self.retry_policy.max_attempts:
                    raise TransportError("Guardful AI request failed") from None
            else:
                if response.is_success:
                    return _json(response)
                error = _error(response)
                if not (retryable and error.retryable and attempt < self.retry_policy.max_attempts):
                    raise error
            time.sleep(_retry_delay(response, self.retry_policy, attempt))
        raise TransportError("Guardful AI request failed")

    def get_capabilities(self) -> Capabilities:
        return Capabilities.parse(_object(self._request("GET", "/v1/capabilities")))

    def get_check_taxonomy(self) -> CheckTaxonomy:
        return CheckTaxonomy.parse(_object(self._request("GET", "/v1/check-taxonomy")))

    def list_checks(self) -> tuple[Check, ...]:
        return tuple(Check.parse(item) for item in _list(self._request("GET", "/v1/checks")))

    def list_policies(self, *, offset: int = 0, limit: int = 20) -> tuple[Policy, ...]:
        if (
            type(offset) is not int
            or type(limit) is not int
            or not 0 <= offset <= 1000
            or not 1 <= limit <= 50
        ):
            raise ConfigurationError("pagination_invalid")
        return tuple(
            Policy.parse(item)
            for item in _list(
                self._request("GET", "/v1/scan-policies", params={"offset": offset, "limit": limit})
            )
        )

    def list_templates(self) -> tuple[Template, ...]:
        return tuple(
            Template.parse(item)
            for item in _list(self._request("GET", "/v1/scan-policy-templates"))
        )

    def copy_template(
        self,
        slug: str,
        *,
        name: str,
        direction: str | None = None,
        selected_checks: Sequence[str] | None = None,
    ) -> Policy:
        payload: dict[str, Any] = {"name": name}
        if direction is not None:
            payload["direction"] = direction
        if selected_checks is not None:
            payload["selected_checks"] = list(selected_checks)
        return Policy.parse(
            _object(self._request("POST", f"/v1/scan-policy-templates/{slug}/copy", json=payload))
        )

    def get_policy(self, policy_id: UUID | str, *, version: int | None = None) -> PolicyVersion:
        params = {"version": version} if version is not None else None
        return PolicyVersion.parse(
            _object(self._request("GET", f"/v1/scan-policies/{policy_id}", params=params))
        )

    def publish_policy(
        self,
        policy_id: UUID | str,
        *,
        expected_version: int,
        checks: Sequence[Mapping[str, Any]],
        direction: str,
        runtime_choice: str = "retain",
        custom_rules: Sequence[Mapping[str, Any]] | None = None,
        semantic_policies: Sequence[Mapping[str, Any]] | None = None,
    ) -> PolicyVersion:
        return PolicyVersion.parse(
            _object(
                self._request(
                    "POST",
                    f"/v1/scan-policies/{policy_id}/versions",
                    json={
                        "expected_version": expected_version,
                        "checks": list(checks),
                        "direction": direction,
                        "processing_mode": "local_only",
                        "runtime_choice": runtime_choice,
                        **(
                            {"custom_rules": list(custom_rules)} if custom_rules is not None else {}
                        ),
                        **(
                            {"semantic_policies": list(semantic_policies)}
                            if semantic_policies is not None
                            else {}
                        ),
                    },
                )
            )
        )

    def estimate(
        self,
        policy_id: UUID | str,
        content: str,
        *,
        version: int | None = None,
        direction: str = "input",
        context: str | None = None,
        structured_fields: StructuredFields | None = None,
    ) -> PriceQuote:
        payload = self._check_payload(
            policy_id, content, version, direction, context, False, structured_fields
        )
        return PriceQuote.parse(
            _object(self._request("POST", f"/v1/scan-policies/{policy_id}/estimate", json=payload)),
            expected_version=version,
        )

    @staticmethod
    def _check_payload(
        policy_id: UUID | str,
        content: str,
        version: int | None,
        direction: str,
        context: str | None,
        return_redacted_content: bool,
        structured_fields: StructuredFields | None = None,
        reporting: ReportingContext | Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "content": content,
            "scan_policy_id": str(policy_id),
            "direction": direction,
            "return_redacted_content": return_redacted_content,
        }
        if version is not None:
            payload["scan_policy_version"] = version
        if context is not None:
            payload["context"] = context
        if structured_fields is not None:
            payload["structured_fields"] = dict(structured_fields)
        if reporting is not None:
            payload["reporting"] = reporting_payload(reporting)
        return payload

    def check(
        self,
        policy_id: UUID | str,
        content: str,
        *,
        idempotency_key: str,
        version: int | None = None,
        direction: str = "input",
        context: str | None = None,
        structured_fields: StructuredFields | None = None,
        return_redacted_content: bool = False,
        reporting: ReportingContext | Mapping[str, Any] | None = None,
        input_retention_days: int | None = None,
        include_input: bool | None = None,
    ) -> ScanResult:
        payload = self._check_payload(
            policy_id,
            content,
            version,
            direction,
            context,
            return_redacted_content,
            structured_fields,
            reporting,
        )
        if input_retention_days is not None:
            if type(input_retention_days) is not int or input_retention_days not in {0, 1, 7, 30}:
                raise ValueError("input_retention_invalid")
            payload["input_retention_days"] = input_retention_days
        if include_input is not None:
            if type(include_input) is not bool:
                raise ValueError("include_input_invalid")
            payload["include_input"] = include_input
        return ScanResult.parse(
            _object(
                self._request(
                    "POST",
                    "/v1/check",
                    json=payload,
                    idempotency_key=idempotency_key,
                    retryable=True,
                )
            ),
            expected_version=version,
        )

    def get_scan(self, scan_id: UUID | str, *, include_input: bool | None = None) -> ScanResult:
        return ScanResult.parse(
            _object(
                self._request(
                    "GET",
                    f"/v1/scans/{identifier(scan_id)}",
                    params=_input_query(include_input),
                    retryable=True,
                )
            )
        )

    def list_datasets(
        self,
        *,
        page: int = 1,
        page_size: int = 50,
        search: str = "",
        archived: bool = False,
        order: str = "-updated",
        tag: str | None = None,
        source: str | None = None,
    ) -> NumberedPage[Dataset]:
        params = _pages(page, page_size)
        if (
            not isinstance(search, str)
            or len(search) > 120
            or type(archived) is not bool
            or order not in ("name", "-updated", "-received")
        ):
            raise ConfigurationError("dataset_filters_invalid")
        params.update(search=search, archived=archived, order=order)
        for key, value, maximum in (("tag", tag, 40), ("source", source, 16)):
            if value is not None:
                if not isinstance(value, str) or len(value) > maximum:
                    raise ConfigurationError("dataset_filters_invalid")
                params[key] = value
        return NumberedPage.parse(
            _object(self._request("GET", "/v1/datasets", params=params, retryable=True)),
            "datasets",
            Dataset,
        )

    def get_dataset(self, dataset_id: UUID | str) -> Dataset:
        return Dataset.parse(
            _object(self._request("GET", _dataset_path(dataset_id), retryable=True))
        )

    def setup_dataset_run(self, value: DatasetRunSetup) -> DatasetRunReceipt:
        return DatasetRunReceipt.parse(
            _object(
                self._request(
                    "POST",
                    "/v1/dataset-runs",
                    json=value.to_payload(),
                    retryable=True,
                )
            )
        )

    def create_dataset(self, value: DatasetWrite) -> Dataset:
        # Creation has no recovery key: do not automatically retry a lost response.
        return Dataset.parse(
            _object(self._request("POST", "/v1/datasets", json=value.to_payload()))
        )

    def update_dataset(self, dataset_id: UUID | str, value: DatasetWrite) -> Dataset:
        return Dataset.parse(
            _object(
                self._request(
                    "PUT", _dataset_path(dataset_id), json=value.to_payload(), retryable=True
                )
            )
        )

    def list_dataset_runs(
        self, dataset_id: UUID | str, *, page: int = 1, page_size: int = 50
    ) -> NumberedPage[DatasetRun]:
        return NumberedPage.parse(
            _object(
                self._request(
                    "GET",
                    _dataset_path(dataset_id) + "/runs",
                    params=_pages(page, page_size),
                    retryable=True,
                )
            ),
            "runs",
            DatasetRun,
        )

    def create_dataset_run(self, dataset_id: UUID | str, value: DatasetRunWrite) -> DatasetRun:
        # Immutable external_id is the server's existing run recovery identity.
        return DatasetRun.parse(
            _object(
                self._request(
                    "POST",
                    _dataset_path(dataset_id) + "/runs",
                    json=value.to_payload(),
                    retryable=True,
                )
            )
        )

    def get_report_summary(
        self, dataset_id: UUID | str, *, query: ReportQuery | Mapping[str, Any] | None = None
    ) -> ReportSummary:
        return ReportSummary.parse(
            _object(
                self._request(
                    "POST",
                    _dataset_path(dataset_id) + "/summary/query",
                    json=_report_query(query),
                    retryable=True,
                )
            )
        )

    def get_report_breakdowns(
        self, dataset_id: UUID | str, *, query: ReportQuery | Mapping[str, Any] | None = None
    ) -> ReportBreakdowns:
        return ReportBreakdowns.parse(
            _object(
                self._request(
                    "POST",
                    _dataset_path(dataset_id) + "/breakdowns/query",
                    json=_report_query(query),
                    retryable=True,
                )
            )
        )

    def get_report_series(
        self, dataset_id: UUID | str, *, query: ReportQuery | Mapping[str, Any] | None = None
    ) -> ReportSeries:
        return ReportSeries.parse(
            _object(
                self._request(
                    "POST",
                    _dataset_path(dataset_id) + "/series/query",
                    json=_report_query(query),
                    retryable=True,
                )
            )
        )

    def get_report_records(
        self,
        dataset_id: UUID | str,
        *,
        query: ReportQuery | Mapping[str, Any] | None = None,
        include_input: bool | None = None,
    ) -> ReportRecordPage:
        return ReportRecordPage.parse(
            _object(
                self._request(
                    "POST",
                    _dataset_path(dataset_id) + "/records/query",
                    json=_report_query(query),
                    params=_input_query(include_input),
                    retryable=True,
                )
            )
        )

    def upload_audit_source(
        self,
        filename: str,
        content: bytes,
        *,
        source_format: str,
        retention: str = "default",
        input_retention_days: int | None = None,
        idempotency_key: str | None = None,
    ) -> AuditSource:
        data = {"source_format": source_format, "retention": retention}
        if input_retention_days is not None:
            if (
                type(input_retention_days) is not int
                or input_retention_days not in {0, 1, 7, 30}
                or retention != "default"
            ):
                raise ConfigurationError("input_retention_invalid")
            data["input_retention_days"] = str(input_retention_days)
        return AuditSource.parse(
            _object(
                self._request(
                    "POST",
                    "/v1/audit-sources",
                    data=data,
                    files={"file": (filename, content, "application/octet-stream")},
                    idempotency_key=idempotency_key,
                    retryable=idempotency_key is not None,
                )
            )
        )

    def create_audit(
        self,
        source_id: UUID | str,
        policy_id: UUID | str,
        *,
        fields: Sequence[tuple[str, str]],
        metadata_fields: Sequence[str] = (),
        date_field: str | None = None,
        version: int | None = None,
        idempotency_key: str | None = None,
        reporting: AuditReportingContext | Mapping[str, Any] | None = None,
        destination: DatasetDestination | None = None,
        reporting_date: DateMapping | Mapping[str, Any] | None = None,
        structured_fields: Sequence[Mapping[str, str]] | None = None,
        context_field: str | None = None,
    ) -> Audit:
        payload: dict[str, Any] = {
            "source_id": str(source_id),
            "scan_policy_id": str(policy_id),
            "fields": [{"source": name, "direction": direction} for name, direction in fields],
            "metadata_fields": list(metadata_fields),
        }
        if date_field is not None:
            payload["date_field"] = date_field
        if version is not None:
            payload["scan_policy_version"] = version
        if destination is not None:
            if reporting is not None:
                raise ConfigurationError("dataset_destination_conflict")
            payload["destination"] = destination.to_payload()
        if reporting is not None:
            payload["reporting"] = audit_reporting_payload(reporting)
        if reporting_date is not None:
            payload["reporting_date"] = date_mapping_payload(reporting_date)
        if structured_fields is not None:
            payload["structured_fields"] = [dict(item) for item in structured_fields]
        if context_field is not None:
            payload["context_field"] = context_field
        return Audit.parse(
            _object(
                self._request(
                    "POST",
                    "/v1/audits",
                    json=payload,
                    idempotency_key=idempotency_key,
                    retryable=idempotency_key is not None,
                )
            )
        )

    def run_audit(self, audit_id: UUID | str) -> Audit:
        return Audit.parse(
            _object(self._request("POST", f"/v1/audits/{audit_id}/run", retryable=True))
        )

    def get_audit(self, audit_id: UUID | str) -> Audit:
        return Audit.parse(_object(self._request("GET", f"/v1/audits/{audit_id}", retryable=True)))

    def cancel_audit(self, audit_id: UUID | str) -> Audit:
        return Audit.parse(
            _object(self._request("POST", f"/v1/audits/{audit_id}/cancel", retryable=True))
        )

    def list_audit_results(
        self,
        audit_id: UUID | str,
        *,
        cursor: str | None = None,
        limit: int = 50,
        include_input: bool | None = None,
    ) -> Page[AuditResult]:
        params: dict[str, Any] = {"limit": limit, **_input_query(include_input)}
        if cursor is not None:
            params["cursor"] = cursor
        value = _object(
            self._request("GET", f"/v1/audits/{audit_id}/results", params=params, retryable=True)
        )
        items, next_cursor = value.get("items"), value.get("next_cursor")
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ProtocolError("server returned invalid audit results")
        if next_cursor is not None and not isinstance(next_cursor, str):
            raise ProtocolError("server returned invalid audit results cursor")
        return Page(tuple(AuditResult.parse(item) for item in items), next_cursor)

    def list_audit_findings(
        self,
        audit_id: UUID | str,
        *,
        cursor: str | None = None,
        limit: int = 50,
        include_input: bool | None = None,
    ) -> Page[AuditFinding]:
        params: dict[str, Any] = {"limit": limit, **_input_query(include_input)}
        if cursor is not None:
            params["cursor"] = cursor
        value = _object(
            self._request("GET", f"/v1/audits/{audit_id}/findings", params=params, retryable=True)
        )
        items = value.get("items")
        next_cursor = value.get("next_cursor")
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ProtocolError("server returned invalid findings")
        if next_cursor is not None and not isinstance(next_cursor, str):
            raise ProtocolError("server returned invalid findings cursor")
        return Page(tuple(AuditFinding.parse(item) for item in items), next_cursor)

    def get_usage(self, *, cursor: str | None = None, limit: int = 50) -> Usage:
        params: dict[str, Any] = {"limit": limit}
        if cursor is not None:
            params["cursor"] = cursor
        return Usage.parse(_object(self._request("GET", "/v1/usage", params=params)))

    def wait_for_audit(
        self, audit_id: UUID | str, *, timeout: float = 30.0, interval: float = 0.25
    ) -> Audit:
        if timeout <= 0 or interval <= 0:
            raise ConfigurationError("poll timeout and interval must be positive")
        deadline = time.monotonic() + timeout
        while True:
            value = self.get_audit(audit_id)
            if value.state in TERMINAL_AUDIT_STATES:
                return value
            if time.monotonic() >= deadline:
                raise TransportError("audit polling timed out")
            time.sleep(min(interval, max(0.0, deadline - time.monotonic())))


class AsyncGuardfulAI:
    """Asynchronous Guardful AI API client with the same wire semantics."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "http://127.0.0.1:8000",
        timeout: float | httpx.Timeout = 300.0,
        retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.retry_policy = retry_policy
        self._client = httpx.AsyncClient(
            base_url=_origin(base_url),
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {_api_key(api_key)}",
                "User-Agent": "guardfulai-python/0.1.0",
            },
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncGuardfulAI:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
        data: Mapping[str, str] | None = None,
        files: Mapping[str, tuple[str, bytes, str]] | None = None,
        params: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        retryable: bool = False,
    ) -> Any:
        headers = {}
        if idempotency_key is not None:
            headers["Idempotency-Key"] = _idempotency_key(idempotency_key)
        for attempt in range(1, self.retry_policy.max_attempts + 1):
            response = None
            try:
                response = await self._client.request(
                    method,
                    path,
                    json=json,
                    data=data,
                    files=files,
                    params=params,
                    headers=headers,
                )
            except httpx.TransportError:
                if not retryable or attempt == self.retry_policy.max_attempts:
                    raise TransportError("Guardful AI request failed") from None
            else:
                if response.is_success:
                    return _json(response)
                error = _error(response)
                if not (retryable and error.retryable and attempt < self.retry_policy.max_attempts):
                    raise error
            await asyncio.sleep(_retry_delay(response, self.retry_policy, attempt))
        raise TransportError("Guardful AI request failed")

    async def get_capabilities(self) -> Capabilities:
        return Capabilities.parse(_object(await self._request("GET", "/v1/capabilities")))

    async def get_check_taxonomy(self) -> CheckTaxonomy:
        return CheckTaxonomy.parse(_object(await self._request("GET", "/v1/check-taxonomy")))

    async def list_checks(self) -> tuple[Check, ...]:
        return tuple(Check.parse(item) for item in _list(await self._request("GET", "/v1/checks")))

    async def list_policies(self, *, offset: int = 0, limit: int = 20) -> tuple[Policy, ...]:
        if (
            type(offset) is not int
            or type(limit) is not int
            or not 0 <= offset <= 1000
            or not 1 <= limit <= 50
        ):
            raise ConfigurationError("pagination_invalid")
        return tuple(
            Policy.parse(item)
            for item in _list(
                await self._request(
                    "GET", "/v1/scan-policies", params={"offset": offset, "limit": limit}
                )
            )
        )

    async def list_templates(self) -> tuple[Template, ...]:
        return tuple(
            Template.parse(item)
            for item in _list(await self._request("GET", "/v1/scan-policy-templates"))
        )

    async def copy_template(
        self,
        slug: str,
        *,
        name: str,
        direction: str | None = None,
        selected_checks: Sequence[str] | None = None,
    ) -> Policy:
        payload: dict[str, Any] = {"name": name}
        if direction is not None:
            payload["direction"] = direction
        if selected_checks is not None:
            payload["selected_checks"] = list(selected_checks)
        return Policy.parse(
            _object(
                await self._request("POST", f"/v1/scan-policy-templates/{slug}/copy", json=payload)
            )
        )

    async def get_policy(
        self, policy_id: UUID | str, *, version: int | None = None
    ) -> PolicyVersion:
        params = {"version": version} if version is not None else None
        return PolicyVersion.parse(
            _object(await self._request("GET", f"/v1/scan-policies/{policy_id}", params=params))
        )

    async def publish_policy(
        self,
        policy_id: UUID | str,
        *,
        expected_version: int,
        checks: Sequence[Mapping[str, Any]],
        direction: str,
        runtime_choice: str = "retain",
        custom_rules: Sequence[Mapping[str, Any]] | None = None,
        semantic_policies: Sequence[Mapping[str, Any]] | None = None,
    ) -> PolicyVersion:
        return PolicyVersion.parse(
            _object(
                await self._request(
                    "POST",
                    f"/v1/scan-policies/{policy_id}/versions",
                    json={
                        "expected_version": expected_version,
                        "checks": list(checks),
                        "direction": direction,
                        "processing_mode": "local_only",
                        "runtime_choice": runtime_choice,
                        **(
                            {"custom_rules": list(custom_rules)} if custom_rules is not None else {}
                        ),
                        **(
                            {"semantic_policies": list(semantic_policies)}
                            if semantic_policies is not None
                            else {}
                        ),
                    },
                )
            )
        )

    async def estimate(
        self,
        policy_id: UUID | str,
        content: str,
        *,
        version: int | None = None,
        direction: str = "input",
        context: str | None = None,
        structured_fields: StructuredFields | None = None,
    ) -> PriceQuote:
        payload = GuardfulAI._check_payload(
            policy_id,
            content,
            version,
            direction,
            context,
            False,
            structured_fields,
        )
        return PriceQuote.parse(
            _object(
                await self._request("POST", f"/v1/scan-policies/{policy_id}/estimate", json=payload)
            ),
            expected_version=version,
        )

    async def check(
        self,
        policy_id: UUID | str,
        content: str,
        *,
        idempotency_key: str,
        version: int | None = None,
        direction: str = "input",
        context: str | None = None,
        structured_fields: StructuredFields | None = None,
        return_redacted_content: bool = False,
        reporting: ReportingContext | Mapping[str, Any] | None = None,
        input_retention_days: int | None = None,
        include_input: bool | None = None,
    ) -> ScanResult:
        payload = GuardfulAI._check_payload(
            policy_id,
            content,
            version,
            direction,
            context,
            return_redacted_content,
            structured_fields,
            reporting,
        )
        if input_retention_days is not None:
            if type(input_retention_days) is not int or input_retention_days not in {0, 1, 7, 30}:
                raise ValueError("input_retention_invalid")
            payload["input_retention_days"] = input_retention_days
        if include_input is not None:
            if type(include_input) is not bool:
                raise ValueError("include_input_invalid")
            payload["include_input"] = include_input
        return ScanResult.parse(
            _object(
                await self._request(
                    "POST",
                    "/v1/check",
                    json=payload,
                    idempotency_key=idempotency_key,
                    retryable=True,
                )
            ),
            expected_version=version,
        )

    async def get_scan(
        self, scan_id: UUID | str, *, include_input: bool | None = None
    ) -> ScanResult:
        return ScanResult.parse(
            _object(
                await self._request(
                    "GET",
                    f"/v1/scans/{identifier(scan_id)}",
                    params=_input_query(include_input),
                    retryable=True,
                )
            )
        )

    async def list_datasets(
        self,
        *,
        page: int = 1,
        page_size: int = 50,
        search: str = "",
        archived: bool = False,
        order: str = "-updated",
        tag: str | None = None,
        source: str | None = None,
    ) -> NumberedPage[Dataset]:
        params = _pages(page, page_size)
        if (
            not isinstance(search, str)
            or len(search) > 120
            or type(archived) is not bool
            or order not in ("name", "-updated", "-received")
        ):
            raise ConfigurationError("dataset_filters_invalid")
        params.update(search=search, archived=archived, order=order)
        for key, value, maximum in (("tag", tag, 40), ("source", source, 16)):
            if value is not None:
                if not isinstance(value, str) or len(value) > maximum:
                    raise ConfigurationError("dataset_filters_invalid")
                params[key] = value
        return NumberedPage.parse(
            _object(await self._request("GET", "/v1/datasets", params=params, retryable=True)),
            "datasets",
            Dataset,
        )

    async def get_dataset(self, dataset_id: UUID | str) -> Dataset:
        return Dataset.parse(
            _object(await self._request("GET", _dataset_path(dataset_id), retryable=True))
        )

    async def setup_dataset_run(self, value: DatasetRunSetup) -> DatasetRunReceipt:
        return DatasetRunReceipt.parse(
            _object(
                await self._request(
                    "POST",
                    "/v1/dataset-runs",
                    json=value.to_payload(),
                    retryable=True,
                )
            )
        )

    async def create_dataset(self, value: DatasetWrite) -> Dataset:
        # Creation has no recovery key: do not automatically retry a lost response.
        return Dataset.parse(
            _object(await self._request("POST", "/v1/datasets", json=value.to_payload()))
        )

    async def update_dataset(self, dataset_id: UUID | str, value: DatasetWrite) -> Dataset:
        return Dataset.parse(
            _object(
                await self._request(
                    "PUT", _dataset_path(dataset_id), json=value.to_payload(), retryable=True
                )
            )
        )

    async def list_dataset_runs(
        self, dataset_id: UUID | str, *, page: int = 1, page_size: int = 50
    ) -> NumberedPage[DatasetRun]:
        return NumberedPage.parse(
            _object(
                await self._request(
                    "GET",
                    _dataset_path(dataset_id) + "/runs",
                    params=_pages(page, page_size),
                    retryable=True,
                )
            ),
            "runs",
            DatasetRun,
        )

    async def create_dataset_run(
        self, dataset_id: UUID | str, value: DatasetRunWrite
    ) -> DatasetRun:
        # Immutable external_id is the server's existing run recovery identity.
        return DatasetRun.parse(
            _object(
                await self._request(
                    "POST",
                    _dataset_path(dataset_id) + "/runs",
                    json=value.to_payload(),
                    retryable=True,
                )
            )
        )

    async def get_report_summary(
        self, dataset_id: UUID | str, *, query: ReportQuery | Mapping[str, Any] | None = None
    ) -> ReportSummary:
        return ReportSummary.parse(
            _object(
                await self._request(
                    "POST",
                    _dataset_path(dataset_id) + "/summary/query",
                    json=_report_query(query),
                    retryable=True,
                )
            )
        )

    async def get_report_breakdowns(
        self, dataset_id: UUID | str, *, query: ReportQuery | Mapping[str, Any] | None = None
    ) -> ReportBreakdowns:
        return ReportBreakdowns.parse(
            _object(
                await self._request(
                    "POST",
                    _dataset_path(dataset_id) + "/breakdowns/query",
                    json=_report_query(query),
                    retryable=True,
                )
            )
        )

    async def get_report_series(
        self, dataset_id: UUID | str, *, query: ReportQuery | Mapping[str, Any] | None = None
    ) -> ReportSeries:
        return ReportSeries.parse(
            _object(
                await self._request(
                    "POST",
                    _dataset_path(dataset_id) + "/series/query",
                    json=_report_query(query),
                    retryable=True,
                )
            )
        )

    async def get_report_records(
        self,
        dataset_id: UUID | str,
        *,
        query: ReportQuery | Mapping[str, Any] | None = None,
        include_input: bool | None = None,
    ) -> ReportRecordPage:
        return ReportRecordPage.parse(
            _object(
                await self._request(
                    "POST",
                    _dataset_path(dataset_id) + "/records/query",
                    json=_report_query(query),
                    params=_input_query(include_input),
                    retryable=True,
                )
            )
        )

    async def upload_audit_source(
        self,
        filename: str,
        content: bytes,
        *,
        source_format: str,
        retention: str = "default",
        input_retention_days: int | None = None,
        idempotency_key: str | None = None,
    ) -> AuditSource:
        data = {"source_format": source_format, "retention": retention}
        if input_retention_days is not None:
            if (
                type(input_retention_days) is not int
                or input_retention_days not in {0, 1, 7, 30}
                or retention != "default"
            ):
                raise ConfigurationError("input_retention_invalid")
            data["input_retention_days"] = str(input_retention_days)
        return AuditSource.parse(
            _object(
                await self._request(
                    "POST",
                    "/v1/audit-sources",
                    data=data,
                    files={"file": (filename, content, "application/octet-stream")},
                    idempotency_key=idempotency_key,
                    retryable=idempotency_key is not None,
                )
            )
        )

    async def create_audit(
        self,
        source_id: UUID | str,
        policy_id: UUID | str,
        *,
        fields: Sequence[tuple[str, str]],
        metadata_fields: Sequence[str] = (),
        date_field: str | None = None,
        version: int | None = None,
        idempotency_key: str | None = None,
        reporting: AuditReportingContext | Mapping[str, Any] | None = None,
        destination: DatasetDestination | None = None,
        reporting_date: DateMapping | Mapping[str, Any] | None = None,
        structured_fields: Sequence[Mapping[str, str]] | None = None,
        context_field: str | None = None,
    ) -> Audit:
        payload: dict[str, Any] = {
            "source_id": str(source_id),
            "scan_policy_id": str(policy_id),
            "fields": [{"source": name, "direction": direction} for name, direction in fields],
            "metadata_fields": list(metadata_fields),
        }
        if date_field is not None:
            payload["date_field"] = date_field
        if version is not None:
            payload["scan_policy_version"] = version
        if destination is not None:
            if reporting is not None:
                raise ConfigurationError("dataset_destination_conflict")
            payload["destination"] = destination.to_payload()
        if reporting is not None:
            payload["reporting"] = audit_reporting_payload(reporting)
        if reporting_date is not None:
            payload["reporting_date"] = date_mapping_payload(reporting_date)
        if structured_fields is not None:
            payload["structured_fields"] = [dict(item) for item in structured_fields]
        if context_field is not None:
            payload["context_field"] = context_field
        return Audit.parse(
            _object(
                await self._request(
                    "POST",
                    "/v1/audits",
                    json=payload,
                    idempotency_key=idempotency_key,
                    retryable=idempotency_key is not None,
                )
            )
        )

    async def run_audit(self, audit_id: UUID | str) -> Audit:
        return Audit.parse(
            _object(await self._request("POST", f"/v1/audits/{audit_id}/run", retryable=True))
        )

    async def get_audit(self, audit_id: UUID | str) -> Audit:
        return Audit.parse(
            _object(await self._request("GET", f"/v1/audits/{audit_id}", retryable=True))
        )

    async def cancel_audit(self, audit_id: UUID | str) -> Audit:
        return Audit.parse(
            _object(await self._request("POST", f"/v1/audits/{audit_id}/cancel", retryable=True))
        )

    async def list_audit_results(
        self,
        audit_id: UUID | str,
        *,
        cursor: str | None = None,
        limit: int = 50,
        include_input: bool | None = None,
    ) -> Page[AuditResult]:
        params: dict[str, Any] = {"limit": limit, **_input_query(include_input)}
        if cursor is not None:
            params["cursor"] = cursor
        value = _object(
            await self._request(
                "GET", f"/v1/audits/{audit_id}/results", params=params, retryable=True
            )
        )
        items, next_cursor = value.get("items"), value.get("next_cursor")
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ProtocolError("server returned invalid audit results")
        if next_cursor is not None and not isinstance(next_cursor, str):
            raise ProtocolError("server returned invalid audit results cursor")
        return Page(tuple(AuditResult.parse(item) for item in items), next_cursor)

    async def list_audit_findings(
        self,
        audit_id: UUID | str,
        *,
        cursor: str | None = None,
        limit: int = 50,
        include_input: bool | None = None,
    ) -> Page[AuditFinding]:
        params: dict[str, Any] = {"limit": limit, **_input_query(include_input)}
        if cursor is not None:
            params["cursor"] = cursor
        value = _object(
            await self._request(
                "GET", f"/v1/audits/{audit_id}/findings", params=params, retryable=True
            )
        )
        items, next_cursor = value.get("items"), value.get("next_cursor")
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ProtocolError("server returned invalid findings")
        if next_cursor is not None and not isinstance(next_cursor, str):
            raise ProtocolError("server returned invalid findings cursor")
        return Page(tuple(AuditFinding.parse(item) for item in items), next_cursor)

    async def get_usage(self, *, cursor: str | None = None, limit: int = 50) -> Usage:
        params: dict[str, Any] = {"limit": limit}
        if cursor is not None:
            params["cursor"] = cursor
        return Usage.parse(_object(await self._request("GET", "/v1/usage", params=params)))

    async def wait_for_audit(
        self, audit_id: UUID | str, *, timeout: float = 30.0, interval: float = 0.25
    ) -> Audit:
        if timeout <= 0 or interval <= 0:
            raise ConfigurationError("poll timeout and interval must be positive")
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            value = await self.get_audit(audit_id)
            if value.state in TERMINAL_AUDIT_STATES:
                return value
            if asyncio.get_running_loop().time() >= deadline:
                raise TransportError("audit polling timed out")
            await asyncio.sleep(
                min(interval, max(0.0, deadline - asyncio.get_running_loop().time()))
            )
