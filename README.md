# Guardful AI Python SDK

Typed synchronous and asynchronous clients for the Guardful AI HTTP API.
Python 3.11–3.15.

## Installation

```sh
python -m pip install guardfulai
```

For a source checkout, use `python -m pip install .` or follow
[Contributing](CONTRIBUTING.md). See [API documentation](https://www.guardfulai.com/docs/api/)
and the [Python integration guide](https://www.guardfulai.com/integrations/python/).

## First check

Supply a scoped key from your secret store, the bare HTTPS service origin,
and a selected immutable policy ID/version. Store an event ID before sending;
reuse it with identical inputs after uncertain responses. Estimates are free;
checks can consume credits. The runnable [sync example](examples/check.py) and
[async example](examples/async_check.py) estimate first and require explicit cost
confirmation. They print only content-free results.

```python
from guardfulai import GuardfulAI

with GuardfulAI(api_key, base_url=base_url) as client:
    quote = client.estimate(policy_id, content, version=policy_version)
    # Obtain application approval of quote.credits before continuing.
    result = client.check(
        policy_id,
        content,
        version=policy_version,
        idempotency_key=event_id,
    )
    if result.status == "completed" and result.decision == "allow":
        pass  # Continue the protected operation.
    else:
        pass  # Stop or route to review; do not forward.
```

For asynchronous code, use `async with AsyncGuardfulAI(...)` and await the same
methods. Errors or malformed/incomplete results never authorize forwarding.
Credentials are supplied explicitly. HTTPS is required except on loopback;
redirects and environment proxies are disabled. SDK error messages omit bodies.
Do not log request/response objects or sensitive application inputs.

HTTPX is the only unconditional runtime dependency. Windows also installs `tzdata`;
other platforms need system IANA timezone data (or install `tzdata`) for named zones.
The SDK does not enable telemetry. Service retention is described below.

### Integration recovery and strict results

`get_capabilities()` returns the typed `capabilities-v1` discovery catalog: current
availability, limits, supported directions/languages/countries and exact execution
versions. Its `risk-catalog-v5` grouping and Review defaults do not promote a model or
change a saved policy. Unknown versions and inconsistent availability fail with a
content-free `ProtocolError`. This 29-check response is frozen for compatibility.
`list_checks()` exposes the additive 40-check `functional-v2` catalog and functional
status; its decoder also accepts older servers' lifecycle fields.

`get_check_taxonomy()` returns typed `protection-taxonomy-v1` product metadata:
five ordered categories, their subcategories, stable check IDs and titles,
directions/actions, redaction eligibility, availability, and concise limitations.
It does not expose model, dependency, upstream rule-source, runtime bundle, artifact,
or detector-family identities. Sync and async clients support all three discovery
representations.

`publish_policy(..., runtime_choice="rules_v3")` explicitly chooses deterministic
checks v3 for a new immutable policy version. `rules_v2` remains available for
compatibility. Suspicious and confusable Unicode default to Review and also support Monitor
and Block;
unsupported model/check combinations fail validation. The default `retain` preserves
the original bundle. Compare the proposed change before publishing; keep old versions
pinned for existing workflows and exact retries.

`list_policies(offset=0, limit=20)` reads a bounded page (at most 50, offset at most
1,000). Pin the returned immutable version before estimating or checking.
Completed check responses require supported schema, identity, accounting and
consistent decision/findings/coverage; malformed or wrong-version responses raise
content-free `ProtocolError`. `ScanResult.status` preserves the validated status.
An explicit estimate version must also match the returned quote.

`upload_audit_source(..., idempotency_key="event:upload")` and
`create_audit(..., version=1, idempotency_key="event:create")` optionally recover
lost creation responses. Reuse keys only for exact retries with identical bytes
and configuration. The create call requires an explicit version when keyed.
Changed requests conflict; keys expire after 24 hours and never restart an
operation silently. A deliberate new run needs fresh keys. Omitting the optional
key retains the existing creation behavior. Sync and async clients expose the
same arguments; the API's existing retention and ledger remain authoritative.

### Check availability

`client.list_checks()` returns `available` from current runtime health and an
environment-neutral `status` of `available` or `unavailable`. Connected, functional
checks are selectable even when accuracy is low or no quality evaluation exists.
The SDK still accepts legacy status strings from older servers.

The default HTTP timeout is 300 seconds to allow a cold model to load. Set `timeout`
explicitly for a shorter client deadline. A short client deadline does not cancel a
server-side scan; use the same idempotency key when retrying.

Semantic scans also expose `result.semantic_assessments` (one `policy_id`,
`outcome`, and bounded `reason_code` per evaluated rule) and
`result.semantic_coverage` (`expected` and `completed`). Compliant rules create no
finding. Violations use their configured action; uncertainty requires review.
`Finding.rule_id` and `Finding.reason_code` retain the corresponding references.
Both assessment fields are `None` for older results that did not record them;
absence does not mean compliant. These fields contain no policy text or model
reasoning.

### Custom policies and supplied fields

Both clients accept `custom_rules` and `semantic_policies` on `publish_policy`.
Omit a body argument to retain the previous version's body; supply an empty list
to clear it. Publication creates an immutable version with the API's existing
permissions, limits and validation. Public policy metadata remains body-free.

```python
version = client.publish_policy(
    policy_id,
    expected_version=1,
    direction="output",
    checks=[{"key": "custom.structured_rule", "action": "review"}],
    custom_rules=[
        {
            "rule_id": "refund_approval",
            "kind": "structured",
            "condition": {
                "all_of": [
                    {"field": "amount", "value_type": "number", "operator": "gt", "value": 500}
                ],
                "unless": [
                    {"field": "approved", "value_type": "boolean", "operator": "eq", "value": True}
                ],
            },
        }
    ],
)
inputs = dict(
    version=version.version,
    direction="output",
    context="Customer refund request",
    structured_fields={"amount": 750, "approved": False},
)
quote = client.estimate(policy_id, "Your refund is approved.", **inputs)
# After your application confirms the quoted cost:
result = client.check(policy_id, "Your refund is approved.", idempotency_key=event_id, **inputs)
```

`StructuredFields` is a public type alias for a mapping of field names to JSON
scalar values. Supply numbers and booleans with their actual types; the SDK does
not extract facts from text or coerce strings. The API rejects missing or invalid
required fields during estimate/check preflight. Omitting fields preserves legacy
requests. Context and supplied values bind retry identity: reuse the same key for
an exact retry; changed inputs require a new operation. These transient values do
not appear in stored result metadata. Use `await` with the same arguments for
`AsyncGuardfulAI`.

### Dataset reporting

Both clients support typed dataset setup and reporting without adding a runtime
package dependency. Grant `datasets:read`, `datasets:write` and `reports:read`
explicitly as needed. Creating datasets/runs requires an all-policy setup key;
stored keys are never expanded. Use a separately restricted submission key only
when the selected dataset is accessible under its allowed policies.

```python
from guardfulai import DatasetDestination, DatasetRunSetup, ReportingContext, ReportQuery

run = client.setup_dataset_run(
    DatasetRunSetup(
        external_id="weekly-support:2026-10-13",
        source_kind="api",
        expected_records=2,
        destination=DatasetDestination(mode="new", name="Weekly support"),
    )
)
for record_id, content in [("ticket-42", "Hello"), ("ticket-43", "Contact sam@example.test")]:
    result = client.check(
        policy_id,
        content,
        version=1,
        idempotency_key=f"weekly-support:2026-10-13:{record_id}",
        reporting=ReportingContext(run.dataset_id, record_id, run_id=run.run_id),
    )
print(run.report_url)  # Relative to your configured service origin
summary = client.get_report_summary(run.dataset_id, query=ReportQuery(run_id=run.run_id))
records = client.get_report_records(
    run.dataset_id, query=ReportQuery(run_id=run.run_id, page_size=50)
)
```

`list_datasets` and `list_dataset_runs` return numbered pages with `items`, `total`,
`page` and `page_size` (maximum 200). `get_dataset` selects an existing identity;
`update_dataset` changes name, description, tags or archive state using `DatasetWrite`.
`setup_dataset_run` atomically creates or recovers the same dataset/run and is safe
to retry unchanged. Choose mode `existing` with a dataset ID to collect runs, or
`standalone` for the catch-all. Both clients expose the same helper.
Archive retains incoming work. The older `create_dataset` is not automatically retried: after
an uncertain response, list/select before creating again. Run creation recovers by
its immutable `external_id`; changing its original setup conflicts.

`get_report_summary`, `get_report_breakdowns`, `get_report_series` and
`get_report_records` return typed, validated results with the selected run, cutoff,
policy/catalog versions and limitations. They always use POST query resources so
private dimensions never appear in URLs. Calls are independent snapshots; do not claim a common cutoff across separate
API calls. Multi-section snapshot exports are tracked by DSR-007.
Omitted `time_basis` lets the server disclose its default; explicitly selected
Event time never becomes scan time. Dates are ISO dates, end is exclusive, and
timestamps need an explicit offset. Record pages are bounded; charts never imply
all records fit into one page.

Check context may also be a validated mapping. A snapshot needs `run_id`; an event
dataset can omit it. Keep record/run/context and ordinary idempotency key identical
through retries and credential rotation. Changed context or a different key for
an existing record conflicts. An intentional new snapshot needs a new run and new
retry key. Never put source text, scan context or redacted output in dimensions.
Absent or null reporting context preserves the old request body.

`create_audit` accepts `AuditReportingContext(dataset_id, run_id=...,
record_id_field="source_row_id")` and an explicit `DateMapping("created", "iso")`.
The source identity column must be separate from scanned text. Audit responses
expose optional `dataset_id` and `run_id`, including recovered creations. Legacy
responses without these fields still parse. This does not change retention,
scan execution or billing. See the [API documentation](https://www.guardfulai.com/docs/api/) for attribution rules.

### Custom fields in uploads

`create_audit` accepts optional `structured_fields` column mappings and
`context_field` in both clients. See the [API documentation](https://www.guardfulai.com/docs/api/)
for a complete example, scalar parsing rules, preflight errors and frozen retries.

Custom report filters include `policy_id`, `policy_version`, `rule_id` and
`outcome`, with `group_by="outcome"` for assessment counts. Summary and record
responses expose `ReportAssessments`; missing historical fields remain `None`.
See the [API documentation](https://www.guardfulai.com/docs/api/) for rule
identity, uncertainty denominators and complete export semantics.

## Input retention and visibility

New authenticated checks inherit organization settings: retain input for seven days and include it in individual results by default. Owners can choose no retention, one, seven or thirty days and hide input by default. Explicit request options override those defaults. Storage failure does not change the decision; inspect input retention status separately. This platform may keep its own copies independently of Guardful AI retention.

Use `input_retention_days=0`, `1`, `7`, or `30` with `check()` or
`upload_audit_source()`. Omit it to inherit. `get_scan()`, `get_report_records()`,
`list_audit_results()` and `list_audit_findings()` accept `include_input=True` or
`False`; omission inherits visibility. Historical scan input requires
`scan_inputs:read`; audit input retains its existing audit authorization. Input
is available on each result's `input` field and omitted from Python repr output.
