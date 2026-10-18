import asyncio
import json
from datetime import date, datetime
from pathlib import Path
from types import MappingProxyType
from uuid import uuid4

import httpx
import pytest

from guardfulai import (
    AsyncGuardfulAI,
    ConfigurationError,
    GuardfulAI,
    ProtocolError,
    ReportingContext,
    ReportQuery,
)
from guardfulai.reporting_validation import validate_reporting

DATASET = "00000000-0000-4000-8000-000000000002"


def test_typed_request_bounds_and_omitted_context_compatibility():
    assert "time_basis" not in ReportQuery().to_payload()
    assert "run_id" not in ReportingContext(DATASET, "event").to_payload()
    assert (
        ReportingContext(DATASET, "event", event_date=date(2026, 9, 19)).to_payload()["event_date"]
        == "2026-09-19"
    )
    for query in (
        ReportQuery(page_size=201),
        ReportQuery(group_by="dimension"),
        ReportQuery(start="2026-09-20", end="2026-09-19"),
    ):
        with pytest.raises(ConfigurationError):
            query.to_payload()
    with pytest.raises(ConfigurationError):
        ReportingContext(DATASET, "event", event_at=datetime(2026, 9, 19)).to_payload()
    seen = []
    success = json.loads((Path(__file__).parent / "fixtures/check-success.json").read_text())

    def transport(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=success)

    with GuardfulAI("synthetic-key", transport=httpx.MockTransport(transport)) as client:
        client.check(DATASET, "Synthetic", idempotency_key="event")
        client.check(DATASET, "Synthetic", idempotency_key="event", reporting=None)
        client.check(
            DATASET,
            "Synthetic",
            idempotency_key="context",
            reporting=MappingProxyType(ReportingContext(DATASET, "event").to_payload()),
        )
    assert seen[0] == seen[1] and "reporting" not in seen[0]
    assert seen[2]["reporting"]["record_id"] == "event"


@pytest.mark.parametrize(
    "case",
    json.loads((Path(__file__).parent / "fixtures/reporting-contexts.json").read_text()),
    ids=lambda case: case["name"],
)
def test_complete_reporting_input_corpus(case):
    if case["valid"]:
        validate_reporting(case["value"])
    else:
        with pytest.raises(ValueError):
            validate_reporting(case["value"])


@pytest.mark.parametrize("mode", ["new", "existing", "standalone"])
def test_dataset_run_setup_serializes_destination_and_validates_link(mode):
    from guardfulai import DatasetDestination, DatasetRunReceipt, DatasetRunSetup

    destination = DatasetDestination(mode, dataset_id=DATASET if mode == "existing" else None)
    value = DatasetRunSetup("batch:1", "api", 2, destination=destination)
    encoded = value.to_payload()
    assert encoded["destination"]["mode"] == mode
    run = str(uuid4())
    response = {
        "dataset_id": DATASET,
        "dataset_name": "Batch",
        "run_id": run,
        "report_url": f"/app/datasets/{DATASET}/?run_id={run}",
    }
    assert DatasetRunReceipt.parse(response).dataset_id == __import__("uuid").UUID(DATASET)
    with pytest.raises(ProtocolError):
        DatasetRunReceipt.parse(response | {"report_url": "https://other.example.test"})
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=response)

    with GuardfulAI(
        api_key="test",
        base_url="https://service.example.test",
        transport=httpx.MockTransport(handler),
    ) as client:
        assert client.setup_dataset_run(value).run_id == __import__("uuid").UUID(run)
    assert json.loads(requests[0].content) == encoded

    async def asynchronous_setup():
        async with AsyncGuardfulAI(
            api_key="test",
            base_url="https://service.example.test",
            transport=httpx.MockTransport(handler),
        ) as client:
            return await client.setup_dataset_run(value)

    assert asyncio.run(asynchronous_setup()).run_id == __import__("uuid").UUID(run)
    assert json.loads(requests[1].content) == encoded
