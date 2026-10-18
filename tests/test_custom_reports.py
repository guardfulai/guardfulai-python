"""Reporting extension parity and strict content-free response decoding."""

import pytest

from guardfulai import ProtocolError, ReportAssessments


def test_assessment_denominator_is_strict():
    data = dict(
        completed=5,
        compliant=1,
        violated=1,
        uncertain=3,
        uncertainty={"numerator": 3, "denominator": 5, "value": 0.6},
        recorded_segments=1,
        not_recorded_segments=2,
        failed_segments=1,
        pending_segments=0,
        unrun_segments=0,
    )
    assert ReportAssessments.parse(data).uncertainty.value == 0.6
    for changed in (
        {"completed": 6},
        {"uncertain": 4},
        {"uncertainty": {"numerator": 3, "denominator": 6, "value": 0.5}},
    ):
        with pytest.raises(ProtocolError):
            ReportAssessments.parse(data | changed)
