"""The scan-and-triage pipeline."""

from __future__ import annotations

from radon.report import Report, scan_and_triage
from radon.scanner import scan
from radon.triage.mock import MockTriage


def test_scan_and_triage_pairs_every_finding(provider):
    reports = scan_and_triage(provider, MockTriage())
    assert len(reports) == len(scan(provider))
    assert all(r.assessment.explanation for r in reports)
    assert all(r.assessment.remediation for r in reports)


def test_report_round_trips(provider):
    r = scan_and_triage(provider, MockTriage())[0]
    model = Report.model_validate(r.model_dump())
    assert model.finding.id == r.finding.id
    assert model.assessment.severity == r.assessment.severity
    assert model.assessment.explanation == r.assessment.explanation
