"""Triage tests."""

from __future__ import annotations

from radon.models.finding import Finding, Severity
from radon.triage.llm import _parse
from radon.triage.mock import MockTriage
from radon.triage.prompt import render

FINDING = Finding(
    id="gcs:public_bucket:customer-data-backup",
    rule="public_bucket",
    severity=Severity.HIGH,
    service="gcs",
    resource="customer-data-backup",
    detail="bucket customer-data-backup is readable by allUsers",
)


def test_mock_triage_returns_assessment():
    assessment = MockTriage().assess(FINDING)
    assert assessment.severity is Severity.HIGH
    assert assessment.explanation
    assert assessment.remediation


def test_prompt_includes_finding_details():
    text = render(FINDING)
    assert "public_bucket" in text
    assert "customer-data-backup" in text


def test_parse_plain_json():
    content = '{"severity": "critical", "explanation": "risk", "remediation": "fix"}'
    assessment = _parse(content, FINDING)
    assert assessment.severity is Severity.CRITICAL
    assert assessment.explanation == "risk"
    assert assessment.remediation == "fix"


def test_parse_markdown_fenced_json():
    content = '```json\n{"severity": "low", "explanation": "e", "remediation": "r"}\n```'
    assessment = _parse(content, FINDING)
    assert assessment.severity is Severity.LOW


def test_parse_falls_back_to_finding_severity():
    content = '{"severity": "bogus", "explanation": "e", "remediation": "r"}'
    assessment = _parse(content, FINDING)
    assert assessment.severity is Severity.HIGH
