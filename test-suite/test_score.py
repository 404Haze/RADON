"""Posture scoring."""

from __future__ import annotations

from radon.models.finding import Finding, Severity
from radon.score import build_score, posture_score


def _finding(severity: Severity) -> Finding:
    return Finding(
        id=f"x:{severity.value}",
        rule="x",
        severity=severity,
        service="gcs",
        resource="r",
        detail="d",
    )


def test_clean_project_scores_full():
    assert posture_score([]) == 100


def test_more_findings_lower_score():
    crit = posture_score([_finding(Severity.CRITICAL)])
    low = posture_score([_finding(Severity.LOW)])
    assert crit < low < 100


def test_build_score_counts_severities():
    findings = [_finding(Severity.CRITICAL), _finding(Severity.HIGH), _finding(Severity.HIGH)]
    point = build_score(findings, scan_id="s1")
    assert point.critical == 1
    assert point.high == 2
    assert point.score == posture_score(findings)
    assert point.scan_id == "s1"
