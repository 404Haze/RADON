"""End-to-end scan over the demo fixtures."""

from __future__ import annotations

from radon.models.finding import Severity
from radon.scanner import scan

EXPECTED_RULES = {
    "public_bucket",
    "public_binding",
    "open_firewall",
    "unauthenticated_service",
    "secret_in_env",
    "unrotated_key",
}


def test_scan_finds_misconfigurations(provider):
    rules = {f.rule for f in scan(provider)}
    assert EXPECTED_RULES <= rules


def test_scan_dedupes_findings(provider):
    findings = scan(provider)
    ids = [f.id for f in findings]
    assert len(ids) == len(set(ids))


def test_scan_flags_critical_findings(provider):
    findings = scan(provider)
    assert any(f.severity is Severity.CRITICAL for f in findings)
