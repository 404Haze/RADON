"""Deterministic triage: no model, for tests and the offline demo."""

from __future__ import annotations

from radon.models.finding import Finding, Severity
from radon.triage.base import Assessment, Triage

_REMEDIATION = {
    Severity.CRITICAL: "Remove the exposure immediately, then rotate any credentials that may have been affected.",
    Severity.HIGH: "Restrict access to the minimum necessary principals, then audit recent activity for misuse.",
    Severity.MEDIUM: "Tighten the configuration to a least-privilege posture following the fix in the finding detail.",
    Severity.LOW: "Apply the hardening step described in the finding detail during the next maintenance window.",
    Severity.INFO: "No action required; review and document the configuration.",
}


class MockTriage(Triage):
    """Template-based triage that needs no model."""

    def assess(self, finding: Finding) -> Assessment:
        return Assessment(
            severity=finding.severity,
            explanation=(
                f"The {finding.service} resource {finding.resource} triggered the "
                f"{finding.rule} check. {finding.detail}. Left unchecked, this "
                f"expands the attack surface and could allow unauthorized access."
            ),
            remediation=_REMEDIATION[finding.severity],
        )
