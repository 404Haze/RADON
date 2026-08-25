"""Prompt template: finding -> structured JSON assessment."""

from __future__ import annotations

from radon.models.finding import Finding

SYSTEM_PROMPT = (
    "You are a cloud security expert. Given one misconfiguration finding, "
    "return a JSON object with exactly three keys: severity (one of critical, "
    "high, medium, low, info), explanation (one plain-English paragraph on "
    "the risk), and remediation (concrete ordered steps to fix it). "
    "Output only the JSON object, no other text."
)


def render(finding: Finding) -> str:
    """Build the user message for a single finding."""
    return (
        f"Service: {finding.service}\n"
        f"Rule: {finding.rule}\n"
        f"Severity: {finding.severity.value}\n"
        f"Resource: {finding.resource}\n"
        f"Detail: {finding.detail}\n"
        "Assess this finding."
    )
