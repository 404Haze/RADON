"""The risk report: a finding paired with its plain-English assessment."""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel

from radon.models.finding import Finding
from radon.providers.base import GcpProvider
from radon.scanner import scan
from radon.triage.base import Assessment, Triage


class Report(BaseModel):
    """One finding, its plain-English assessment, and its remediation status."""

    finding: Finding
    assessment: Assessment
    status: str = "unresolved"  # "unresolved" | "resolved" | "ignored"


def scan_and_triage(
    provider: GcpProvider,
    triage: Triage,
    progress: Callable[[str, str], None] | None = None,
) -> list[Report]:
    """Scan a provider and pair every finding with its assessment."""
    findings = scan(provider, progress=progress)
    if progress:
        progress(f"Triaging {len(findings)} findings with the local model...", "info")
    reports = [Report(finding=f, assessment=triage.assess(f)) for f in findings]
    return reports
