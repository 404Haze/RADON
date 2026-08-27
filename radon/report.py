"""The risk report: a finding paired with its plain-English assessment."""

from __future__ import annotations

from pydantic import BaseModel

from radon.models.finding import Finding
from radon.providers.base import GcpProvider
from radon.scanner import scan
from radon.triage.base import Assessment, Triage


class Report(BaseModel):
    """One finding plus the triage's plain-English assessment of it."""

    finding: Finding
    assessment: Assessment


def scan_and_triage(provider: GcpProvider, triage: Triage) -> list[Report]:
    """Scan a provider and pair every finding with its assessment."""
    return [Report(finding=f, assessment=triage.assess(f)) for f in scan(provider)]
