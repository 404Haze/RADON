"""The triage interface: turn findings into plain-English assessments."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel

from radon.models.finding import Finding, Severity


class Assessment(BaseModel):
    """The triage's plain-English take on one finding."""

    severity: Severity
    explanation: str
    remediation: str


class Triage(ABC):
    """Produces a plain-English assessment for each finding."""

    @abstractmethod
    def assess(self, finding: Finding) -> Assessment:
        """Return the assessment for one finding."""
