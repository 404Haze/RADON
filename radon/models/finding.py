"""The Finding model: one security misconfiguration."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single misconfiguration discovered by the audit engine.

    ``remediation`` is populated later by the LLM triage layer; the audit
    engine leaves it empty.
    """

    id: str = Field(description="Stable identifier, e.g. gcs:public_bucket:name")
    rule: str = Field(description="Check identifier, e.g. public_bucket")
    severity: Severity
    service: str = Field(description="GCP service: iam, gcs, compute, cloud_run")
    resource: str = Field(description="Human-readable resource name")
    detail: str = Field(description="What the check observed")
    remediation: Optional[str] = Field(default=None, description="Suggested fix, filled by triage")
