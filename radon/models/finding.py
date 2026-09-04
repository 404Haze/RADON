"""The Finding model: one security misconfiguration."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single misconfiguration discovered by the audit engine.

    Raw scan output. The triage layer pairs it with an
    ``Assessment`` (severity, explanation, remediation).
    """

    id: str = Field(description="Stable identifier, e.g. gcs:public_bucket:name")
    rule: str = Field(description="Check identifier, e.g. public_bucket")
    severity: Severity
    service: str = Field(description="GCP service: iam, gcs, compute, cloud_run")
    resource: str = Field(description="Human-readable resource name")
    detail: str = Field(description="What the check observed")
    cis: str | None = Field(default=None, description="CIS GCP Foundations control or NIST SP 800-53")
    cvss: str | None = Field(default=None, description="CVSS v4.0 score")
    attack: str | None = Field(default=None, description="MITRE ATT&CK technique ID")
