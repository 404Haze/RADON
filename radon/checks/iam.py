"""IAM checks."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from radon.models.finding import Finding, Severity

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
PRIVILEGED_ROLES = {"roles/owner", "roles/editor", "roles/iam.securityAdmin"}


def check_public_bindings(policy: dict[str, Any]) -> list[Finding]:
    """Flag IAM bindings that grant access to allUsers or allAuthenticatedUsers."""
    findings: list[Finding] = []
    for binding in policy.get("bindings", []):
        role = binding.get("role", "unknown")
        public = [m for m in binding.get("members", []) if m in PUBLIC_MEMBERS]
        if not public:
            continue
        severity = Severity.CRITICAL if role in PRIVILEGED_ROLES else Severity.HIGH
        findings.append(
            Finding(
                id=f"iam:public_binding:{role}",
                rule="public_binding",
                severity=severity,
                service="iam",
                resource=role,
                detail=f"role {role} is granted to {', '.join(public)}",
            )
        )
    return findings


def check_overprivileged_service_accounts(policy: dict[str, Any]) -> list[Finding]:
    """Flag service accounts that hold owner, editor, or securityAdmin roles."""
    findings: list[Finding] = []
    for binding in policy.get("bindings", []):
        role = binding.get("role", "unknown")
        if role not in PRIVILEGED_ROLES:
            continue
        for member in binding.get("members", []):
            if member.startswith("serviceAccount:"):
                findings.append(
                    Finding(
                        id=f"iam:overprivileged_sa:{member}:{role}",
                        rule="overprivileged_service_account",
                        severity=Severity.CRITICAL,
                        service="iam",
                        resource=member,
                        detail=f"service account {member} holds {role}",
                    )
                )
    return findings


def _parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check_unrotated_keys(
    keys: list[dict[str, Any]],
    now: datetime | None = None,
    max_age_days: int = 90,
) -> list[Finding]:
    """Flag user-managed keys older than max_age_days."""
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []
    for key in keys:
        if key.get("keyType") != "USER_MANAGED":
            continue
        age_days = (now - _parse_time(key.get("validAfterTime"))).days
        if age_days > max_age_days:
            findings.append(
                Finding(
                    id=f"iam:unrotated_key:{key.get('name', 'unknown')}",
                    rule="unrotated_key",
                    severity=Severity.HIGH,
                    service="iam",
                    resource=key.get("name", "unknown"),
                    detail=f"user-managed key is {age_days} days old (limit {max_age_days})",
                )
            )
    return findings


def check_user_managed_keys(keys: list[dict[str, Any]]) -> list[Finding]:
    """Flag any user-managed key, which does not auto-rotate."""
    return [
        Finding(
            id=f"iam:user_managed_key:{key.get('name', 'unknown')}",
            rule="user_managed_key",
            severity=Severity.MEDIUM,
            service="iam",
            resource=key.get("name", "unknown"),
            detail="service account uses a user-managed key (static credential, no auto-rotation)",
        )
        for key in keys
        if key.get("keyType") == "USER_MANAGED"
    ]
