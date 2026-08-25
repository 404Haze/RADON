"""IAM checks."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from radon.models.finding import Finding, Severity

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
PRIVILEGED_ROLES = {"roles/owner", "roles/editor", "roles/iam.securityAdmin"}
SA_ADMIN_ROLE = "roles/iam.serviceAccountAdmin"
DANGEROUS_PERMISSIONS = {
    "iam.serviceAccounts.actAs",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.setIamPolicy",
    "iam.roles.update",
    "resourcemanager.projects.setIamPolicy",
}


def _parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _sa_email_from_key_name(name: str) -> str:
    """projects/{p}/serviceAccounts/{email}/keys/{id} -> email"""
    if "/serviceAccounts/" not in name:
        return ""
    return name.split("/serviceAccounts/")[1].split("/keys/")[0]


def _sa_project(email: str) -> str:
    """Best-effort project id for a service account email."""
    local, _, domain = email.partition("@")
    if domain.endswith("iam.gserviceaccount.com"):
        return domain[: -len("iam.gserviceaccount.com")].rstrip(".")
    return local  # appspot and other default SAs carry the project in the local part


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


def check_primitive_roles_on_users(policy: dict[str, Any]) -> list[Finding]:
    """Flag human users holding owner/editor instead of a least-privilege role."""
    return [
        Finding(
            id=f"iam:primitive_role_on_user:{member}:{binding.get('role')}",
            rule="primitive_role_on_user",
            severity=Severity.CRITICAL,
            service="iam",
            resource=member,
            detail=f"{member} holds {binding.get('role')} instead of a least-privilege role",
        )
        for binding in policy.get("bindings", [])
        if binding.get("role") in {"roles/owner", "roles/editor"}
        for member in binding.get("members", [])
        if member.startswith("user:")
    ]


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


def check_service_account_admin_role(policy: dict[str, Any]) -> list[Finding]:
    """Flag members holding iam.serviceAccountAdmin, which can impersonate any SA."""
    return [
        Finding(
            id=f"iam:service_account_admin:{member}",
            rule="service_account_admin_role",
            severity=Severity.HIGH,
            service="iam",
            resource=member,
            detail=f"{member} holds {SA_ADMIN_ROLE} and can impersonate any service account",
        )
        for binding in policy.get("bindings", [])
        if binding.get("role") == SA_ADMIN_ROLE
        for member in binding.get("members", [])
    ]


def check_custom_role_broad_permissions(roles: list[dict[str, Any]]) -> list[Finding]:
    """Flag custom roles that grant dangerous permissions."""
    findings: list[Finding] = []
    for role in roles:
        dangerous = sorted(set(role.get("includedPermissions", [])) & DANGEROUS_PERMISSIONS)
        if not dangerous:
            continue
        findings.append(
            Finding(
                id=f"iam:custom_role_broad:{role.get('name', 'unknown')}",
                rule="custom_role_broad_permissions",
                severity=Severity.HIGH,
                service="iam",
                resource=role.get("name", "unknown"),
                detail=f"custom role grants {', '.join(dangerous)}",
            )
        )
    return findings


def check_external_members(policy: dict[str, Any], internal_domain: str = "metalorigami.dev") -> list[Finding]:
    """Flag principals from outside the organization."""
    findings: list[Finding] = []
    for binding in policy.get("bindings", []):
        for member in binding.get("members", []):
            if member in PUBLIC_MEMBERS:
                continue
            _, sep, email = member.partition(":")
            if not sep or not email:
                continue
            domain = email.rsplit("@", 1)[-1]
            if domain.endswith("gserviceaccount.com") or domain == internal_domain:
                continue
            findings.append(
                Finding(
                    id=f"iam:external_member:{member}",
                    rule="external_member",
                    severity=Severity.MEDIUM,
                    service="iam",
                    resource=member,
                    detail=f"{member} is outside the organization ({domain})",
                )
            )
    return findings


def check_cross_project_service_accounts(policy: dict[str, Any], project_id: str) -> list[Finding]:
    """Flag service accounts from other projects."""
    findings: list[Finding] = []
    for binding in policy.get("bindings", []):
        for member in binding.get("members", []):
            if not member.startswith("serviceAccount:"):
                continue
            email = member[len("serviceAccount:") :]
            if _sa_project(email) == project_id:
                continue
            findings.append(
                Finding(
                    id=f"iam:cross_project_sa:{member}",
                    rule="cross_project_service_account",
                    severity=Severity.MEDIUM,
                    service="iam",
                    resource=member,
                    detail=f"{member} belongs to project {_sa_project(email)}, not {project_id}",
                )
            )
    return findings


def check_dormant_service_accounts(
    service_accounts: list[dict[str, Any]],
    now: datetime | None = None,
    max_days: int = 90,
) -> list[Finding]:
    """Flag service accounts that have not authenticated recently."""
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []
    for sa in service_accounts:
        if sa.get("disabled"):
            continue
        email = sa.get("email", "unknown")
        last = sa.get("lastAuthenticatedTime")
        if last and (now - _parse_time(last)).days <= max_days:
            continue
        findings.append(
            Finding(
                id=f"iam:dormant_sa:{email}",
                rule="dormant_service_account",
                severity=Severity.MEDIUM,
                service="iam",
                resource=email,
                detail=f"service account {email} has not authenticated in {max_days} days",
            )
        )
    return findings


def check_disabled_service_accounts_with_roles(
    service_accounts: list[dict[str, Any]], policy: dict[str, Any]
) -> list[Finding]:
    """Flag disabled service accounts that still hold IAM roles."""
    disabled = {sa["email"] for sa in service_accounts if sa.get("disabled")}
    if not disabled:
        return []
    findings: list[Finding] = []
    for binding in policy.get("bindings", []):
        role = binding.get("role")
        for member in binding.get("members", []):
            if not member.startswith("serviceAccount:"):
                continue
            email = member[len("serviceAccount:") :]
            if email in disabled:
                findings.append(
                    Finding(
                        id=f"iam:disabled_sa_role:{email}:{role}",
                        rule="disabled_service_account_with_role",
                        severity=Severity.MEDIUM,
                        service="iam",
                        resource=email,
                        detail=f"disabled service account {email} still holds {role}",
                    )
                )
    return findings


def check_orphaned_keys(
    service_accounts: list[dict[str, Any]], keys: list[dict[str, Any]]
) -> list[Finding]:
    """Flag active keys on disabled service accounts."""
    disabled = {sa["email"] for sa in service_accounts if sa.get("disabled")}
    if not disabled:
        return []
    return [
        Finding(
            id=f"iam:orphaned_key:{key.get('name', 'unknown')}",
            rule="orphaned_key",
            severity=Severity.HIGH,
            service="iam",
            resource=key.get("name", "unknown"),
            detail=f"key belongs to disabled service account {_sa_email_from_key_name(key.get('name', ''))}",
        )
        for key in keys
        if not key.get("disabled") and _sa_email_from_key_name(key.get("name", "")) in disabled
    ]


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


def check_keys_without_expiry(keys: list[dict[str, Any]]) -> list[Finding]:
    """Flag user-managed keys with no expiry date."""
    return [
        Finding(
            id=f"iam:key_no_expiry:{key.get('name', 'unknown')}",
            rule="key_without_expiry",
            severity=Severity.MEDIUM,
            service="iam",
            resource=key.get("name", "unknown"),
            detail="user-managed key has no expiry date",
        )
        for key in keys
        if key.get("keyType") == "USER_MANAGED" and not key.get("validBeforeTime")
    ]


def check_excessive_keys(keys: list[dict[str, Any]], max_keys: int = 3) -> list[Finding]:
    """Flag service accounts with too many active keys."""
    counts: dict[str, int] = {}
    for key in keys:
        if key.get("disabled"):
            continue
        email = _sa_email_from_key_name(key.get("name", ""))
        if email:
            counts[email] = counts.get(email, 0) + 1
    return [
        Finding(
            id=f"iam:excessive_keys:{email}",
            rule="excessive_service_account_keys",
            severity=Severity.MEDIUM,
            service="iam",
            resource=email,
            detail=f"service account {email} has {n} active keys",
        )
        for email, n in counts.items()
        if n >= max_keys
    ]


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
