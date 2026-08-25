"""IAM checks."""

from __future__ import annotations

from datetime import datetime, timezone

from radon.checks.iam import (
    check_cross_project_service_accounts,
    check_custom_role_broad_permissions,
    check_disabled_service_accounts_with_roles,
    check_dormant_service_accounts,
    check_excessive_keys,
    check_external_members,
    check_keys_without_expiry,
    check_orphaned_keys,
    check_overprivileged_service_accounts,
    check_primitive_roles_on_users,
    check_public_bindings,
    check_service_account_admin_role,
    check_unrotated_keys,
    check_user_managed_keys,
)
from radon.models.finding import Severity

POLICY = {
    "bindings": [
        {"role": "roles/storage.objectViewer", "members": ["allUsers", "serviceAccount:retired-bot@demo-project.iam.gserviceaccount.com"]},
        {"role": "roles/editor", "members": ["serviceAccount:legacy-deploy@demo-project.iam.gserviceaccount.com"]},
        {"role": "roles/owner", "members": ["user:founder@metalorigami.dev"]},
        {"role": "roles/iam.serviceAccountAdmin", "members": ["user:dev@metalorigami.dev"]},
        {"role": "roles/viewer", "members": ["user:contractor@vendor.example.com"]},
        {"role": "roles/storage.admin", "members": ["serviceAccount:audit-bot@other-project.iam.gserviceaccount.com"]},
    ]
}

SERVICE_ACCOUNTS = [
    {"email": "legacy-deploy@demo-project.iam.gserviceaccount.com", "disabled": False, "lastAuthenticatedTime": "2026-08-20T00:00:00Z"},
    {"email": "demo-project@appspot.gserviceaccount.com", "disabled": False, "lastAuthenticatedTime": "2024-05-01T00:00:00Z"},
    {"email": "retired-bot@demo-project.iam.gserviceaccount.com", "disabled": True},
    {"email": "dormant-bot@demo-project.iam.gserviceaccount.com", "disabled": False, "lastAuthenticatedTime": "2024-03-15T00:00:00Z"},
]

KEYS = [
    {
        "name": "projects/demo-project/serviceAccounts/legacy-deploy@demo-project.iam.gserviceaccount.com/keys/abc123",
        "keyType": "USER_MANAGED",
        "validAfterTime": "2022-01-15T00:00:00Z",
        "validBeforeTime": None,
    },
    {
        "name": "projects/demo-project/serviceAccounts/legacy-deploy@demo-project.iam.gserviceaccount.com/keys/def456",
        "keyType": "USER_MANAGED",
        "validAfterTime": "2026-07-01T00:00:00Z",
        "validBeforeTime": "2027-07-01T00:00:00Z",
    },
    {
        "name": "projects/demo-project/serviceAccounts/legacy-deploy@demo-project.iam.gserviceaccount.com/keys/ghi789",
        "keyType": "USER_MANAGED",
        "validAfterTime": "2026-08-01T00:00:00Z",
        "validBeforeTime": None,
    },
    {
        "name": "projects/demo-project/serviceAccounts/retired-bot@demo-project.iam.gserviceaccount.com/keys/ret1",
        "keyType": "USER_MANAGED",
        "validAfterTime": "2026-06-15T00:00:00Z",
        "validBeforeTime": "2027-06-15T00:00:00Z",
    },
]

ROLES = [
    {"name": "projects/demo-project/roles/DevOpsAdmin", "includedPermissions": ["iam.serviceAccounts.setIamPolicy", "storage.objects.get"]},
    {"name": "projects/demo-project/roles/ReadOnlyAuditor", "includedPermissions": ["storage.objects.get"]},
]

NOW = datetime(2026, 8, 25, tzinfo=timezone.utc)


def test_public_binding_fires():
    findings = check_public_bindings(POLICY)
    assert any(f.rule == "public_binding" and "storage.objectViewer" in f.resource for f in findings)


def test_primitive_role_on_user_fires():
    findings = check_primitive_roles_on_users(POLICY)
    assert len(findings) == 1
    assert "founder@metalorigami.dev" in findings[0].resource
    assert findings[0].severity is Severity.CRITICAL


def test_overprivileged_service_account_fires():
    findings = check_overprivileged_service_accounts(POLICY)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert "legacy-deploy" in findings[0].resource


def test_service_account_admin_role_fires():
    findings = check_service_account_admin_role(POLICY)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_custom_role_broad_permissions_fires():
    findings = check_custom_role_broad_permissions(ROLES)
    assert len(findings) == 1
    assert "DevOpsAdmin" in findings[0].resource


def test_external_member_fires():
    findings = check_external_members(POLICY)
    assert len(findings) == 1
    assert "contractor@vendor.example.com" in findings[0].resource


def test_cross_project_service_account_fires():
    findings = check_cross_project_service_accounts(POLICY, "demo-project")
    assert len(findings) == 1
    assert "audit-bot" in findings[0].resource


def test_dormant_service_account_fires():
    findings = check_dormant_service_accounts(SERVICE_ACCOUNTS, now=NOW)
    dormant = {f.resource for f in findings}
    assert "demo-project@appspot.gserviceaccount.com" in dormant
    assert "dormant-bot@demo-project.iam.gserviceaccount.com" in dormant
    assert "legacy-deploy@demo-project.iam.gserviceaccount.com" not in dormant
    assert "retired-bot@demo-project.iam.gserviceaccount.com" not in dormant


def test_disabled_service_account_with_role_fires():
    findings = check_disabled_service_accounts_with_roles(SERVICE_ACCOUNTS, POLICY)
    assert len(findings) == 1
    assert "retired-bot" in findings[0].resource


def test_orphaned_key_fires():
    findings = check_orphaned_keys(SERVICE_ACCOUNTS, KEYS)
    assert len(findings) == 1
    assert "ret1" in findings[0].resource
    assert findings[0].severity is Severity.HIGH


def test_unrotated_key_fires():
    findings = check_unrotated_keys(KEYS, now=NOW)
    assert len(findings) == 1
    assert findings[0].rule == "unrotated_key"
    assert "abc123" in findings[0].resource


def test_key_without_expiry_fires():
    findings = check_keys_without_expiry(KEYS)
    assert len(findings) == 2


def test_excessive_keys_fires():
    findings = check_excessive_keys(KEYS)
    assert len(findings) == 1
    assert "legacy-deploy" in findings[0].resource


def test_user_managed_keys_fire():
    findings = check_user_managed_keys(KEYS)
    assert len(findings) == 4
