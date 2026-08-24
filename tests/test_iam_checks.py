"""IAM checks."""

from __future__ import annotations

from datetime import datetime, timezone

from radon.checks.iam import (
    check_overprivileged_service_accounts,
    check_public_bindings,
    check_unrotated_keys,
    check_user_managed_keys,
)
from radon.models.finding import Severity

POLICY = {
    "bindings": [
        {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
        {"role": "roles/editor", "members": ["serviceAccount:legacy-deploy@demo-project.iam.gserviceaccount.com"]},
        {"role": "roles/owner", "members": ["user:founder@metalorigami.dev"]},
    ]
}

KEYS = [
    {
        "name": "projects/demo-project/serviceAccounts/legacy-deploy@demo-project.iam.gserviceaccount.com/keys/abc123",
        "keyType": "USER_MANAGED",
        "validAfterTime": "2022-01-15T00:00:00Z",
    }
]


def test_public_binding_fires():
    findings = check_public_bindings(POLICY)
    assert any(f.rule == "public_binding" and "storage.objectViewer" in f.resource for f in findings)


def test_overprivileged_service_account_fires():
    findings = check_overprivileged_service_accounts(POLICY)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert "legacy-deploy" in findings[0].resource


def test_unrotated_key_fires():
    now = datetime(2026, 8, 25, tzinfo=timezone.utc)
    findings = check_unrotated_keys(KEYS, now=now)
    assert len(findings) == 1
    assert findings[0].rule == "unrotated_key"


def test_user_managed_key_fires():
    findings = check_user_managed_keys(KEYS)
    assert len(findings) == 1
    assert findings[0].rule == "user_managed_key"
