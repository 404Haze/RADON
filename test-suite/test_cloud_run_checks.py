"""Cloud Run checks."""

from __future__ import annotations

from radon.checks.cloud_run import (
    check_ingress,
    check_resource_limits,
    check_secrets_in_env,
    check_unauthenticated,
)
from radon.models.finding import Severity

SERVICE = {
    "name": "legacy-api",
    "ingress": "INGRESS_TRAFFIC_ALL",
    "allowUnauthenticated": True,
    "env": [
        {"name": "DB_PASSWORD", "value": "hunter2-super-secret"},
        {"name": "API_KEY", "value": "sk-live-1234567890"},
    ],
}


def test_unauthenticated_fires():
    findings = check_unauthenticated(SERVICE)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_open_ingress_fires():
    assert len(check_ingress(SERVICE)) == 1


def test_secrets_in_env_fire():
    findings = check_secrets_in_env(SERVICE)
    assert len(findings) == 2
    assert all(f.severity is Severity.CRITICAL for f in findings)


def test_no_limits_fires():
    assert len(check_resource_limits(SERVICE)) == 1
