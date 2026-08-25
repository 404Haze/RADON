"""Cloud Run checks."""

from __future__ import annotations

from radon.checks.cloud_run import (
    check_binary_authorization,
    check_concurrency_limit,
    check_execution_environment,
    check_ingress,
    check_latest_image_tag,
    check_min_instances,
    check_resource_limits,
    check_secrets_in_env,
    check_timeout,
    check_unauthenticated,
    check_vpc_connector,
)
from radon.models.finding import Severity

MISCONFIGURED_SERVICE = {
    "name": "legacy-api",
    "ingress": "INGRESS_TRAFFIC_ALL",
    "allowUnauthenticated": True,
    "env": [
        {"name": "DB_PASSWORD", "value": "hunter2-super-secret"},
        {"name": "API_KEY", "value": "sk-…"},
    ],
    "image": "gcr.io/demo-project/legacy-api:latest",
    "vpcConnector": None,
    "timeout": None,
    "concurrency": None,
    "executionEnvironment": "GEN1",
    "minInstances": None,
    "binaryAuthorization": "DISABLED",
}

CLEAN_SERVICE = {
    "name": "payments-api",
    "ingress": "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
    "allowUnauthenticated": False,
    "env": [],
    "image": "gcr.io/demo-project/payments-api:1.4.2",
    "vpcConnector": "projects/demo-project/locations/us-central1/connectors/payments-vpc",
    "timeout": 30,
    "concurrency": 80,
    "executionEnvironment": "GEN2",
    "minInstances": 1,
    "binaryAuthorization": "ENABLED",
    "limits": {"cpu": "1000m", "memory": "512Mi"},
}


def test_unauthenticated_fires():
    findings = check_unauthenticated(MISCONFIGURED_SERVICE)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_open_ingress_fires():
    assert len(check_ingress(MISCONFIGURED_SERVICE)) == 1


def test_secrets_in_env_fire():
    findings = check_secrets_in_env(MISCONFIGURED_SERVICE)
    assert len(findings) == 2
    assert all(f.severity is Severity.CRITICAL for f in findings)


def test_no_limits_fires():
    assert len(check_resource_limits(MISCONFIGURED_SERVICE)) == 1


def test_no_vpc_connector_fires():
    findings = check_vpc_connector(MISCONFIGURED_SERVICE)
    assert len(findings) == 1
    assert check_vpc_connector(CLEAN_SERVICE) == []


def test_latest_image_tag_fires():
    findings = check_latest_image_tag(MISCONFIGURED_SERVICE)
    assert len(findings) == 1
    assert check_latest_image_tag(CLEAN_SERVICE) == []


def test_no_timeout_fires():
    assert len(check_timeout(MISCONFIGURED_SERVICE)) == 1
    assert check_timeout(CLEAN_SERVICE) == []


def test_no_concurrency_limit_fires():
    assert len(check_concurrency_limit(MISCONFIGURED_SERVICE)) == 1
    assert check_concurrency_limit(CLEAN_SERVICE) == []


def test_execution_environment_gen1_fires():
    assert len(check_execution_environment(MISCONFIGURED_SERVICE)) == 1
    assert check_execution_environment(CLEAN_SERVICE) == []


def test_no_min_instances_fires():
    assert len(check_min_instances(MISCONFIGURED_SERVICE)) == 1
    assert check_min_instances(CLEAN_SERVICE) == []


def test_binary_authorization_disabled_fires():
    findings = check_binary_authorization(MISCONFIGURED_SERVICE)
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert check_binary_authorization(CLEAN_SERVICE) == []
