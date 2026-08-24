"""Scan orchestrator: run all checks over a provider and collect findings."""

from __future__ import annotations

from radon.checks.cloud_run import (
    check_ingress,
    check_resource_limits,
    check_secrets_in_env,
    check_unauthenticated,
)
from radon.checks.compute import (
    check_default_service_account,
    check_disk_encryption,
    check_open_firewall,
    check_public_ip,
    check_serial_port,
)
from radon.checks.gcs import (
    check_cmek,
    check_logging,
    check_public_bucket,
    check_uniform_bucket_level_access,
)
from radon.checks.iam import (
    check_overprivileged_service_accounts,
    check_public_bindings,
    check_unrotated_keys,
    check_user_managed_keys,
)
from radon.models.finding import Finding
from radon.providers.base import GcpProvider


def scan(provider: GcpProvider) -> list[Finding]:
    """Run every check against the provider and return deduplicated findings."""
    findings: list[Finding] = []

    policy = provider.get_iam_policy()
    findings += check_public_bindings(policy)
    findings += check_overprivileged_service_accounts(policy)
    keys = provider.list_service_account_keys()
    findings += check_unrotated_keys(keys)
    findings += check_user_managed_keys(keys)

    for bucket in provider.list_buckets():
        findings += check_public_bucket(bucket)
        findings += check_uniform_bucket_level_access(bucket)
        findings += check_cmek(bucket)
        findings += check_logging(bucket)

    for instance in provider.list_instances():
        findings += check_public_ip(instance)
        findings += check_default_service_account(instance)
        findings += check_disk_encryption(instance)
        findings += check_serial_port(instance)

    for rule in provider.list_firewall_rules():
        findings += check_open_firewall(rule)

    for service in provider.list_cloud_run_services():
        findings += check_unauthenticated(service)
        findings += check_ingress(service)
        findings += check_secrets_in_env(service)
        findings += check_resource_limits(service)

    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.id not in seen:
            seen.add(finding.id)
            unique.append(finding)
    return unique
