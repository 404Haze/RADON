"""Scan orchestrator: run all checks over a provider and collect findings."""

from __future__ import annotations

from radon.classification import enrich

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
from radon.checks.compute import (
    check_default_network,
    check_default_service_account,
    check_disk_encryption,
    check_firewall_all_ports,
    check_ip_forwarding,
    check_legacy_network,
    check_metadata_secrets,
    check_open_firewall,
    check_open_ssh_rdp,
    check_os_login,
    check_project_wide_ssh_keys,
    check_public_ip,
    check_serial_port,
    check_shielded_vm,
)
from radon.checks.gcs import (
    check_cmek,
    check_external_project_access,
    check_lifecycle,
    check_logging,
    check_public_bucket,
    check_public_bucket_iam,
    check_public_object,
    check_retention_policy,
    check_single_region,
    check_uniform_bucket_level_access,
    check_versioning,
)
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
from collections import Counter
from collections.abc import Callable

from radon.models.finding import Finding
from radon.providers.base import GcpProvider

_SERVICE_RULES = {
    "iam": [
        "public_binding", "primitive_role_on_user", "overprivileged_service_account",
        "service_account_admin_role", "custom_role_broad_permissions", "external_member",
        "cross_project_service_account", "dormant_service_account", "disabled_service_account_with_role",
        "orphaned_key", "unrotated_key", "key_without_expiry",
        "excessive_service_account_keys", "user_managed_key",
    ],
    "gcs": [
        "public_bucket", "public_bucket_iam", "public_object", "no_uniform_bucket_level_access",
        "versioning_disabled", "external_project_access", "no_cmek", "no_access_logging",
        "retention_policy_missing", "lifecycle_rule_missing", "single_region",
    ],
    "compute": [
        "public_ip", "default_service_account", "no_customer_supplied_encryption_key",
        "serial_port_enabled", "open_firewall", "open_ssh_rdp", "firewall_all_ports",
        "default_network", "legacy_network", "project_wide_ssh_keys", "os_login_disabled",
        "shielded_vm_disabled", "ip_forwarding_enabled", "metadata_contains_secrets",
    ],
    "cloud_run": [
        "unauthenticated_service", "open_ingress", "secret_in_env", "no_resource_limits",
        "no_vpc_connector", "latest_image_tag", "no_timeout", "no_concurrency_limit",
        "execution_environment_gen1", "no_min_instances", "binary_authorization_disabled",
    ],
}


def _emit_rules(emit, rules: list[str], findings: list[Finding], before: int) -> None:
    counts = Counter(f.rule for f in findings[before:])
    for rule in rules:
        n = counts[rule]
        emit(f"{rule}: {n} finding(s)" if n else f"{rule}: clean", "fail" if n else "ok")


def scan(provider: GcpProvider, progress: Callable[[str, str], None] | None = None) -> list[Finding]:
    """Run every check against the provider and return deduplicated findings."""

    def emit(msg: str, level: str = "info") -> None:
        if progress:
            progress(msg, level)

    findings: list[Finding] = []

    emit("Checking IAM...")
    before = len(findings)
    policy = provider.get_iam_policy()
    service_accounts = provider.list_service_accounts()
    keys = provider.list_service_account_keys()
    roles = provider.list_project_roles()

    findings += check_public_bindings(policy)
    findings += check_primitive_roles_on_users(policy)
    findings += check_overprivileged_service_accounts(policy)
    findings += check_service_account_admin_role(policy)
    findings += check_custom_role_broad_permissions(roles)
    findings += check_external_members(policy)
    findings += check_cross_project_service_accounts(policy, provider.project_id)
    findings += check_dormant_service_accounts(service_accounts)
    findings += check_disabled_service_accounts_with_roles(service_accounts, policy)
    findings += check_orphaned_keys(service_accounts, keys)
    findings += check_unrotated_keys(keys)
    findings += check_keys_without_expiry(keys)
    findings += check_excessive_keys(keys)
    findings += check_user_managed_keys(keys)

    _emit_rules(emit, _SERVICE_RULES["iam"], findings, before)
    emit("Checking GCS buckets...")
    before = len(findings)
    for bucket in provider.list_buckets():
        findings += check_public_bucket(bucket)
        findings += check_public_bucket_iam(bucket)
        findings += check_uniform_bucket_level_access(bucket)
        findings += check_versioning(bucket)
        findings += check_external_project_access(bucket, provider.project_id)
        findings += check_cmek(bucket)
        findings += check_logging(bucket)
        findings += check_retention_policy(bucket)
        findings += check_lifecycle(bucket)
        findings += check_single_region(bucket)

    for obj in provider.list_objects():
        findings += check_public_object(obj)

    _emit_rules(emit, _SERVICE_RULES["gcs"], findings, before)
    emit("Checking Compute instances...")
    before = len(findings)
    networks = {n["name"]: n.get("subnetMode", "") for n in provider.list_networks()}

    for instance in provider.list_instances():
        findings += check_public_ip(instance)
        findings += check_default_service_account(instance)
        findings += check_disk_encryption(instance)
        findings += check_serial_port(instance)
        findings += check_project_wide_ssh_keys(instance)
        findings += check_os_login(instance)
        findings += check_shielded_vm(instance)
        findings += check_ip_forwarding(instance)
        findings += check_metadata_secrets(instance)
        findings += check_default_network(instance)
        findings += check_legacy_network(instance, networks)

    for rule in provider.list_firewall_rules():
        findings += check_open_firewall(rule)
        findings += check_open_ssh_rdp(rule)
        findings += check_firewall_all_ports(rule)

    _emit_rules(emit, _SERVICE_RULES["compute"], findings, before)
    emit("Checking Cloud Run services...")
    before = len(findings)
    for service in provider.list_cloud_run_services():
        findings += check_unauthenticated(service)
        findings += check_ingress(service)
        findings += check_secrets_in_env(service)
        findings += check_resource_limits(service)
        findings += check_vpc_connector(service)
        findings += check_latest_image_tag(service)
        findings += check_timeout(service)
        findings += check_concurrency_limit(service)
        findings += check_execution_environment(service)
        findings += check_min_instances(service)
        findings += check_binary_authorization(service)

    _emit_rules(emit, _SERVICE_RULES["cloud_run"], findings, before)
    emit(f"Collected {len(findings)} findings.")
    return enrich(_dedupe(findings))


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.id not in seen:
            seen.add(finding.id)
            unique.append(finding)
    return unique
