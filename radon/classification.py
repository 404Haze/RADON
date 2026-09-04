"""Framework classification for findings.

Maps each check rule to its CIS GCP Foundations Benchmark control (or a NIST
SP 800-53 fallback where CIS has no control), a CVSS v4.0 score, and a MITRE
ATT&CK technique. Kept as one data-driven table so the mapping is trivial to
audit and edit.
"""

from __future__ import annotations

from radon.models.finding import Finding

CLASSIFICATION: dict[str, dict[str, str]] = {
    # IAM
    "public_binding": {"cis": "NIST AC-3", "cvss": "9.0", "attack": "T1078"},
    "primitive_role_on_user": {"cis": "CIS 1.1", "cvss": "9.1", "attack": "T1078"},
    "overprivileged_service_account": {"cis": "CIS 1.5", "cvss": "9.1", "attack": "T1078"},
    "service_account_admin_role": {"cis": "CIS 1.6", "cvss": "7.8", "attack": "T1098"},
    "custom_role_broad_permissions": {"cis": "CIS 1.8", "cvss": "7.8", "attack": "T1098"},
    "external_member": {"cis": "CIS 1.1", "cvss": "5.3", "attack": "T1078"},
    "cross_project_service_account": {"cis": "NIST AC-4", "cvss": "5.3", "attack": "T1078"},
    "dormant_service_account": {"cis": "NIST AC-2", "cvss": "5.0", "attack": "T1078"},
    "disabled_service_account_with_role": {"cis": "NIST AC-2", "cvss": "5.0", "attack": "T1098"},
    "orphaned_key": {"cis": "CIS 1.4", "cvss": "7.2", "attack": "T1528"},
    "unrotated_key": {"cis": "CIS 1.7", "cvss": "7.2", "attack": "T1528"},
    "key_without_expiry": {"cis": "CIS 1.7", "cvss": "5.3", "attack": "T1528"},
    "excessive_service_account_keys": {"cis": "CIS 1.4", "cvss": "5.0", "attack": "T1528"},
    "user_managed_key": {"cis": "CIS 1.4", "cvss": "5.3", "attack": "T1528"},
    # GCS
    "public_bucket_iam": {"cis": "CIS 5.1", "cvss": "9.1", "attack": "T1530"},
    "public_bucket": {"cis": "CIS 5.1", "cvss": "7.5", "attack": "T1530"},
    "public_object": {"cis": "CIS 5.1", "cvss": "7.5", "attack": "T1530"},
    "no_uniform_bucket_level_access": {"cis": "CIS 5.2", "cvss": "5.3", "attack": "T1530"},
    "versioning_disabled": {"cis": "NIST CP-9", "cvss": "4.3", "attack": "T1485"},
    "external_project_access": {"cis": "NIST AC-4", "cvss": "5.3", "attack": "T1530"},
    "no_cmek": {"cis": "NIST SC-28", "cvss": "2.0", "attack": "T1486"},
    "no_access_logging": {"cis": "CIS 2.1", "cvss": "2.0", "attack": "T1562"},
    "retention_policy_missing": {"cis": "NIST AU-11", "cvss": "2.0", "attack": "T1485"},
    "lifecycle_rule_missing": {"cis": "NIST", "cvss": "0.5", "attack": ""},
    "single_region": {"cis": "NIST CP-7", "cvss": "0.5", "attack": ""},
    # Compute
    "metadata_contains_secrets": {"cis": "NIST SC-28", "cvss": "9.1", "attack": "T1552"},
    "firewall_all_ports": {"cis": "CIS 3.6/3.7", "cvss": "9.8", "attack": "T1190"},
    "open_ssh_rdp": {"cis": "CIS 3.6/3.7", "cvss": "7.5", "attack": "T1021"},
    "open_firewall": {"cis": "CIS 3.6/3.7", "cvss": "7.5", "attack": "T1190"},
    "legacy_network": {"cis": "CIS 3.2", "cvss": "7.0", "attack": "T1599"},
    "public_ip": {"cis": "CIS 4.9", "cvss": "5.3", "attack": "T1190"},
    "default_service_account": {"cis": "CIS 4.1", "cvss": "5.3", "attack": "T1078"},
    "default_network": {"cis": "CIS 3.1", "cvss": "5.0", "attack": "T1599"},
    "project_wide_ssh_keys": {"cis": "CIS 4.3", "cvss": "5.3", "attack": "T1078"},
    "os_login_disabled": {"cis": "CIS 4.4", "cvss": "5.0", "attack": "T1078"},
    "shielded_vm_disabled": {"cis": "CIS 4.8", "cvss": "5.0", "attack": "T1562"},
    "ip_forwarding_enabled": {"cis": "CIS 4.6", "cvss": "5.3", "attack": "T1090"},
    "no_customer_supplied_encryption_key": {"cis": "CIS 4.7", "cvss": "2.0", "attack": "T1486"},
    "serial_port_enabled": {"cis": "CIS 4.5", "cvss": "2.0", "attack": "T1078"},
    # Cloud Run
    "secret_in_env": {"cis": "CIS 1.17", "cvss": "9.1", "attack": "T1552"},
    "unauthenticated_service": {"cis": "NIST AC-3", "cvss": "7.5", "attack": "T1190"},
    "open_ingress": {"cis": "NIST SC-7", "cvss": "5.3", "attack": "T1190"},
    "no_vpc_connector": {"cis": "NIST SC-7", "cvss": "5.3", "attack": "T1599"},
    "binary_authorization_disabled": {"cis": "NIST CM-3", "cvss": "5.0", "attack": "T1195"},
    "latest_image_tag": {"cis": "NIST CM-3", "cvss": "5.0", "attack": "T1195"},
    "no_resource_limits": {"cis": "NIST SC-5", "cvss": "2.0", "attack": "T1499"},
    "no_timeout": {"cis": "NIST SC-5", "cvss": "2.0", "attack": "T1499"},
    "no_concurrency_limit": {"cis": "NIST SC-5", "cvss": "2.0", "attack": "T1499"},
    "execution_environment_gen1": {"cis": "NIST", "cvss": "1.0", "attack": ""},
    "no_min_instances": {"cis": "NIST", "cvss": "0.5", "attack": ""},
}


def enrich(findings: list[Finding]) -> list[Finding]:
    """Stamp each finding with its framework citation, in place."""
    for finding in findings:
        c = CLASSIFICATION.get(finding.rule)
        if c:
            finding.cis = c["cis"]
            finding.cvss = c["cvss"]
            finding.attack = c["attack"]
    return findings
