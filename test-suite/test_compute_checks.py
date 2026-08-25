"""Compute Engine checks."""

from __future__ import annotations

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
from radon.models.finding import Severity

INSTANCE = {
    "name": "public-web-server",
    "networkInterfaces": [{"accessConfigs": [{"natIP": "34.120.14.88"}]}],
    "serviceAccounts": [{"email": "demo-project@appspot.gserviceaccount.com"}],
    "disks": [{"boot": True, "diskEncryptionKey": None}],
}

MISCONFIGURED_INSTANCE = {
    "name": "public-web-server",
    "networkInterfaces": [
        {"network": "projects/demo-project/global/networks/default", "accessConfigs": [{"natIP": "34.120.14.88"}]}
    ],
    "serviceAccounts": [{"email": "demo-project@appspot.gserviceaccount.com"}],
    "disks": [{"boot": True, "diskEncryptionKey": None}],
    "canIpForward": True,
    "metadata": {
        "items": [
            {"key": "serial-port-enable", "value": "true"},
            {"key": "enable-oslogin", "value": "false"},
            {"key": "block-project-ssh-keys", "value": "false"},
            {"key": "DB_PASSWORD", "value": "secret"},
        ]
    },
}

LEGACY_INSTANCE = {
    "name": "legacy-worker",
    "networkInterfaces": [{"network": "projects/demo-project/global/networks/legacy-vpc"}],
    "serviceAccounts": [{"email": "demo-project@appspot.gserviceaccount.com"}],
    "disks": [{"boot": True, "diskEncryptionKey": None}],
    "canIpForward": False,
    "metadata": {"items": []},
    "shieldedInstanceConfig": {"enableSecureBoot": False, "enableVtpm": False},
}

NETWORKS = {"default": "AUTO", "legacy-vpc": "LEGACY"}

OPEN_RULE = {
    "name": "allow-all-ingress",
    "direction": "INGRESS",
    "sourceRanges": ["0.0.0.0/0"],
    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
}

SSH_RDP_RULE = {
    "name": "allow-ssh-rdp",
    "direction": "INGRESS",
    "sourceRanges": ["0.0.0.0/0"],
    "allowed": [{"IPProtocol": "tcp", "ports": ["22", "3389"]}],
}

ALL_PORTS_RULE = {
    "name": "allow-all-tcp",
    "direction": "INGRESS",
    "sourceRanges": ["0.0.0.0/0"],
    "allowed": [{"IPProtocol": "tcp"}],
}

INTERNAL_RULE = {
    "name": "allow-internal",
    "direction": "INGRESS",
    "sourceRanges": ["10.0.0.0/8"],
    "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
}


def test_public_ip_fires():
    findings = check_public_ip(INSTANCE)
    assert len(findings) == 1
    assert findings[0].rule == "public_ip"


def test_default_service_account_fires():
    findings = check_default_service_account(INSTANCE)
    assert len(findings) == 1
    assert findings[0].rule == "default_service_account"


def test_disk_encryption_fires():
    findings = check_disk_encryption(INSTANCE)
    assert len(findings) == 1
    assert findings[0].rule == "no_customer_supplied_encryption_key"


def test_serial_port_absent_does_not_fire():
    assert check_serial_port(INSTANCE) == []


def test_serial_port_enabled_fires():
    findings = check_serial_port(MISCONFIGURED_INSTANCE)
    assert len(findings) == 1
    assert findings[0].rule == "serial_port_enabled"


def test_open_firewall_fires():
    findings = check_open_firewall(OPEN_RULE)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_open_ssh_rdp_fires():
    findings = check_open_ssh_rdp(SSH_RDP_RULE)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_firewall_all_ports_fires():
    findings = check_firewall_all_ports(ALL_PORTS_RULE)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL


def test_internal_firewall_does_not_fire():
    assert check_open_firewall(INTERNAL_RULE) == []
    assert check_open_ssh_rdp(INTERNAL_RULE) == []
    assert check_firewall_all_ports(INTERNAL_RULE) == []


def test_default_network_fires():
    findings = check_default_network(MISCONFIGURED_INSTANCE)
    assert len(findings) == 1
    assert check_default_network(LEGACY_INSTANCE) == []


def test_legacy_network_fires():
    findings = check_legacy_network(LEGACY_INSTANCE, NETWORKS)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert check_legacy_network(MISCONFIGURED_INSTANCE, NETWORKS) == []


def test_project_wide_ssh_keys_fire():
    findings = check_project_wide_ssh_keys(MISCONFIGURED_INSTANCE)
    assert len(findings) == 1


def test_os_login_disabled_fires():
    findings = check_os_login(MISCONFIGURED_INSTANCE)
    assert len(findings) == 1


def test_shielded_vm_disabled_fires():
    findings = check_shielded_vm(LEGACY_INSTANCE)
    assert len(findings) == 1
    assert len(check_shielded_vm(MISCONFIGURED_INSTANCE)) == 1


def test_ip_forwarding_fires():
    findings = check_ip_forwarding(MISCONFIGURED_INSTANCE)
    assert len(findings) == 1


def test_metadata_secrets_fire():
    findings = check_metadata_secrets(MISCONFIGURED_INSTANCE)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
