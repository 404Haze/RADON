"""Compute Engine checks."""

from __future__ import annotations

from radon.checks.compute import (
    check_default_service_account,
    check_disk_encryption,
    check_open_firewall,
    check_public_ip,
    check_serial_port,
)
from radon.models.finding import Severity

INSTANCE = {
    "name": "public-web-server",
    "networkInterfaces": [{"accessConfigs": [{"natIP": "34.120.14.88"}]}],
    "serviceAccounts": [{"email": "demo-project@appspot.gserviceaccount.com"}],
    "disks": [{"boot": True, "diskEncryptionKey": None}],
}

OPEN_RULE = {
    "name": "allow-all-ingress",
    "direction": "INGRESS",
    "sourceRanges": ["0.0.0.0/0"],
    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
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


def test_open_firewall_fires():
    findings = check_open_firewall(OPEN_RULE)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_internal_firewall_does_not_fire():
    assert check_open_firewall(INTERNAL_RULE) == []
