"""Compute Engine checks."""

from __future__ import annotations

from typing import Any

from radon.models.finding import Finding, Severity


def _is_default_sa(email: str) -> bool:
    return email.endswith("@appspot.gserviceaccount.com") or "-compute@developer.gserviceaccount.com" in email


def check_public_ip(instance: dict[str, Any]) -> list[Finding]:
    """Flag instances exposing a public IP address."""
    name = instance.get("name", "unknown")
    ips = [
        ac["natIP"]
        for nic in instance.get("networkInterfaces", [])
        for ac in nic.get("accessConfigs", [])
        if ac.get("natIP")
    ]
    if not ips:
        return []
    return [
        Finding(
            id=f"compute:public_ip:{name}",
            rule="public_ip",
            severity=Severity.MEDIUM,
            service="compute",
            resource=name,
            detail=f"instance {name} has public IP(s): {', '.join(ips)}",
        )
    ]


def check_default_service_account(instance: dict[str, Any]) -> list[Finding]:
    """Flag instances running with a default service account."""
    name = instance.get("name", "unknown")
    default_sas = [sa["email"] for sa in instance.get("serviceAccounts", []) if _is_default_sa(sa.get("email", ""))]
    if not default_sas:
        return []
    return [
        Finding(
            id=f"compute:default_sa:{name}",
            rule="default_service_account",
            severity=Severity.MEDIUM,
            service="compute",
            resource=name,
            detail=f"instance {name} uses default service account(s): {', '.join(default_sas)}",
        )
    ]


def check_disk_encryption(instance: dict[str, Any]) -> list[Finding]:
    """Flag boot disks without a customer-supplied encryption key."""
    name = instance.get("name", "unknown")
    unencrypted = [d for d in instance.get("disks", []) if d.get("boot") and not d.get("diskEncryptionKey")]
    if not unencrypted:
        return []
    return [
        Finding(
            id=f"compute:no_csek:{name}",
            rule="no_customer_supplied_encryption_key",
            severity=Severity.LOW,
            service="compute",
            resource=name,
            detail=f"instance {name} boot disk uses default Google-managed encryption",
        )
    ]


def check_serial_port(instance: dict[str, Any]) -> list[Finding]:
    """Flag instances with serial port access enabled."""
    name = instance.get("name", "unknown")
    if not instance.get("serialPortEnabled"):
        return []
    return [
        Finding(
            id=f"compute:serial_port:{name}",
            rule="serial_port_enabled",
            severity=Severity.LOW,
            service="compute",
            resource=name,
            detail=f"instance {name} has serial port access enabled",
        )
    ]


def check_open_firewall(rule: dict[str, Any]) -> list[Finding]:
    """Flag firewall rules allowing ingress from 0.0.0.0/0."""
    name = rule.get("name", "unknown")
    if rule.get("direction") != "INGRESS" or "0.0.0.0/0" not in rule.get("sourceRanges", []):
        return []
    protocols = ", ".join(a.get("IPProtocol", "?") for a in rule.get("allowed", []))
    return [
        Finding(
            id=f"compute:open_firewall:{name}",
            rule="open_firewall",
            severity=Severity.HIGH,
            service="compute",
            resource=name,
            detail=f"firewall rule {name} allows {protocols} from 0.0.0.0/0",
        )
    ]
