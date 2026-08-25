"""Compute Engine checks."""

from __future__ import annotations

from typing import Any

from radon.models.finding import Finding, Severity

SECRET_HINTS = ("password", "passwd", "secret", "token", "apikey", "accesskey", "credential")


def _is_default_sa(email: str) -> bool:
    return email.endswith("@appspot.gserviceaccount.com") or "-compute@developer.gserviceaccount.com" in email


def _looks_like_secret(name: str) -> bool:
    normalized = name.lower().replace("_", "").replace("-", "")
    return any(hint in normalized for hint in SECRET_HINTS)


def _metadata(instance: dict[str, Any]) -> dict[str, str]:
    return {item.get("key", "").lower(): item.get("value", "") for item in instance.get("metadata", {}).get("items", [])}


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"true", "1"}


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
    if not _truthy(_metadata(instance).get("serial-port-enable")):
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


def check_open_ssh_rdp(rule: dict[str, Any]) -> list[Finding]:
    """Flag SSH (22) or RDP (3389) open to the world."""
    name = rule.get("name", "unknown")
    if rule.get("direction") != "INGRESS" or "0.0.0.0/0" not in rule.get("sourceRanges", []):
        return []
    ports = {p for a in rule.get("allowed", []) for p in a.get("ports", [])}
    sensitive = sorted(p for p in ports if p in {"22", "3389"})
    if not sensitive:
        return []
    return [
        Finding(
            id=f"compute:open_ssh_rdp:{name}",
            rule="open_ssh_rdp",
            severity=Severity.HIGH,
            service="compute",
            resource=name,
            detail=f"firewall rule {name} opens port(s) {', '.join(sensitive)} to the world",
        )
    ]


def check_firewall_all_ports(rule: dict[str, Any]) -> list[Finding]:
    """Flag rules that open every port to the world."""
    name = rule.get("name", "unknown")
    if rule.get("direction") != "INGRESS" or "0.0.0.0/0" not in rule.get("sourceRanges", []):
        return []
    unrestricted = [a.get("IPProtocol", "?") for a in rule.get("allowed", []) if not a.get("ports")]
    if not unrestricted:
        return []
    return [
        Finding(
            id=f"compute:firewall_all_ports:{name}",
            rule="firewall_all_ports",
            severity=Severity.CRITICAL,
            service="compute",
            resource=name,
            detail=f"firewall rule {name} opens all ports ({', '.join(unrestricted)}) to the world",
        )
    ]


def check_default_network(instance: dict[str, Any]) -> list[Finding]:
    """Flag instances on the over-permissive default VPC network."""
    name = instance.get("name", "unknown")
    for nic in instance.get("networkInterfaces", []):
        if nic.get("network", "").endswith("/networks/default"):
            return [
                Finding(
                    id=f"compute:default_network:{name}",
                    rule="default_network",
                    severity=Severity.MEDIUM,
                    service="compute",
                    resource=name,
                    detail=f"instance {name} is on the default VPC network",
                )
            ]
    return []


def check_legacy_network(instance: dict[str, Any], networks: dict[str, str]) -> list[Finding]:
    """Flag instances on pre-VPC legacy networks."""
    name = instance.get("name", "unknown")
    for nic in instance.get("networkInterfaces", []):
        net_name = nic.get("network", "").rsplit("/", 1)[-1]
        if networks.get(net_name) == "LEGACY":
            return [
                Finding(
                    id=f"compute:legacy_network:{name}",
                    rule="legacy_network",
                    severity=Severity.HIGH,
                    service="compute",
                    resource=name,
                    detail=f"instance {name} is on the legacy network {net_name}",
                )
            ]
    return []


def check_project_wide_ssh_keys(instance: dict[str, Any]) -> list[Finding]:
    """Flag instances that accept project-wide SSH keys."""
    name = instance.get("name", "unknown")
    if _truthy(_metadata(instance).get("block-project-ssh-keys")):
        return []
    return [
        Finding(
            id=f"compute:project_wide_ssh:{name}",
            rule="project_wide_ssh_keys",
            severity=Severity.MEDIUM,
            service="compute",
            resource=name,
            detail=f"instance {name} accepts project-wide SSH keys",
        )
    ]


def check_os_login(instance: dict[str, Any]) -> list[Finding]:
    """Flag instances not using OS Login."""
    name = instance.get("name", "unknown")
    if _truthy(_metadata(instance).get("enable-oslogin")):
        return []
    return [
        Finding(
            id=f"compute:os_login_disabled:{name}",
            rule="os_login_disabled",
            severity=Severity.MEDIUM,
            service="compute",
            resource=name,
            detail=f"instance {name} does not use OS Login",
        )
    ]


def check_shielded_vm(instance: dict[str, Any]) -> list[Finding]:
    """Flag instances without Shielded VM (secure boot and vTPM)."""
    name = instance.get("name", "unknown")
    config = instance.get("shieldedInstanceConfig", {})
    if config.get("enableSecureBoot") and config.get("enableVtpm"):
        return []
    return [
        Finding(
            id=f"compute:shielded_vm_disabled:{name}",
            rule="shielded_vm_disabled",
            severity=Severity.MEDIUM,
            service="compute",
            resource=name,
            detail=f"instance {name} does not have Shielded VM enabled",
        )
    ]


def check_ip_forwarding(instance: dict[str, Any]) -> list[Finding]:
    """Flag instances that can forward IP traffic."""
    name = instance.get("name", "unknown")
    if not instance.get("canIpForward"):
        return []
    return [
        Finding(
            id=f"compute:ip_forwarding:{name}",
            rule="ip_forwarding_enabled",
            severity=Severity.MEDIUM,
            service="compute",
            resource=name,
            detail=f"instance {name} has IP forwarding enabled",
        )
    ]


def check_metadata_secrets(instance: dict[str, Any]) -> list[Finding]:
    """Flag secrets stored in instance metadata."""
    name = instance.get("name", "unknown")
    return [
        Finding(
            id=f"compute:metadata_secret:{name}:{key}",
            rule="metadata_contains_secrets",
            severity=Severity.CRITICAL,
            service="compute",
            resource=name,
            detail=f"instance {name} stores a secret in metadata key {key}",
        )
        for key in _metadata(instance)
        if _looks_like_secret(key)
    ]
