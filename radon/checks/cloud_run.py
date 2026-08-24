"""Cloud Run checks."""

from __future__ import annotations

from typing import Any

from radon.models.finding import Finding, Severity

SECRET_HINTS = ("password", "passwd", "secret", "token", "apikey", "accesskey", "credential")


def _looks_like_secret(name: str) -> bool:
    normalized = name.lower().replace("_", "").replace("-", "")
    return any(hint in normalized for hint in SECRET_HINTS)


def check_unauthenticated(service: dict[str, Any]) -> list[Finding]:
    """Flag services that allow unauthenticated invocations."""
    name = service.get("name", "unknown")
    if not service.get("allowUnauthenticated"):
        return []
    return [
        Finding(
            id=f"cloudrun:unauthenticated:{name}",
            rule="unauthenticated_service",
            severity=Severity.HIGH,
            service="cloud_run",
            resource=name,
            detail=f"service {name} allows unauthenticated invocations",
        )
    ]


def check_ingress(service: dict[str, Any]) -> list[Finding]:
    """Flag services open to all ingress traffic."""
    name = service.get("name", "unknown")
    if service.get("ingress") != "INGRESS_TRAFFIC_ALL":
        return []
    return [
        Finding(
            id=f"cloudrun:open_ingress:{name}",
            rule="open_ingress",
            severity=Severity.MEDIUM,
            service="cloud_run",
            resource=name,
            detail=f"service {name} accepts traffic from all sources",
        )
    ]


def check_secrets_in_env(service: dict[str, Any]) -> list[Finding]:
    """Flag secrets stored in plaintext environment variables."""
    name = service.get("name", "unknown")
    return [
        Finding(
            id=f"cloudrun:secret_in_env:{name}:{env['name']}",
            rule="secret_in_env",
            severity=Severity.CRITICAL,
            service="cloud_run",
            resource=name,
            detail=f"service {name} stores a secret in environment variable {env['name']}",
        )
        for env in service.get("env", [])
        if _looks_like_secret(env.get("name", ""))
    ]


def check_resource_limits(service: dict[str, Any]) -> list[Finding]:
    """Flag services with no explicit resource limits."""
    name = service.get("name", "unknown")
    if service.get("limits"):
        return []
    return [
        Finding(
            id=f"cloudrun:no_limits:{name}",
            rule="no_resource_limits",
            severity=Severity.LOW,
            service="cloud_run",
            resource=name,
            detail=f"service {name} has no explicit resource limits",
        )
    ]
