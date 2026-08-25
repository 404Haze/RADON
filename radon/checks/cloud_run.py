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


def check_vpc_connector(service: dict[str, Any]) -> list[Finding]:
    """Flag services not attached to a VPC connector."""
    name = service.get("name", "unknown")
    if service.get("vpcConnector"):
        return []
    return [
        Finding(
            id=f"cloudrun:no_vpc_connector:{name}",
            rule="no_vpc_connector",
            severity=Severity.MEDIUM,
            service="cloud_run",
            resource=name,
            detail=f"service {name} is not attached to a VPC connector",
        )
    ]


def check_latest_image_tag(service: dict[str, Any]) -> list[Finding]:
    """Flag services deploying the :latest image tag."""
    name = service.get("name", "unknown")
    if not service.get("image", "").endswith(":latest"):
        return []
    return [
        Finding(
            id=f"cloudrun:latest_image:{name}",
            rule="latest_image_tag",
            severity=Severity.MEDIUM,
            service="cloud_run",
            resource=name,
            detail=f"service {name} deploys the :latest image tag",
        )
    ]


def check_timeout(service: dict[str, Any]) -> list[Finding]:
    """Flag services with no request timeout set."""
    name = service.get("name", "unknown")
    if service.get("timeout"):
        return []
    return [
        Finding(
            id=f"cloudrun:no_timeout:{name}",
            rule="no_timeout",
            severity=Severity.LOW,
            service="cloud_run",
            resource=name,
            detail=f"service {name} has no request timeout set",
        )
    ]


def check_concurrency_limit(service: dict[str, Any]) -> list[Finding]:
    """Flag services with no concurrency cap."""
    name = service.get("name", "unknown")
    if service.get("concurrency"):
        return []
    return [
        Finding(
            id=f"cloudrun:no_concurrency:{name}",
            rule="no_concurrency_limit",
            severity=Severity.LOW,
            service="cloud_run",
            resource=name,
            detail=f"service {name} has no concurrency cap",
        )
    ]


def check_execution_environment(service: dict[str, Any]) -> list[Finding]:
    """Flag services on the deprecated first-generation runtime."""
    name = service.get("name", "unknown")
    if service.get("executionEnvironment", "GEN2") != "GEN1":
        return []
    return [
        Finding(
            id=f"cloudrun:gen1:{name}",
            rule="execution_environment_gen1",
            severity=Severity.LOW,
            service="cloud_run",
            resource=name,
            detail=f"service {name} runs on the deprecated first-generation runtime",
        )
    ]


def check_min_instances(service: dict[str, Any]) -> list[Finding]:
    """Flag services with no minimum instances."""
    name = service.get("name", "unknown")
    if service.get("minInstances"):
        return []
    return [
        Finding(
            id=f"cloudrun:no_min_instances:{name}",
            rule="no_min_instances",
            severity=Severity.LOW,
            service="cloud_run",
            resource=name,
            detail=f"service {name} has no minimum instances",
        )
    ]


def check_binary_authorization(service: dict[str, Any]) -> list[Finding]:
    """Flag services that do not enforce binary authorization."""
    name = service.get("name", "unknown")
    if service.get("binaryAuthorization") == "ENABLED":
        return []
    return [
        Finding(
            id=f"cloudrun:no_binary_authz:{name}",
            rule="binary_authorization_disabled",
            severity=Severity.MEDIUM,
            service="cloud_run",
            resource=name,
            detail=f"service {name} does not enforce binary authorization",
        )
    ]
