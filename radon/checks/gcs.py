"""Cloud Storage checks."""

from __future__ import annotations

from typing import Any

from radon.models.finding import Finding, Severity

PUBLIC_ENTITIES = {"allUsers", "allAuthenticatedUsers"}


def check_public_bucket(bucket: dict[str, Any]) -> list[Finding]:
    """Flag a bucket whose ACL grants access to allUsers or allAuthenticatedUsers."""
    name = bucket.get("name", "unknown")
    public = [a["entity"] for a in bucket.get("acl", []) if a.get("entity") in PUBLIC_ENTITIES]
    if not public:
        return []
    return [
        Finding(
            id=f"gcs:public_bucket:{name}",
            rule="public_bucket",
            severity=Severity.HIGH,
            service="gcs",
            resource=name,
            detail=f"bucket {name} is readable by {', '.join(public)}",
        )
    ]


def check_uniform_bucket_level_access(bucket: dict[str, Any]) -> list[Finding]:
    """Flag buckets still using per-object ACLs instead of uniform access."""
    name = bucket.get("name", "unknown")
    enabled = bucket.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled")
    if enabled:
        return []
    return [
        Finding(
            id=f"gcs:no_ubla:{name}",
            rule="no_uniform_bucket_level_access",
            severity=Severity.MEDIUM,
            service="gcs",
            resource=name,
            detail=f"bucket {name} does not enforce uniform bucket-level access",
        )
    ]


def check_cmek(bucket: dict[str, Any]) -> list[Finding]:
    """Flag buckets without a customer-managed encryption key."""
    name = bucket.get("name", "unknown")
    if bucket.get("encryption", {}).get("defaultKmsKeyName"):
        return []
    return [
        Finding(
            id=f"gcs:no_cmek:{name}",
            rule="no_cmek",
            severity=Severity.LOW,
            service="gcs",
            resource=name,
            detail=f"bucket {name} has no customer-managed encryption key",
        )
    ]


def check_logging(bucket: dict[str, Any]) -> list[Finding]:
    """Flag buckets with access logging disabled."""
    name = bucket.get("name", "unknown")
    if bucket.get("logging", {}).get("logBucket"):
        return []
    return [
        Finding(
            id=f"gcs:no_logging:{name}",
            rule="no_access_logging",
            severity=Severity.LOW,
            service="gcs",
            resource=name,
            detail=f"bucket {name} has access logging disabled",
        )
    ]
