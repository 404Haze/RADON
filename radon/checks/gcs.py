"""Cloud Storage checks."""

from __future__ import annotations

from typing import Any

from radon.models.finding import Finding, Severity

PUBLIC_ENTITIES = {"allUsers", "allAuthenticatedUsers"}


def _sa_project(email: str) -> str:
    """Best-effort project id for a service account email."""
    local, _, domain = email.partition("@")
    if domain.endswith("iam.gserviceaccount.com"):
        return domain[: -len("iam.gserviceaccount.com")].rstrip(".")
    return local


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


def check_public_bucket_iam(bucket: dict[str, Any]) -> list[Finding]:
    """Flag buckets whose IAM policy grants allUsers (uniform-access buckets)."""
    name = bucket.get("name", "unknown")
    public = {
        m
        for b in bucket.get("iamPolicy", {}).get("bindings", [])
        for m in b.get("members", [])
        if m in PUBLIC_ENTITIES
    }
    if not public:
        return []
    return [
        Finding(
            id=f"gcs:public_bucket_iam:{name}",
            rule="public_bucket_iam",
            severity=Severity.HIGH,
            service="gcs",
            resource=name,
            detail=f"bucket {name} grants {', '.join(sorted(public))} via IAM policy",
        )
    ]


def check_public_object(obj: dict[str, Any]) -> list[Finding]:
    """Flag objects that are publicly readable."""
    name = obj.get("name", "unknown")
    public = [a["entity"] for a in obj.get("acl", []) if a.get("entity") in PUBLIC_ENTITIES]
    if not public:
        return []
    return [
        Finding(
            id=f"gcs:public_object:{name}",
            rule="public_object",
            severity=Severity.CRITICAL,
            service="gcs",
            resource=name,
            detail=f"object {name} is readable by {', '.join(public)}",
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


def check_versioning(bucket: dict[str, Any]) -> list[Finding]:
    """Flag buckets with object versioning disabled."""
    name = bucket.get("name", "unknown")
    if bucket.get("versioning", {}).get("enabled"):
        return []
    return [
        Finding(
            id=f"gcs:no_versioning:{name}",
            rule="versioning_disabled",
            severity=Severity.MEDIUM,
            service="gcs",
            resource=name,
            detail=f"bucket {name} has object versioning disabled",
        )
    ]


def check_external_project_access(bucket: dict[str, Any], project_id: str) -> list[Finding]:
    """Flag buckets granting access to another project's service account."""
    name = bucket.get("name", "unknown")
    findings: list[Finding] = []
    for binding in bucket.get("iamPolicy", {}).get("bindings", []):
        for member in binding.get("members", []):
            if not member.startswith("serviceAccount:"):
                continue
            email = member[len("serviceAccount:") :]
            if _sa_project(email) == project_id:
                continue
            findings.append(
                Finding(
                    id=f"gcs:external_access:{name}:{member}",
                    rule="external_project_access",
                    severity=Severity.MEDIUM,
                    service="gcs",
                    resource=name,
                    detail=f"bucket {name} grants access to {member} from another project",
                )
            )
    return findings


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


def check_retention_policy(bucket: dict[str, Any]) -> list[Finding]:
    """Flag buckets without a retention policy or bucket lock."""
    name = bucket.get("name", "unknown")
    if bucket.get("retentionPolicy"):
        return []
    return [
        Finding(
            id=f"gcs:no_retention:{name}",
            rule="retention_policy_missing",
            severity=Severity.LOW,
            service="gcs",
            resource=name,
            detail=f"bucket {name} has no retention policy",
        )
    ]


def check_lifecycle(bucket: dict[str, Any]) -> list[Finding]:
    """Flag buckets without lifecycle rules."""
    name = bucket.get("name", "unknown")
    if bucket.get("lifecycle", {}).get("rule"):
        return []
    return [
        Finding(
            id=f"gcs:no_lifecycle:{name}",
            rule="lifecycle_rule_missing",
            severity=Severity.LOW,
            service="gcs",
            resource=name,
            detail=f"bucket {name} has no lifecycle rules",
        )
    ]


def check_single_region(bucket: dict[str, Any]) -> list[Finding]:
    """Flag buckets stored in a single region rather than multi-region."""
    name = bucket.get("name", "unknown")
    if "-" not in bucket.get("location", ""):
        return []
    return [
        Finding(
            id=f"gcs:single_region:{name}",
            rule="single_region",
            severity=Severity.LOW,
            service="gcs",
            resource=name,
            detail=f"bucket {name} is stored in a single region ({bucket.get('location')})",
        )
    ]
