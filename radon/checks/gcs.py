"""Cloud Storage checks."""

from __future__ import annotations

from typing import Any

from radon.models.finding import Finding, Severity

PUBLIC_ENTITIES = {"allUsers", "allAuthenticatedUsers"}


def check_public_bucket(bucket: dict[str, Any]) -> Finding | None:
    """Flag a bucket whose ACL grants access to allUsers or allAuthenticatedUsers."""
    name = bucket.get("name", "unknown")
    for acl in bucket.get("acl", []):
        entity = acl.get("entity")
        if entity in PUBLIC_ENTITIES:
            return Finding(
                id=f"gcs:public_bucket:{name}",
                rule="public_bucket",
                severity=Severity.HIGH,
                service="gcs",
                resource=name,
                detail=f"bucket {name} is readable by {entity}",
            )
    return None
