"""Cloud Storage checks."""

from __future__ import annotations

from radon.checks.gcs import (
    check_cmek,
    check_external_project_access,
    check_lifecycle,
    check_logging,
    check_public_bucket,
    check_public_bucket_iam,
    check_public_object,
    check_retention_policy,
    check_single_region,
    check_uniform_bucket_level_access,
    check_versioning,
)
from radon.models.finding import Severity

MISCONFIGURED_BUCKET = {
    "name": "customer-data-backup",
    "location": "US-CENTRAL1",
    "acl": [{"entity": "allUsers", "role": "READER"}],
    "iamPolicy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["serviceAccount:audit-bot@other-project.iam.gserviceaccount.com"]}]},
    "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}},
    "encryption": {"defaultKmsKeyName": None},
    "logging": {"logBucket": None},
    "versioning": {"enabled": False},
    "retentionPolicy": None,
    "lifecycle": {"rule": []},
}

CLEAN_BUCKET = {
    "name": "internal-archives",
    "location": "US",
    "acl": [{"entity": "project-owners-123", "role": "OWNER"}],
    "iamPolicy": {"bindings": [{"role": "roles/storage.objectAdmin", "members": ["serviceAccount:legacy-deploy@demo-project.iam.gserviceaccount.com"]}]},
    "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}},
    "encryption": {"defaultKmsKeyName": "projects/demo/locations/us-central1/keyRings/infra/cryptoKeys/archive-cmek"},
    "logging": {"logBucket": "logs"},
    "versioning": {"enabled": True},
    "retentionPolicy": {"retentionPeriod": "31536000s"},
    "lifecycle": {"rule": [{"action": {"type": "Delete"}}]},
}

IAM_PUBLIC_BUCKET = {
    "name": "marketing-assets",
    "iamPolicy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
}

PUBLIC_OBJECT = {"name": "customer-export-2025.csv", "acl": [{"entity": "allUsers", "role": "READER"}]}
PRIVATE_OBJECT = {"name": "audit-log.jsonl", "acl": [{"entity": "project-owners-123", "role": "OWNER"}]}


def test_public_bucket_fires():
    findings = check_public_bucket(MISCONFIGURED_BUCKET)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_private_bucket_does_not_fire():
    assert check_public_bucket(CLEAN_BUCKET) == []


def test_public_bucket_iam_fires():
    findings = check_public_bucket_iam(IAM_PUBLIC_BUCKET)
    assert len(findings) == 1
    assert findings[0].rule == "public_bucket_iam"


def test_public_object_fires():
    findings = check_public_object(PUBLIC_OBJECT)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_private_object_does_not_fire():
    assert check_public_object(PRIVATE_OBJECT) == []


def test_no_ubla_fires():
    findings = check_uniform_bucket_level_access(MISCONFIGURED_BUCKET)
    assert len(findings) == 1


def test_versioning_disabled_fires():
    assert len(check_versioning(MISCONFIGURED_BUCKET)) == 1
    assert check_versioning(CLEAN_BUCKET) == []


def test_external_project_access_fires():
    findings = check_external_project_access(MISCONFIGURED_BUCKET, "demo-project")
    assert len(findings) == 1
    assert check_external_project_access(CLEAN_BUCKET, "demo-project") == []


def test_misconfigured_bucket_fires_cmek_and_logging():
    assert len(check_cmek(MISCONFIGURED_BUCKET)) == 1
    assert len(check_logging(MISCONFIGURED_BUCKET)) == 1


def test_retention_policy_missing_fires():
    assert len(check_retention_policy(MISCONFIGURED_BUCKET)) == 1
    assert check_retention_policy(CLEAN_BUCKET) == []


def test_lifecycle_rule_missing_fires():
    assert len(check_lifecycle(MISCONFIGURED_BUCKET)) == 1
    assert check_lifecycle(CLEAN_BUCKET) == []


def test_single_region_fires():
    assert len(check_single_region(MISCONFIGURED_BUCKET)) == 1
    assert check_single_region(CLEAN_BUCKET) == []


def test_configured_bucket_is_clean():
    assert check_uniform_bucket_level_access(CLEAN_BUCKET) == []
    assert check_cmek(CLEAN_BUCKET) == []
    assert check_logging(CLEAN_BUCKET) == []
