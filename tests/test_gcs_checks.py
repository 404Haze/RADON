"""Cloud Storage checks."""

from __future__ import annotations

from radon.checks.gcs import (
    check_cmek,
    check_logging,
    check_public_bucket,
    check_uniform_bucket_level_access,
)
from radon.models.finding import Severity

PUBLIC_BUCKET = {
    "name": "customer-data-backup",
    "acl": [{"entity": "allUsers", "role": "READER"}],
    "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}},
    "encryption": {"defaultKmsKeyName": None},
    "logging": {"logBucket": None},
}

PRIVATE_BUCKET = {
    "name": "internal-archives",
    "acl": [{"entity": "project-owners-123", "role": "OWNER"}],
    "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}},
    "encryption": {"defaultKmsKeyName": "projects/demo/locations/us-central1/keyRings/infra/cryptoKeys/archive-cmek"},
    "logging": {"logBucket": "internal-archives-logs"},
}


def test_public_bucket_fires():
    findings = check_public_bucket(PUBLIC_BUCKET)
    assert len(findings) == 1
    assert findings[0].rule == "public_bucket"
    assert findings[0].severity is Severity.HIGH


def test_private_bucket_does_not_fire():
    assert check_public_bucket(PRIVATE_BUCKET) == []


def test_no_ubla_fires():
    findings = check_uniform_bucket_level_access(PUBLIC_BUCKET)
    assert len(findings) == 1
    assert findings[0].rule == "no_uniform_bucket_level_access"


def test_misconfigured_bucket_fires_cmek_and_logging():
    assert len(check_cmek(PUBLIC_BUCKET)) == 1
    assert len(check_logging(PUBLIC_BUCKET)) == 1


def test_configured_bucket_is_clean():
    assert check_uniform_bucket_level_access(PRIVATE_BUCKET) == []
    assert check_cmek(PRIVATE_BUCKET) == []
    assert check_logging(PRIVATE_BUCKET) == []
