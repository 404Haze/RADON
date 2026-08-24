"""The canonical check: a public bucket must fire, a private one must not."""

from __future__ import annotations

from radon.checks.gcs import check_public_bucket
from radon.models.finding import Severity


def test_public_bucket_fires():
    bucket = {"name": "customer-data-backup", "acl": [{"entity": "allUsers", "role": "READER"}]}
    finding = check_public_bucket(bucket)
    assert finding is not None
    assert finding.rule == "public_bucket"
    assert finding.severity is Severity.HIGH
    assert finding.service == "gcs"


def test_private_bucket_does_not_fire():
    bucket = {"name": "internal-archives", "acl": [{"entity": "project-owners-123", "role": "OWNER"}]}
    assert check_public_bucket(bucket) is None
