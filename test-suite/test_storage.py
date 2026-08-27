"""Storage backends."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from radon.models.finding import Finding, Severity
from radon.report import Report
from radon.score import build_score
from radon.storage import MemoryStorage
from radon.triage.base import Assessment

TS = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)


def _report(rule: str) -> Report:
    finding = Finding(
        id=f"gcs:{rule}:x",
        rule=rule,
        severity=Severity.HIGH,
        service="gcs",
        resource="x",
        detail="d",
    )
    assessment = Assessment(severity=Severity.HIGH, explanation="e", remediation="r")
    return Report(finding=finding, assessment=assessment)


def test_memory_storage_round_trips():
    store = MemoryStorage()
    reports = [_report("public_bucket")]
    store.save_scan(reports, build_score([r.finding for r in reports], "scan-1", TS))
    assert [r.finding.id for r in store.latest_reports()] == ["gcs:public_bucket:x"]
    assert [p.scan_id for p in store.score_history()] == ["scan-1"]


def test_memory_storage_keeps_history():
    store = MemoryStorage()
    store.save_scan([_report("a")], build_score([], "s1", TS))
    store.save_scan([_report("b")], build_score([], "s2", TS))
    assert [p.scan_id for p in store.score_history()] == ["s1", "s2"]
    assert store.latest_reports()[0].finding.rule == "b"


def test_mongo_storage_round_trips():
    mongomock = pytest.importorskip("mongomock")
    from radon.storage.mongo import MongoStorage

    store = MongoStorage(client=mongomock.MongoClient())
    reports = [_report("public_bucket")]
    store.save_scan(reports, build_score([r.finding for r in reports], "scan-1", TS))
    assert [r.finding.rule for r in store.latest_reports()] == ["public_bucket"]
    assert [p.scan_id for p in store.score_history()] == ["scan-1"]
