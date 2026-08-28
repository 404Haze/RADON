"""API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from radon.api import create_app
from radon.chat import MockChat
from radon.storage import MemoryStorage
from radon.triage import MockTriage


def _client(provider):
    app = create_app(
        storage=MemoryStorage(),
        provider=provider,
        triage=MockTriage(),
        chat=MockChat(),
    )
    return TestClient(app)


def test_scan_persists_and_returns_score(provider):
    client = _client(provider)
    resp = client.post("/scan")
    assert resp.status_code == 200
    score = resp.json()
    assert 0 <= score["score"] <= 100
    assert score["critical"] + score["high"] + score["medium"] + score["low"] + score["info"] > 0


def test_findings_served_after_scan(provider):
    client = _client(provider)
    client.post("/scan")
    findings = client.get("/findings").json()
    assert findings
    assert all("rule" in f for f in findings)


def test_reports_carry_assessments(provider):
    client = _client(provider)
    client.post("/scan")
    reports = client.get("/reports").json()
    assert reports
    assert all("assessment" in r and "explanation" in r["assessment"] for r in reports)


def test_score_history_accumulates(provider):
    client = _client(provider)
    client.post("/scan")
    client.post("/scan")
    assert len(client.get("/score/history").json()) == 2


def test_score_404_before_first_scan(provider):
    client = _client(provider)
    assert client.get("/score").status_code == 404


def test_resolve_marks_report_resolved(provider):
    client = _client(provider)
    client.post("/scan")
    fid = client.get("/reports").json()[0]["finding"]["id"]
    resp = client.post("/reports/status", params={"finding_id": fid, "status": "resolved"})
    assert resp.status_code == 200
    updated = client.get("/reports").json()
    assert next(r for r in updated if r["finding"]["id"] == fid)["status"] == "resolved"


def test_ignored_persists_across_scans(provider):
    client = _client(provider)
    client.post("/scan")
    fid = client.get("/reports").json()[0]["finding"]["id"]
    client.post("/reports/status", params={"finding_id": fid, "status": "ignored"})
    client.post("/scan")  # a fresh scan regenerates findings as unresolved
    updated = client.get("/reports").json()
    assert next(r for r in updated if r["finding"]["id"] == fid)["status"] == "ignored"


def test_dashboard_serves(provider):
    client = _client(provider)
    assert client.get("/").status_code == 200


def test_health_endpoint(provider):
    client = _client(provider)
    assert client.get("/health").json() == {"status": "ok"}


def test_chat_endpoint(provider):
    client = _client(provider)
    resp = client.post("/chat", json={"messages": [{"role": "user", "content": "how do I fix public buckets?"}]})
    assert resp.status_code == 200
    assert "reply" in resp.json()


def test_summary_endpoint_after_scan(provider):
    client = _client(provider)
    client.post("/scan")
    resp = client.get("/summary")
    assert resp.status_code == 200
    assert resp.json()["summary"]


def test_summary_endpoint_empty(provider):
    client = _client(provider)
    resp = client.get("/summary")
    assert resp.status_code == 200
    assert "No scan" in resp.json()["summary"]


def test_scan_stream(provider):
    client = _client(provider)
    resp = client.get("/scan/stream")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert "done" in resp.text
