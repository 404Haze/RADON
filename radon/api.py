"""FastAPI app: run scans and serve findings, reports, and the posture score."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

from radon.config import Config
from radon.models.finding import Finding
from radon.providers import get_provider
from radon.providers.base import GcpProvider
from radon.report import Report, scan_and_triage
from radon.score import ScorePoint, build_score
from radon.storage import Storage, get_storage
from radon.triage import get_triage
from radon.triage.base import Triage

_DASHBOARD = Path(__file__).parent / "dashboard"


def create_app(
    storage: Storage | None = None,
    provider: GcpProvider | None = None,
    triage: Triage | None = None,
) -> FastAPI:
    """Build the app, with dependencies injectable for tests."""
    app = FastAPI(title="R.A.D.O.N.", version="0.1.0")
    store = storage or get_storage()
    tri = triage or get_triage()

    def resolve_provider() -> GcpProvider:
        return provider or get_provider(Config.load())

    @app.post("/scan", response_model=ScorePoint)
    def run_scan() -> ScorePoint:
        reports = scan_and_triage(resolve_provider(), tri)
        score = build_score([r.finding for r in reports], scan_id=uuid4().hex)
        store.save_scan(reports, score)
        return score

    @app.get("/findings", response_model=list[Finding])
    def list_findings() -> list[Finding]:
        return [r.finding for r in store.latest_reports()]

    @app.get("/reports", response_model=list[Report])
    def list_reports() -> list[Report]:
        return store.latest_reports()

    @app.post("/reports/status")
    def update_status(finding_id: str, status: str = "remediated") -> dict:
        store.set_status(finding_id, status)
        return {"finding_id": finding_id, "status": status}

    @app.get("/score", response_model=ScorePoint)
    def latest_score() -> ScorePoint:
        history = store.score_history()
        if not history:
            raise HTTPException(status_code=404, detail="no scans have run")
        return history[-1]

    @app.get("/score/history", response_model=list[ScorePoint])
    def score_history() -> list[ScorePoint]:
        return store.score_history()

    app.mount("/", StaticFiles(directory=_DASHBOARD, html=True), name="dashboard")
    return app


app = create_app()
