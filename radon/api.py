"""FastAPI app: run scans and serve findings, reports, chat, and the posture score."""

from __future__ import annotations

import json
import os
import queue
import threading
from collections import Counter
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from radon.chat import Chat, LlmChat, MockChat, get_chat
from radon.config import Config
from radon.models.finding import Finding
from radon.providers import get_provider
from radon.providers.base import GcpProvider
from radon.report import Report, scan_and_triage
from radon.score import ScorePoint, build_score
from radon.storage import Storage, get_storage
from radon.triage import MockTriage
from radon.triage.base import Triage

_DASHBOARD = Path(__file__).parent / "dashboard"
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class ChatRequest(BaseModel):
    messages: list[dict[str, str]]


def _narrative_prompt(findings: list[Finding]) -> str:
    counts = Counter(f.severity.value for f in findings)
    ordered = sorted(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.value))
    sample = "\n".join(
        f"- [{f.severity.value}] {f.service}/{f.rule}: {f.detail}" for f in ordered[:15]
    )
    totals = ", ".join(f"{counts[s]} {s}" for s in _SEVERITY_ORDER if counts[s])
    return (
        "You are a cloud security analyst. Summarize this GCP project's posture in "
        "2-4 plain-English sentences a non-expert can understand, then name the top "
        "two things to fix first.\n\n"
        f"Findings: {totals}\n{sample}"
    )


def _deterministic_summary(findings: list[Finding]) -> str:
    counts = Counter(f.severity.value for f in findings)
    services = Counter(f.service for f in findings).most_common(2)
    services_txt = " and ".join(s for s, _ in services) if services else "the project"
    return (
        f"This project surfaced {len(findings)} issues — {counts['critical']} critical, "
        f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low. "
        f"Most concentrate in {services_txt}, driven by public exposure and "
        f"over-privileged principals. Resolve the critical and high findings first, "
        f"then tighten the rest toward a least-privilege baseline."
    )


def create_app(
    storage: Storage | None = None,
    provider: GcpProvider | None = None,
    triage: Triage | None = None,
    chat: Chat | None = None,
) -> FastAPI:
    """Build the app, with dependencies injectable for tests."""
    app = FastAPI(title="R.A.D.O.N.", version="0.1.0")
    store = storage or get_storage()
    tri = triage or MockTriage()  # finding descriptions stay fast; the live LLM is reserved for chat/narrative
    ch = chat or get_chat()

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
    def update_status(finding_id: str, status: str = "resolved") -> dict:
        store.set_status(finding_id, status)
        return {"finding_id": finding_id, "status": status}

    @app.post("/chat")
    def chat_endpoint(req: ChatRequest) -> dict:
        return {"reply": ch.respond(req.messages)}

    @app.get("/summary")
    def summary() -> dict:
        findings = [r.finding for r in store.latest_reports()]
        if not findings:
            return {"summary": "No scan has been run yet. Run one to see your risk summary."}
        if isinstance(ch, MockChat):
            return {"summary": _deterministic_summary(findings)}
        try:
            return {"summary": ch.respond([{"role": "user", "content": _narrative_prompt(findings)}])}
        except Exception:
            return {"summary": _deterministic_summary(findings)}

    @app.get("/score", response_model=ScorePoint)
    def latest_score() -> ScorePoint:
        history = store.score_history()
        if not history:
            raise HTTPException(status_code=404, detail="no scans have run")
        return history[-1]

    @app.get("/score/history", response_model=list[ScorePoint])
    def score_history() -> list[ScorePoint]:
        return store.score_history()

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/config")
    def config() -> dict:
        return {
            "project_id": os.environ.get("RADON_PROJECT_ID", "demo-project"),
            "endpoint": os.environ.get("RADON_ENDPOINT", "http://localhost:8080"),
            "llm_endpoint": os.environ.get("RADON_LLM_ENDPOINT"),
            "llm_live": isinstance(ch, LlmChat),
            "version": "0.1.0",
        }

    @app.get("/scan/stream")
    def scan_stream() -> StreamingResponse:
        q = queue.Queue()

        def _run() -> None:
            try:
                reports = scan_and_triage(
                    resolve_provider(), tri,
                    progress=lambda msg, level: q.put(("line", {"line": msg, "level": level})),
                )
                score = build_score([r.finding for r in reports], scan_id=uuid4().hex)
                store.save_scan(reports, score)
                q.put(("done", {"done": True, "score": score.model_dump(mode="json")}))
            except Exception as exc:  # pragma: no cover - defensive
                q.put(("error", {"error": str(exc)}))

        threading.Thread(target=_run, daemon=True).start()

        async def gen():
            while True:
                try:
                    kind, data = q.get(timeout=0.5)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(data)}\n\n"
                if kind != "line":
                    return

        return StreamingResponse(gen(), media_type="text/event-stream")

    app.mount("/", StaticFiles(directory=_DASHBOARD, html=True), name="dashboard")
    return app


app = create_app()
