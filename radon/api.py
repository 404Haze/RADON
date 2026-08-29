"""FastAPI app: run scans and serve findings, reports, chat, and the posture score."""

from __future__ import annotations

import json
import os
import queue
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
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
    style: str = "normal"
    user_name: str = "admin"
    context: str = ""
    system_prompt: str = ""


_CHAT_BASE = "You are R.A.D.O.N.'s remediation assistant for a GCP cloud security posture scanner. Help the user understand and fix security findings."

_CHAT_STYLES = {
    "concise": "Keep responses short and to the point.",
    "normal": "",
    "socratic": "Prefer guiding questions over direct answers.",
    "informal": "Keep a casual, conversational tone.",
}

_DEFAULT_CONTEXT = "This project runs on Google Cloud Platform (GCP)."

_DEFAULT_SYSTEM_PROMPT = "Always provide actionable remediation steps. Ask the user for more information when needed."


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
    top = sorted(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.value))[:3]
    issues = ", ".join(f.rule.replace("_", " ") for f in top)
    return (
        f"{len(findings)} issues — {counts['critical']} critical, {counts['high']} high, "
        f"{counts['medium']} medium, {counts['low']} low. The most urgent are {issues}."
    )


def _sample_history() -> list[ScorePoint]:
    # Spiky mountain: jittery up-and-down climb, small drop at the very end.
    scores = [36, 54, 40, 59, 44, 63, 49, 70, 53, 75, 58, 81, 64, 87, 71, 90, 85]
    sev = [
        (10, 15, 35, 21), (5, 11, 27, 15), (9, 14, 32, 19), (4, 9, 24, 14),
        (8, 13, 29, 17), (3, 8, 22, 13), (7, 12, 26, 16), (2, 6, 18, 10),
        (6, 10, 23, 14), (1, 4, 15, 9), (5, 8, 20, 12), (1, 3, 12, 7),
        (4, 6, 17, 10), (0, 2, 9, 6), (3, 5, 14, 8), (0, 1, 7, 5),
        (0, 1, 8, 5),
    ]
    now = datetime.now(timezone.utc)
    points = []
    for i, (score, (c, h, m, l)) in enumerate(zip(scores, sev)):
        points.append(ScorePoint(
            scan_id=f"sample-{i}",
            timestamp=now - timedelta(days=len(scores) - 1 - i),
            score=score, critical=c, high=h, medium=m, low=l, info=0,
        ))
    return points


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
        context = req.context or _DEFAULT_CONTEXT
        system_prompt = req.system_prompt or _DEFAULT_SYSTEM_PROMPT
        name = f"Refer to the user as '{req.user_name}'." if req.user_name else ""
        parts = [_CHAT_BASE, context, system_prompt, _CHAT_STYLES.get(req.style, ""), name]
        system = " ".join(x for x in parts if x)
        messages = [{"role": "system", "content": system}, *req.messages]
        return {"reply": ch.respond(messages)}

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

    @app.post("/seed")
    def seed() -> dict:
        points = _sample_history()
        store.seed_history(points)
        return {"seeded": len(points)}

    @app.post("/reset")
    def reset() -> dict:
        store.reset()
        return {"status": "reset"}

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
