"""FastAPI app: run scans and serve findings, reports, chat, and the posture score."""

from __future__ import annotations

import json
import os
import queue
import random
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
from radon.models.finding import Finding, Severity
from radon.providers import get_provider
from radon.providers.base import GcpProvider
from radon.report import Report, scan_and_triage
from radon.score import ScorePoint, build_score
from radon.storage import Storage, get_storage
from radon.triage import MockTriage
from radon.triage.base import Assessment, Triage

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


_SAMPLE_RULES = {
    "critical": [("public_bucket", "gcs"), ("public_binding", "iam"), ("secret_in_env", "cloud_run"), ("orphaned_key", "iam")],
    "high": [("unauthenticated_service", "cloud_run"), ("external_member", "iam"), ("default_service_account", "compute"), ("public_bucket_iam", "gcs")],
    "medium": [("open_ingress", "cloud_run"), ("open_firewall", "compute"), ("no_cmek", "gcs"), ("versioning_disabled", "gcs"), ("latest_image_tag", "cloud_run")],
    "low": [("no_timeout", "cloud_run"), ("no_concurrency_limit", "cloud_run"), ("single_region", "gcs"), ("no_resource_limits", "cloud_run")],
}


def _sample_history(rng: random.Random) -> list[ScorePoint]:
    # Each scan rolls 40-67 vulnerabilities with fixed severity odds (critical 10%,
    # high 20%, medium 40%, low 30%); the score is derived from the counts via the
    # same penalty weighting as posture_score (critical 40, high 20, medium 10, low 5).
    n = 17
    now = datetime.now(timezone.utc)
    points = []
    for i in range(n):
        total = rng.randint(40, 67)
        c = h = m = l = 0
        for _ in range(total):
            r = rng.random()
            if r < 0.10:
                c += 1
            elif r < 0.30:
                h += 1
            elif r < 0.70:
                m += 1
            else:
                l += 1
        penalty = 40 * c + 20 * h + 10 * m + 5 * l
        points.append(ScorePoint(
            scan_id=f"sample-{i}",
            timestamp=now - timedelta(days=n - 1 - i),
            score=round(100 * 100 / (100 + penalty)),
            critical=c, high=h, medium=m, low=l, info=0,
        ))
    return points


def _sample_reports(rng: random.Random, counts: dict[str, int]) -> list[Report]:
    """Demo reports matching the latest sample scan's severity counts."""
    reports = []
    n = 0
    for sev in ("critical", "high", "medium", "low"):
        pool = _SAMPLE_RULES[sev]
        for _ in range(counts.get(sev, 0)):
            rule, service = pool[rng.randrange(len(pool))]
            n += 1
            resource = f"demo-{service}-resource-{n}"
            finding = Finding(
                id=f"sample:{sev}:{n}",
                rule=rule,
                severity=Severity(sev),
                service=service,
                resource=resource,
                detail=f"Sample {sev} issue: {rule.replace('_', ' ')} on {resource}.",
            )
            assessment = Assessment(
                severity=Severity(sev),
                explanation="Sample data for the demo.",
                remediation=f"Address {rule.replace('_', ' ')} on {resource}.",
            )
            reports.append(Report(finding=finding, assessment=assessment))
    return reports


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
        rng = random.Random()
        points = _sample_history(rng)
        latest = points[-1]
        counts = {"critical": latest.critical, "high": latest.high, "medium": latest.medium, "low": latest.low}
        reports = _sample_reports(rng, counts)
        store.seed_history(points[:-1])
        store.save_scan(reports, latest)
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
