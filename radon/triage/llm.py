"""Live triage: calls a llama.cpp server over its OpenAI-compatible API."""

from __future__ import annotations

import json

import httpx

from radon.models.finding import Finding, Severity
from radon.triage.base import Assessment, Triage
from radon.triage.prompt import SYSTEM_PROMPT, render


class LlmTriage(Triage):
    """Triages findings by calling a llama.cpp server's chat completions."""

    def __init__(self, endpoint: str = "http://localhost:8080", client: httpx.Client | None = None):
        self._client = client or httpx.Client(base_url=endpoint.rstrip("/"), timeout=120)

    def assess(self, finding: Finding) -> Assessment:
        resp = self._client.post(
            "/v1/chat/completions",
            json={
                "model": "local",
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": render(finding)},
                ],
                "temperature": 0.0,
            },
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return _parse(content, finding)


def _parse(content: str, finding: Finding) -> Assessment:
    text = content.strip()
    # tolerate a ```json ... ``` wrapper the model sometimes adds
    if text.startswith("```"):
        text = text.strip("`").removeprefix("json").strip()
    data = json.loads(text)
    try:
        severity = Severity(data["severity"])
    except (KeyError, ValueError):
        severity = finding.severity
    return Assessment(
        severity=severity,
        explanation=data.get("explanation", ""),
        remediation=data.get("remediation", ""),
    )
