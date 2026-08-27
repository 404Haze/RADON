"""Triage: turn findings into plain-English assessments."""

from __future__ import annotations

import os

from radon.triage.base import Assessment, Triage
from radon.triage.llm import LlmTriage
from radon.triage.mock import MockTriage

__all__ = ["Assessment", "Triage", "MockTriage", "LlmTriage", "get_triage"]


def get_triage(endpoint: str | None = None) -> Triage:
    """Mock triage by default; live llama.cpp when an endpoint is configured."""
    if endpoint is None:
        endpoint = os.environ.get("RADON_LLM_ENDPOINT")
    return LlmTriage(endpoint) if endpoint else MockTriage()
