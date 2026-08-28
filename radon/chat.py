"""Conversational LLM: the AI chat and risk-narrative backend."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

import httpx


class Chat(ABC):
    """A conversational LLM for the dashboard's chat and risk summary."""

    @abstractmethod
    def respond(self, messages: list[dict[str, str]]) -> str:
        """Reply to a conversation: messages are {"role": ..., "content": ...} dicts."""


class MockChat(Chat):
    """Deterministic chat that needs no model, for tests and the offline demo."""

    def respond(self, messages: list[dict[str, str]]) -> str:
        last = messages[-1]["content"].strip()
        return (
            "I'd walk you through remediating that against your project's IAM and "
            "network config, but no model is loaded here. Point RADON_LLM_ENDPOINT "
            f'at a llama.cpp server to enable live triage. (You asked: "{last[:120]}")'
        )


class LlmChat(Chat):
    """Chats with a llama.cpp server over its OpenAI-compatible API."""

    def __init__(self, endpoint: str = "http://localhost:8080", client: httpx.Client | None = None):
        self._client = client or httpx.Client(base_url=endpoint.rstrip("/"), timeout=120)

    def respond(self, messages: list[dict[str, str]]) -> str:
        resp = self._client.post(
            "/v1/chat/completions",
            json={"model": "local", "messages": messages, "temperature": 0.4},
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


def get_chat(endpoint: str | None = None) -> Chat:
    """Mock chat by default; live llama.cpp when an endpoint is configured."""
    if endpoint is None:
        endpoint = os.environ.get("RADON_LLM_ENDPOINT")
    return LlmChat(endpoint) if endpoint else MockChat()
