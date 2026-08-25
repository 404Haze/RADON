"""Runtime configuration: which GCP-compatible endpoint to scan."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    endpoint: str
    project_id: str

    @classmethod
    def load(cls, env: Mapping[str, str] | None = None) -> "Config":
        env = os.environ if env is None else env
        endpoint = env.get("RADON_ENDPOINT", "http://localhost:8080")
        project_id = env.get("RADON_PROJECT_ID", "demo-project")
        return cls(endpoint=endpoint, project_id=project_id)
