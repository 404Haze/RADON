"""Runtime configuration: which GCP-compatible endpoint to scan."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_RUNTIME_CONFIG = Path(__file__).parent / "runtime_config.json"


def runtime_config() -> dict:
    """Persisted runtime settings (model, provider, endpoints, mongo)."""
    if _RUNTIME_CONFIG.exists():
        try:
            return json.loads(_RUNTIME_CONFIG.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_runtime_config(cfg: dict) -> None:
    _RUNTIME_CONFIG.write_text(json.dumps(cfg, indent=2))


@dataclass(frozen=True)
class Config:
    endpoint: str
    project_id: str

    @classmethod
    def load(cls, env: Mapping[str, str] | None = None) -> "Config":
        env = os.environ if env is None else env
        cfg = runtime_config()
        endpoint = cfg.get("endpoint") or env.get("RADON_ENDPOINT", "http://localhost:8080")
        project_id = cfg.get("project_id") or env.get("RADON_PROJECT_ID", "demo-project")
        return cls(endpoint=endpoint, project_id=project_id)
