"""Runtime configuration and the live-vs-fixture mode switch."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum


class DataSource(str, Enum):
    LIVE = "live"
    FIXTURE = "fixture"


@dataclass(frozen=True)
class Config:
    data_source: DataSource
    fixture_dir: str
    project_id: str | None = None

    @classmethod
    def load(cls, env: Mapping[str, str] | None = None) -> "Config":
        """Resolve the data source from the environment.

        Priority:
        1. RADON_DATA_SOURCE, if set, wins outright (lets the demo and tests force a mode).
        2. GOOGLE_APPLICATION_CREDENTIALS present means live mode.
        3. Otherwise fixture mode.
        """
        env = os.environ if env is None else env

        explicit = env.get("RADON_DATA_SOURCE")
        if explicit:
            data_source = DataSource(explicit.lower())
        elif env.get("GOOGLE_APPLICATION_CREDENTIALS"):
            data_source = DataSource.LIVE
        else:
            data_source = DataSource.FIXTURE

        fixture_dir = env.get("RADON_FIXTURE_DIR", "fixtures/demo-project")
        project_id = env.get("RADON_PROJECT_ID")

        return cls(data_source=data_source, fixture_dir=fixture_dir, project_id=project_id)
