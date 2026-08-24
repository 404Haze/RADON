"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from radon.config import Config, DataSource
from radon.providers import get_provider

REPO_ROOT = Path(__file__).parent.parent
DEMO_DIR = REPO_ROOT / "fixtures" / "demo-project"


@pytest.fixture
def config() -> Config:
    return Config(data_source=DataSource.FIXTURE, fixture_dir=str(DEMO_DIR))


@pytest.fixture
def provider(config: Config):
    return get_provider(config)
