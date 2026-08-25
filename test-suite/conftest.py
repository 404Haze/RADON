"""Shared pytest fixtures: an in-process GCP emulator and an HTTP provider against it."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from gcp_emulator.app import app
from radon.providers.http import HttpGcpProvider


@pytest.fixture
def provider() -> HttpGcpProvider:
    """An HTTP provider wired to the emulator through an in-process test client."""
    return HttpGcpProvider("http://testserver", "demo-project", client=TestClient(app))
