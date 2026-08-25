"""Provider layer: an HTTP client pointed at a GCP-compatible endpoint."""

from __future__ import annotations

from radon.config import Config
from radon.providers.base import GcpProvider
from radon.providers.http import HttpGcpProvider


def get_provider(config: Config) -> GcpProvider:
    """Build the provider that targets the configured endpoint."""
    return HttpGcpProvider(config.endpoint, config.project_id)
