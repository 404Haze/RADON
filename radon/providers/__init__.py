"""Provider layer: live GCP client or bundled fixtures.

Imports are lazy so the heavy google-cloud-* client libraries are only
pulled in when live mode is actually requested.
"""

from __future__ import annotations

from radon.config import Config, DataSource
from radon.providers.base import GcpProvider


def get_provider(config: Config) -> GcpProvider:
    """Build the provider that matches the configured data source."""
    if config.data_source is DataSource.FIXTURE:
        from radon.providers.fixture_provider import FixtureProvider

        return FixtureProvider(config.fixture_dir)

    if config.project_id is None:
        raise ValueError("live mode requires RADON_PROJECT_ID")

    from radon.providers.gcp_provider import LiveGcpProvider

    return LiveGcpProvider(config.project_id)
