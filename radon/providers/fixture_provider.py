"""Fixture provider: reads bundled JSON that mirrors real GCP API responses."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from radon.providers.base import GcpProvider


class FixtureProvider(GcpProvider):
    """Loads the demo project from JSON files under a fixture directory."""

    def __init__(self, fixture_dir: str | Path):
        self.fixture_dir = Path(fixture_dir)

    def _load(self, filename: str) -> Any:
        path = self.fixture_dir / filename
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)

    def get_iam_policy(self) -> dict[str, Any]:
        return self._load("iam_policy.json")

    def list_service_accounts(self) -> list[dict[str, Any]]:
        return self._load("service_accounts.json")

    def list_service_account_keys(self) -> list[dict[str, Any]]:
        return self._load("keys.json")

    def list_buckets(self) -> list[dict[str, Any]]:
        return self._load("buckets.json")

    def list_instances(self) -> list[dict[str, Any]]:
        return self._load("instances.json")

    def list_firewall_rules(self) -> list[dict[str, Any]]:
        return self._load("firewall_rules.json")

    def list_cloud_run_services(self) -> list[dict[str, Any]]:
        return self._load("cloud_run_services.json")
