"""HTTP provider: talks to a GCP-compatible API endpoint (the emulator or, later, real GCP)."""

from __future__ import annotations

from typing import Any

import httpx

from radon.providers.base import GcpProvider


class HttpGcpProvider(GcpProvider):
    """Fetches GCP resources over HTTP from a configurable base URL.

    Point it at the bundled emulator for offline runs, or at real GCP once
    authentication is wired in (Phase 6). The response shapes are identical
    either way.
    """

    def __init__(self, endpoint: str, project_id: str, client: httpx.Client | None = None):
        self.project_id = project_id
        self._client = client or httpx.Client(base_url=endpoint.rstrip("/"), timeout=30)

    def _get(self, path: str) -> Any:
        resp = self._client.get(path)
        resp.raise_for_status()
        return resp.json()

    def get_iam_policy(self) -> dict[str, Any]:
        return self._get(f"/iam/v1/projects/{self.project_id}/policy")

    def list_service_accounts(self) -> list[dict[str, Any]]:
        return self._get(f"/iam/v1/projects/{self.project_id}/serviceAccounts")

    def list_service_account_keys(self) -> list[dict[str, Any]]:
        keys: list[dict[str, Any]] = []
        for sa in self.list_service_accounts():
            email = sa.get("email")
            if email:
                keys += self._get(f"/iam/v1/projects/{self.project_id}/serviceAccounts/{email}/keys")
        return keys

    def list_project_roles(self) -> list[dict[str, Any]]:
        return self._get(f"/iam/v1/projects/{self.project_id}/roles")

    def list_buckets(self) -> list[dict[str, Any]]:
        return self._get("/storage/v1/b")

    def list_objects(self) -> list[dict[str, Any]]:
        return self._get("/storage/v1/objects")

    def list_instances(self) -> list[dict[str, Any]]:
        return self._get(f"/compute/v1/projects/{self.project_id}/zones/us-central1-a/instances")

    def list_firewall_rules(self) -> list[dict[str, Any]]:
        return self._get(f"/compute/v1/projects/{self.project_id}/global/firewalls")

    def list_cloud_run_services(self) -> list[dict[str, Any]]:
        return self._get(f"/run/v1/projects/{self.project_id}/services")
