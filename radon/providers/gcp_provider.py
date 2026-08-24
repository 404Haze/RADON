"""Live provider backed by the google-cloud-* client libraries.

Not exercised until a billing account exists; see plan.md Phase 6.
"""

from __future__ import annotations

from typing import Any

from radon.providers.base import GcpProvider


class LiveGcpProvider(GcpProvider):
    """Calls the real GCP API and normalizes responses to the fixture shapes."""

    def __init__(self, project_id: str):
        self.project_id = project_id

    def get_iam_policy(self) -> dict[str, Any]:
        raise NotImplementedError("live GCP calls land in Phase 6")

    def list_service_accounts(self) -> list[dict[str, Any]]:
        raise NotImplementedError("live GCP calls land in Phase 6")

    def list_service_account_keys(self) -> list[dict[str, Any]]:
        raise NotImplementedError("live GCP calls land in Phase 6")

    def list_buckets(self) -> list[dict[str, Any]]:
        raise NotImplementedError("live GCP calls land in Phase 6")

    def list_instances(self) -> list[dict[str, Any]]:
        raise NotImplementedError("live GCP calls land in Phase 6")

    def list_firewall_rules(self) -> list[dict[str, Any]]:
        raise NotImplementedError("live GCP calls land in Phase 6")

    def list_cloud_run_services(self) -> list[dict[str, Any]]:
        raise NotImplementedError("live GCP calls land in Phase 6")
