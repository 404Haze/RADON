"""Abstract provider: the contract the HTTP client (and any live backend) implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class GcpProvider(ABC):
    """Data source for GCP resources.

    Every method returns plain dicts (or lists of dicts) shaped like the
    resources the real GCP API returns. Checks consume these dicts and do
    not know whether the data came from the live API or the emulator.
    """

    project_id: str

    @abstractmethod
    def get_iam_policy(self) -> dict[str, Any]:
        """The project IAM policy, with a ``bindings`` list."""

    @abstractmethod
    def list_service_accounts(self) -> list[dict[str, Any]]:
        """Service accounts in the project."""

    @abstractmethod
    def list_service_account_keys(self) -> list[dict[str, Any]]:
        """User-managed keys for the project's service accounts."""

    @abstractmethod
    def list_project_roles(self) -> list[dict[str, Any]]:
        """Custom IAM roles defined in the project."""

    @abstractmethod
    def list_buckets(self) -> list[dict[str, Any]]:
        """Cloud Storage buckets."""

    @abstractmethod
    def list_objects(self) -> list[dict[str, Any]]:
        """Cloud Storage objects, each with its ACL."""

    @abstractmethod
    def list_instances(self) -> list[dict[str, Any]]:
        """Compute Engine instances."""

    @abstractmethod
    def list_firewall_rules(self) -> list[dict[str, Any]]:
        """VPC firewall rules."""

    @abstractmethod
    def list_cloud_run_services(self) -> list[dict[str, Any]]:
        """Cloud Run services."""
