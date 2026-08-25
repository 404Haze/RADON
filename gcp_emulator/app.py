"""A local emulator of the GCP API surface R.A.D.O.N. audits.

Serves GCP-style REST endpoints backed by a deliberately-misconfigured demo
project, so the scanner runs end to end without a real Google account.

Run it with:

    python -m gcp_emulator          # serves on http://127.0.0.1:8080

then point R.A.D.O.N. at http://127.0.0.1:8080 (the default).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI

DATA_DIR = Path(__file__).parent / "data"


def _load(name: str) -> Any:
    with (DATA_DIR / name).open(encoding="utf-8") as fh:
        return json.load(fh)


app = FastAPI(title="GCP Emulator", version="0.1.0")


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "gcp-emulator", "project": "demo-project", "status": "ok"}


@app.get("/storage/v1/b")
def list_buckets() -> list[dict[str, Any]]:
    return _load("buckets.json")


@app.get("/storage/v1/objects")
def list_objects() -> list[dict[str, Any]]:
    return _load("objects.json")


@app.get("/iam/v1/projects/{project}/policy")
def get_iam_policy(project: str) -> dict[str, Any]:
    return _load("iam_policy.json")


@app.get("/iam/v1/projects/{project}/serviceAccounts")
def list_service_accounts(project: str) -> list[dict[str, Any]]:
    return _load("service_accounts.json")


@app.get("/iam/v1/projects/{project}/serviceAccounts/{sa}/keys")
def list_service_account_keys(project: str, sa: str) -> list[dict[str, Any]]:
    keys = _load("keys.json")
    return [k for k in keys if sa in k.get("name", "")]


@app.get("/iam/v1/projects/{project}/roles")
def list_roles(project: str) -> list[dict[str, Any]]:
    return _load("custom_roles.json")


@app.get("/compute/v1/projects/{project}/global/firewalls")
def list_firewalls(project: str) -> list[dict[str, Any]]:
    return _load("firewall_rules.json")


@app.get("/compute/v1/projects/{project}/zones/{zone}/instances")
def list_instances(project: str, zone: str) -> list[dict[str, Any]]:
    return _load("instances.json")


@app.get("/run/v1/projects/{project}/services")
def list_services(project: str) -> list[dict[str, Any]]:
    return _load("cloud_run_services.json")
