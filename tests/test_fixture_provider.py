"""The fixture provider must load the demo project the way live data would arrive."""

from __future__ import annotations


def test_loads_buckets(provider):
    buckets = provider.list_buckets()
    assert any(b["name"] == "customer-data-backup" for b in buckets)


def test_loads_iam_policy(provider):
    policy = provider.get_iam_policy()
    assert "bindings" in policy
    roles = [b["role"] for b in policy["bindings"]]
    assert "roles/storage.objectViewer" in roles


def test_loads_firewall_rules(provider):
    rules = provider.list_firewall_rules()
    assert any(r["name"] == "allow-all-ingress" for r in rules)


def test_loads_cloud_run_services(provider):
    services = provider.list_cloud_run_services()
    assert any(s["name"] == "legacy-api" for s in services)
