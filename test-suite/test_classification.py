"""Classification enrichment tests."""

from radon.classification import CLASSIFICATION, enrich
from radon.models.finding import Finding, Severity


def test_enrich_stamps_finding():
    f = Finding(id="x", rule="public_bucket", severity=Severity.HIGH, service="gcs", resource="b", detail="d")
    enrich([f])
    assert f.cis == "CIS 5.1"
    assert f.cvss == "7.5"
    assert f.attack == "T1530"


def test_enrich_skips_unknown_rule():
    f = Finding(id="x", rule="not_a_real_rule", severity=Severity.LOW, service="gcs", resource="b", detail="d")
    enrich([f])
    assert f.cis is None
    assert f.cvss is None


def test_every_rule_is_classified():
    from radon.scanner import _SERVICE_RULES

    for service, rules in _SERVICE_RULES.items():
        for rule in rules:
            assert rule in CLASSIFICATION, f"missing classification for {service}:{rule}"
