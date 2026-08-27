"""Posture scoring: turn findings into a 0-100 security score."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone

from pydantic import BaseModel

from radon.models.finding import Finding, Severity

_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 1,
}


class ScorePoint(BaseModel):
    """A posture score snapshot for one scan."""

    scan_id: str
    timestamp: datetime
    score: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


def posture_score(findings: Iterable[Finding]) -> int:
    """0-100 posture score; higher is better.

    Sums severity-weighted penalties and damps them so the score degrades
    smoothly instead of bottoming out at 0: ``100 * 100 / (100 + penalty)``.
    A clean project scores 100.
    """
    penalty = sum(_WEIGHTS[f.severity] for f in findings)
    return round(100 * 100 / (100 + penalty))


def build_score(findings: list[Finding], scan_id: str, timestamp: datetime | None = None) -> ScorePoint:
    """Snapshot a scan's severity distribution and score."""
    counts = Counter(f.severity for f in findings)
    return ScorePoint(
        scan_id=scan_id,
        timestamp=timestamp or datetime.now(timezone.utc),
        score=posture_score(findings),
        critical=counts[Severity.CRITICAL],
        high=counts[Severity.HIGH],
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        info=counts[Severity.INFO],
    )
