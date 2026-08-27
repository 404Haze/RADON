"""Storage interface: persist scan results."""

from __future__ import annotations

from abc import ABC, abstractmethod

from radon.report import Report
from radon.score import ScorePoint


class Storage(ABC):
    """Persists reports and the posture score history."""

    @abstractmethod
    def save_scan(self, reports: list[Report], score: ScorePoint) -> None:
        """Store one scan's reports as the latest, and append its score to history."""

    @abstractmethod
    def latest_reports(self) -> list[Report]:
        """Return the most recent scan's reports."""

    @abstractmethod
    def score_history(self) -> list[ScorePoint]:
        """Return the score trend, oldest first."""
