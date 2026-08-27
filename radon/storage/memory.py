"""In-memory storage for tests and the offline demo."""

from __future__ import annotations

from radon.report import Report
from radon.score import ScorePoint
from radon.storage.base import Storage


class MemoryStorage(Storage):
    """Keeps the latest reports and the full score history in memory."""

    def __init__(self) -> None:
        self._reports: list[Report] = []
        self._history: list[ScorePoint] = []

    def save_scan(self, reports: list[Report], score: ScorePoint) -> None:
        self._reports = list(reports)
        self._history.append(score)

    def latest_reports(self) -> list[Report]:
        return list(self._reports)

    def score_history(self) -> list[ScorePoint]:
        return list(self._history)

    def set_status(self, finding_id: str, status: str) -> None:
        for report in self._reports:
            if report.finding.id == finding_id:
                report.status = status
                return
