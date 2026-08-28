"""In-memory storage for tests and the offline demo."""

from __future__ import annotations

from radon.report import Report
from radon.score import ScorePoint
from radon.storage.base import Storage


class MemoryStorage(Storage):
    def __init__(self):
        self._reports: list[Report] = []
        self._history: list[ScorePoint] = []
        self._ignored: set[str] = set()

    def save_scan(self, reports: list[Report], score: ScorePoint) -> None:
        for report in reports:
            if report.finding.id in self._ignored:
                report.status = "ignored"
        self._reports = list(reports)
        self._history.append(score)

    def latest_reports(self) -> list[Report]:
        return list(self._reports)

    def score_history(self) -> list[ScorePoint]:
        return list(self._history)

    def set_status(self, finding_id: str, status: str) -> None:
        if status == "ignored":
            self._ignored.add(finding_id)
        else:
            self._ignored.discard(finding_id)
        for report in self._reports:
            if report.finding.id == finding_id:
                report.status = status
                return
