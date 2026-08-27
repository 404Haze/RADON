"""MongoDB storage via PyMongo."""

from __future__ import annotations

from radon.report import Report
from radon.score import ScorePoint
from radon.storage.base import Storage


class MongoStorage(Storage):
    """Persists to MongoDB: a ``reports`` collection and a ``history`` collection.

    ``client`` is injectable so tests can pass a mongomock client; otherwise a
    real PyMongo client is built from ``uri``.
    """

    def __init__(self, uri: str = "mongodb://localhost:27017", database: str = "radon", client=None) -> None:
        if client is None:
            from pymongo import MongoClient

            client = MongoClient(uri)
        self._reports = client[database]["reports"]
        self._history = client[database]["history"]

    def save_scan(self, reports: list[Report], score: ScorePoint) -> None:
        self._reports.delete_many({})
        if reports:
            self._reports.insert_many(r.model_dump(mode="json") for r in reports)
        self._history.insert_one(score.model_dump())

    def latest_reports(self) -> list[Report]:
        return [Report.model_validate(d) for d in self._reports.find()]

    def score_history(self) -> list[ScorePoint]:
        return [ScorePoint.model_validate(d) for d in self._history.find().sort("timestamp", 1)]

    def set_status(self, finding_id: str, status: str) -> None:
        self._reports.update_one({"finding.id": finding_id}, {"$set": {"status": status}})
