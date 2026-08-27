"""Storage: persist scan results."""

from __future__ import annotations

import os

from radon.storage.base import Storage
from radon.storage.memory import MemoryStorage
from radon.storage.mongo import MongoStorage

__all__ = ["Storage", "MemoryStorage", "MongoStorage", "get_storage"]


def get_storage(uri: str | None = None) -> Storage:
    """Memory storage by default; MongoDB when a URI is configured."""
    if uri is None:
        uri = os.environ.get("RADON_MONGO_URI")
    return MongoStorage(uri) if uri else MemoryStorage()
