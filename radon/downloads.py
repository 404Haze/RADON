"""Model catalogue + background download jobs for the Settings panel."""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from uuid import uuid4

import httpx

_ROOT = Path(__file__).parent.parent
_MODELS_DIR = _ROOT / "models"
_TRASH_DIR = _MODELS_DIR / ".trash"

# name -> display label; file -> exact GGUF filename in models/; repo -> HF source.
# The 1.2B default is gated on HF but ships on disk; the other two are public
# (TheBloke / microsoft) so the download path actually streams for the demo.
COMPATIBLE_MODELS = [
    {"name": "LFM-2.5-1.2B", "repo": "unsloth/LFM2.5-1.2B-Instruct-UD",
     "file": "LFM2.5-1.2B-Instruct-UD-Q5_K_XL.gguf", "quant": "Q5_K_XL", "size": "0.8 GB"},
    {"name": "Mistral-7B-Instruct-v0.2", "repo": "TheBloke/Mistral-7B-Instruct-v0.2-GGUF",
     "file": "mistral-7b-instruct-v0.2.Q4_K_M.gguf", "quant": "Q4_K_M", "size": "4.4 GB"},
    {"name": "Phi-3-mini-4k-instruct", "repo": "microsoft/Phi-3-mini-4k-instruct-gguf",
     "file": "Phi-3-mini-4k-instruct-q4.gguf", "quant": "Q4", "size": "2.2 GB"},
]


def _by_name(name: str) -> dict | None:
    for c in COMPATIBLE_MODELS:
        if c["name"] == name:
            return c
    return None


def compatible_payload() -> list[dict]:
    out = []
    for c in COMPATIBLE_MODELS:
        downloaded = (_MODELS_DIR / c["file"]).exists()
        out.append({**c, "downloaded": downloaded,
                    "url": f"https://huggingface.co/{c['repo']}/resolve/main/{c['file']}"})
    return out


class DownloadJob:
    def __init__(self, name: str, url: str, filename: str):
        self.id = uuid4().hex[:12]
        self.name = name
        self.url = url
        self.filename = filename
        self.total = 0
        self.done = 0
        self.status = "downloading"  # downloading | done | cancelled | error
        self.error = ""
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def to_dict(self) -> dict:
        total = self.total
        return {
            "id": self.id,
            "name": self.name,
            "filename": self.filename,
            "total": total,
            "done": self.done,
            "status": self.status,
            "error": self.error,
            "percent": round(100 * self.done / total, 1) if total else 0,
        }


class DownloadManager:
    def __init__(self) -> None:
        self._jobs: dict[str, DownloadJob] = {}
        self._lock = threading.Lock()

    def get(self, job_id: str) -> DownloadJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def start(self, name: str) -> DownloadJob | None:
        spec = _by_name(name)
        if spec is None:
            return None
        url = f"https://huggingface.co/{spec['repo']}/resolve/main/{spec['file']}"
        job = DownloadJob(name, url, spec["file"])
        with self._lock:
            self._jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def _run(self, job: DownloadJob) -> None:
        tmp = _MODELS_DIR / (job.filename + ".part")
        digest = hashlib.sha256()
        try:
            with httpx.stream("GET", job.url, timeout=30.0, follow_redirects=True) as resp:
                resp.raise_for_status()
                job.total = int(resp.headers.get("content-length") or 0)
                with open(tmp, "wb") as fh:
                    for chunk in resp.iter_bytes(chunk_size=65536):
                        if job._cancel.is_set():
                            job.status = "cancelled"
                            break
                        fh.write(chunk)
                        digest.update(chunk)
                        job.done += len(chunk)
            if job.status == "cancelled":
                tmp.unlink(missing_ok=True)
                return
            final = _MODELS_DIR / job.filename
            tmp.replace(final)
            job.status = "done"
        except Exception as exc:  # noqa: BLE001 - report any transport failure to the UI
            tmp.unlink(missing_ok=True)
            job.status = "error"
            job.error = str(exc)[:160]


def delete_model(filename: str) -> dict:
    """Move a model file to models/.trash/ so it is recoverable but undetected."""
    if Path(filename).name != filename:
        return {"status": "error", "error": "invalid name"}
    src = _MODELS_DIR / filename
    if not src.exists():
        return {"status": "error", "error": "not found"}
    _TRASH_DIR.mkdir(parents=True, exist_ok=True)
    src.replace(_TRASH_DIR / filename)
    return {"status": "deleted"}
