"""Process supervision for the LLM server and MongoDB (laptop/dev mode).

In the deployed (compose) mode these run as separate containers; here the API
process acts as the command center that starts/stops them so a single
`uvicorn radon.api:app` brings the whole stack up.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import threading
from pathlib import Path

from radon.config import runtime_config

_ROOT = Path(__file__).parent.parent
_MODELS_DIR = _ROOT / "models"
_LLAMA_BIN = _ROOT / "vendor" / "llama.cpp" / "build" / "bin" / "llama-server"
_LLAMA_HOST = "127.0.0.1"
_LLAMA_PORT = 8081
_MONGO_CONTAINER = "radon-mongo"
_MONGO_VOLUME = "radon-mongo-data"
_MONGO_IMAGE = "docker.io/library/mongo:7"


def _tcp_open(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _podman(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["podman", *args], capture_output=True, text=True, timeout=30)


class ComponentManager:
    """Owns the llama-server child process and the mongo podman container."""

    def __init__(self) -> None:
        self._llama: subprocess.Popen | None = None
        self._lock = threading.Lock()

    # ---- llama ----

    def llama_status(self) -> str:
        """up | starting | down"""
        if _tcp_open(_LLAMA_HOST, _LLAMA_PORT):
            return "up"
        with self._lock:
            if self._llama is not None and self._llama.poll() is None:
                return "starting"
        return "down"

    def _model_path(self) -> Path | None:
        cfg = runtime_config()
        name = (cfg.get("model") or "").strip()
        if name:
            p = _MODELS_DIR / name
            if p.exists():
                return p
        for p in sorted(_MODELS_DIR.glob("*.gguf")):
            return p
        return None

    def start_llama(self) -> dict:
        with self._lock:
            if self._llama is not None and self._llama.poll() is None:
                return {"status": "up"}
            model = self._model_path()
            if model is None:
                return {"status": "error", "error": "no model file in models/"}
            self._llama = subprocess.Popen(
                [str(_LLAMA_BIN), "-m", str(model), "--host", _LLAMA_HOST, "--port", str(_LLAMA_PORT)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return {"status": "starting", "pid": self._llama.pid}

    def stop_llama(self) -> dict:
        with self._lock:
            p = self._llama
            self._llama = None
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        return {"status": "stopped"}

    # ---- mongo ----

    def mongo_status(self) -> str:
        """up | down"""
        if not shutil.which("podman"):
            return "down"
        try:
            r = _podman(["ps", "-a", "--filter", f"name={_MONGO_CONTAINER}", "--format", "{{.Status}}"])
        except (subprocess.SubprocessError, OSError):
            return "down"
        out = (r.stdout or "").strip()
        if not out:
            return "down"
        return "up" if out.lower().startswith("up ") else "down"

    def start_mongo(self) -> dict:
        if self.mongo_status() == "up":
            return {"status": "up"}
        if not shutil.which("podman"):
            return {"status": "error", "error": "podman not found"}
        try:
            r = _podman(["ps", "-a", "--filter", f"name={_MONGO_CONTAINER}", "--format", "{{.Names}}"])
            if (r.stdout or "").strip():
                _podman(["start", _MONGO_CONTAINER])
            else:
                _podman(["run", "-d", "--name", _MONGO_CONTAINER,
                         "-p", "127.0.0.1:27017:27017",
                         "-v", f"{_MONGO_VOLUME}:/data/db", _MONGO_IMAGE])
        except (subprocess.SubprocessError, OSError) as exc:
            return {"status": "error", "error": str(exc)[:120]}
        return {"status": "starting"}

    def stop_mongo(self) -> dict:
        if shutil.which("podman"):
            try:
                _podman(["stop", _MONGO_CONTAINER])
            except (subprocess.SubprocessError, OSError):
                pass
        return {"status": "stopped"}

    def restart_mongo(self) -> dict:
        if shutil.which("podman"):
            try:
                _podman(["restart", _MONGO_CONTAINER])
            except (subprocess.SubprocessError, OSError):
                pass
        return {"status": "starting"}

    def auto_start(self) -> None:
        """Bring up anything that is down (idempotent; skips what is already up)."""
        if self.llama_status() == "down":
            self.start_llama()
        if self.mongo_status() == "down":
            self.start_mongo()
