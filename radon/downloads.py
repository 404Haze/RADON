"""Model catalogue + delete-to-trash for the Settings panel."""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).parent.parent
_MODELS_DIR = _ROOT / "models"
_TRASH_DIR = _MODELS_DIR / ".trash"

# Display catalogue for the Settings panel. `file` is the on-disk GGUF name used to
# detect the "already downloaded" state (empty for models we don't ship).
COMPATIBLE_MODELS = [
    {"name": "LFM-2.5-1.2B", "repo": "unsloth/LFM2.5-1.2B-Instruct-UD",
     "file": "LFM2.5-1.2B-Instruct-UD-Q5_K_XL.gguf", "quant": "Q5_K_XL", "size": "0.8 GB"},
    {"name": "LFM2.5-8B-A1B", "repo": "unsloth/LFM2.5-8B-A1B",
     "file": "", "quant": "Q5", "size": "~5.5 GB"},
    {"name": "Gemma 4 26B-A4B", "repo": "unsloth/gemma-4-26B-A4B",
     "file": "", "quant": "Q4", "size": "~14 GB"},
]


def compatible_payload() -> list[dict]:
    out = []
    for c in COMPATIBLE_MODELS:
        downloaded = bool(c["file"]) and (_MODELS_DIR / c["file"]).exists()
        out.append({**c, "downloaded": downloaded,
                    "link": f"https://huggingface.co/{c['repo']}"})
    return out


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
