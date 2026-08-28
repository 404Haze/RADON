"""Run the emulator: python -m gcp_emulator"""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "gcp_emulator.app:app",
        host=os.environ.get("EMULATOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("EMULATOR_PORT", "8080")),
    )


if __name__ == "__main__":
    main()
