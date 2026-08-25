"""Run the emulator: python -m gcp_emulator"""

from __future__ import annotations

import uvicorn


def main() -> None:
    uvicorn.run("gcp_emulator.app:app", host="127.0.0.1", port=8080)


if __name__ == "__main__":
    main()
