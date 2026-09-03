#!/usr/bin/env bash
# R.A.D.O.N. dev launcher: starts the emulator + the API. The API autostarts
# llama-server and the mongo container on boot, so this one command brings up
# the whole stack. Ctrl+C stops it.
set -euo pipefail
cd "$(dirname "$0")/.."

export RADON_ENDPOINT="${RADON_ENDPOINT:-http://127.0.0.1:8080}"
export RADON_LLM_ENDPOINT="${RADON_LLM_ENDPOINT:-http://127.0.0.1:8081}"
export RADON_MONGO_URI="${RADON_MONGO_URI:-mongodb://127.0.0.1:27017}"

.venv/bin/python -m gcp_emulator &
EMU_PID=$!
trap 'kill "$EMU_PID" 2>/dev/null || true' EXIT

.venv/bin/uvicorn radon.api:app --host 127.0.0.1 --port 8000
