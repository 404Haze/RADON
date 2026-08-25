#!/usr/bin/env bash
# R.A.D.O.N. setup: build llama.cpp and fetch the pinned LFM 2.5 model.
# Neither llama.cpp nor the model weights live in this repo; this fetches
# them at install time, pinned to known-good versions.
set -euo pipefail

cd "$(dirname "$0")/.."

./scripts/build_llamacpp.sh
./scripts/fetch_model.sh

cat <<'EOF'

Setup complete.

  llama.cpp server:  vendor/llama.cpp/build/bin/llama-server
  model weights:     models/LFM2.5-1.2B-Instruct-UD-Q5_K_XL.gguf

Start the triage server later with:

  vendor/llama.cpp/build/bin/llama-server \
      -m models/LFM2.5-1.2B-Instruct-UD-Q5_K_XL.gguf \
      --port 8080
EOF
