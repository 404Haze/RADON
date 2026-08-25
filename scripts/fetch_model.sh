#!/usr/bin/env bash
# Fetch the pinned LFM 2.5 model (unsloth dynamic Q6) and verify its checksum.
set -euo pipefail
cd "$(dirname "$0")/.."

MODEL_REPO="unsloth/LFM2.5-1.2B-Instruct-GGUF"
MODEL_FILE="LFM2.5-1.2B-Instruct-UD-Q5_K_XL.gguf"
SHA256="7ad5eef540097e1afc0118799e5d22005c0c1721cba0a2b01bed287e4888baaf"
URL="https://huggingface.co/${MODEL_REPO}/resolve/main/${MODEL_FILE}"
OUT="models/${MODEL_FILE}"

mkdir -p models

if [ -f "$OUT" ] && echo "$SHA256  $OUT" | sha256sum -c --quiet; then
  echo "already present and verified: $OUT"
  exit 0
fi

echo "Fetching ${MODEL_FILE} (~1 GB) ..."
curl -L --fail --progress-bar -o "$OUT" "$URL"

echo "Verifying checksum ..."
echo "$SHA256  $OUT" | sha256sum -c -
echo "OK: $OUT"
