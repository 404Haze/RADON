#!/usr/bin/env bash
# Fetch the pinned LFM 2.5 model (unsloth dynamic Q6) and verify its checksum.
set -euo pipefail
cd "$(dirname "$0")/.."

MODEL_REPO="unsloth/LFM2.5-1.2B-Instruct-GGUF"
MODEL_FILE="LFM2.5-1.2B-Instruct-UD-Q6_K_XL.gguf"
SHA256="a1ede0b031a20596cdaa6d2a7f15a855d3514253d125ed1d476ea3e0a84018ae"
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
