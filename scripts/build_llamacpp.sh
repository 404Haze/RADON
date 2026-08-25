#!/usr/bin/env bash
# Clone and build llama.cpp at a pinned release (CPU build).
set -euo pipefail
cd "$(dirname "$0")/.."

LLAMACPP_VERSION="v0.3.0"
LLAMACPP_REPO="https://github.com/ggml-org/llama.cpp.git"
LLAMACPP_DIR="vendor/llama.cpp"

if [ ! -d "$LLAMACPP_DIR" ]; then
  echo "Cloning llama.cpp ${LLAMACPP_VERSION} ..."
  git clone --depth 1 --branch "$LLAMACPP_VERSION" "$LLAMACPP_REPO" "$LLAMACPP_DIR"
fi

echo "Building llama.cpp (CPU) ..."
# -DGGML_NATIVE=OFF keeps the binary portable. Drop it for a small speedup on
# your own machine (builds with -march=native). Swap the repo above for
# Intel's ik_llama.cpp fork if you want its ~3x CPU acceleration.
# Only the server target is built: tests/bench add a lot of compile time and
# disk for binaries we never use.
cmake -S "$LLAMACPP_DIR" -B "$LLAMACPP_DIR/build" -DGGML_CUDA=OFF -DGGML_NATIVE=OFF
cmake --build "$LLAMACPP_DIR/build" --config Release --target llama-server -j "$(nproc)"

echo "Done. Server binary: $LLAMACPP_DIR/build/bin/llama-server"
