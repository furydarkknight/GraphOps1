#!/usr/bin/env bash
# GraphOps — Optional P2 Model Weight Downloader
# Downloads the full ~90MB all-MiniLM-L6-v2 ONNX model weights from HuggingFace
# to replace Git LFS 133-byte pointer stubs.

set -e

DEST_DIR="$(dirname "$0")/../analytics/models/inkloom/encoder"
mkdir -p "$DEST_DIR"

echo "Downloading all-MiniLM-L6-v2 ONNX weights from HuggingFace..."
curl -L -o "$DEST_DIR/model.onnx.data" \
  "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx.data"

echo "Weights downloaded successfully to $DEST_DIR/model.onnx.data"
echo "Restart the analytics service to enable full ONNX inference mode."
