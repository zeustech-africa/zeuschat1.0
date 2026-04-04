#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODEL_DIR="$ROOT_DIR/static/models"

mkdir -p "$MODEL_DIR"

base_url="https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights"

files=(
  tiny_face_detector_model-weights_manifest.json
  tiny_face_detector_model-shard1
  face_landmark_68_model-weights_manifest.json
  face_landmark_68_model-shard1
  face_recognition_model-weights_manifest.json
  face_recognition_model-shard1
  face_recognition_model-shard2
)

echo "Downloading face-api models into: $MODEL_DIR"
for file in "${files[@]}"; do
  echo " - $file"
  curl -fsSL "$base_url/$file" -o "$MODEL_DIR/$file"
done

echo "Done. Models are available in $MODEL_DIR"
