#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/opt/local/bin/python3.14}"
MOCK_LOG="/tmp/zeuschat_mock_backend.log"

cleanup() {
  if [[ -n "${MOCK_PID:-}" ]] && kill -0 "$MOCK_PID" >/dev/null 2>&1; then
    kill "$MOCK_PID" >/dev/null 2>&1 || true
    wait "$MOCK_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

cd "$ROOT_DIR"

if lsof -iTCP:5000 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Port 5000 is already in use. Stop the running service and re-run ./run_tests.sh"
  exit 1
fi

"$PYTHON_BIN" mock_backend.py >"$MOCK_LOG" 2>&1 &
MOCK_PID=$!

echo "Started mock backend (PID: $MOCK_PID)"

READY=0
for _ in {1..80}; do
  if curl -sf http://127.0.0.1:5000/health >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.25
done

if [[ "$READY" -ne 1 ]]; then
  echo "Mock backend failed to start. Log: $MOCK_LOG"
  tail -n 60 "$MOCK_LOG" || true
  exit 1
fi

echo "Mock backend ready. Running pytest..."
"$PYTHON_BIN" -m pytest -q
