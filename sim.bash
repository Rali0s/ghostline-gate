#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${ROOT_DIR}/build-local"
if [[ -z "${LISTEN_PORT:-}" ]]; then
  LISTEN_PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
fi

if [[ -z "${UPSTREAM_PORT:-}" ]]; then
  UPSTREAM_PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
fi
MODE="${MODE:-mqtt}"
MESSAGE="${MESSAGE:-hello through ghostline}"
TOPIC="${TOPIC:-demo/topic}"
OUT_DIR="${ROOT_DIR}/sim-output/${MODE}"

mkdir -p "${OUT_DIR}"
rm -f "${OUT_DIR}/host.log" "${OUT_DIR}/server.log" "${OUT_DIR}/ghostline.log" \
      "${OUT_DIR}/ghostline_audit.log" "${OUT_DIR}/ghostline_actions.log" \
      "${OUT_DIR}/ghostline_audit.jsonl" "${OUT_DIR}/ghostline_actions.jsonl"
touch "${OUT_DIR}/ghostline_audit.log" "${OUT_DIR}/ghostline_actions.log" \
      "${OUT_DIR}/ghostline_audit.jsonl" "${OUT_DIR}/ghostline_actions.jsonl"

pkill -f "${ROOT_DIR}/tests/Server.py --port ${UPSTREAM_PORT}" 2>/dev/null || true
pkill -f "${ROOT_DIR}/tests/Host.py --port ${LISTEN_PORT}" 2>/dev/null || true
pkill -f "${ROOT_DIR}/tests/MqttServer.py --port ${UPSTREAM_PORT}" 2>/dev/null || true
pkill -f "${ROOT_DIR}/tests/MqttHost.py --port ${LISTEN_PORT}" 2>/dev/null || true
pkill -f "${BUILD_DIR}/ghostline_cli ${LISTEN_PORT} 127.0.0.1 ${UPSTREAM_PORT}" 2>/dev/null || true

cleanup() {
  local code=$?
  [[ -n "${HOST_PID:-}" ]] && kill "${HOST_PID}" 2>/dev/null || true
  [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true
  [[ -n "${GHOSTLINE_PID:-}" ]] && kill "${GHOSTLINE_PID}" 2>/dev/null || true
  wait "${HOST_PID:-}" 2>/dev/null || true
  wait "${SERVER_PID:-}" 2>/dev/null || true
  wait "${GHOSTLINE_PID:-}" 2>/dev/null || true
  exit "${code}"
}
trap cleanup EXIT

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}"
cmake --build "${BUILD_DIR}"

SERVER_CMD=(python3 "${ROOT_DIR}/tests/Server.py" --port "${UPSTREAM_PORT}")
HOST_CMD=(python3 "${ROOT_DIR}/tests/Host.py" --port "${LISTEN_PORT}" --message "${MESSAGE}")
FIXTURE_PATH="${ROOT_DIR}/tests/fixtures/raw_live.json"

case "${MODE}" in
  mqtt)
    if [[ "${MESSAGE}" == "hello through ghostline" ]]; then
      MESSAGE="hello mqtt payload"
    fi
    SERVER_CMD=(python3 "${ROOT_DIR}/tests/MqttServer.py" --port "${UPSTREAM_PORT}")
    HOST_CMD=(python3 "${ROOT_DIR}/tests/MqttHost.py" --port "${LISTEN_PORT}" --topic "${TOPIC}" --message "${MESSAGE}")
    FIXTURE_PATH="${ROOT_DIR}/tests/fixtures/mqtt_publish.json"
    ;;
esac

"${SERVER_CMD[@]}" > "${OUT_DIR}/server.log" 2>&1 &
SERVER_PID=$!

sleep 0.5

GHOSTLINE_ARGS=(
  "${BUILD_DIR}/ghostline_cli"
  "${LISTEN_PORT}"
  "127.0.0.1"
  "${UPSTREAM_PORT}"
  "--audit-log" "${OUT_DIR}/ghostline_audit.log"
  "--audit-json" "${OUT_DIR}/ghostline_audit.jsonl"
  "--action-log" "${OUT_DIR}/ghostline_actions.log"
  "--actions-json" "${OUT_DIR}/ghostline_actions.jsonl"
)

case "${MODE}" in
  mqtt)
    GHOSTLINE_ARGS+=(
      "--protocol-hint" "mqtt"
      "--replace-text" "patched-payload"
      "--mutate-direction" "c2s"
      "--mqtt-review-threshold" "8"
    )
    ;;
  raw)
    GHOSTLINE_ARGS+=(
      "--protocol-hint" "raw-live"
      "--raw-live"
      "--raw-find-text" "hello"
      "--replace-text" "patch"
      "--end-hex" "67686f73746c696e65"
      "--mutate-direction" "c2s"
      "--raw-review-threshold" "8"
    )
    ;;
  byte-window)
    GHOSTLINE_ARGS+=(
      "--protocol-hint" "byte-window"
      "--start-hex" "68656c6c6f"
      "--end-hex" "67686f73746c696e65"
      "--replace-text" "patched"
      "--mutate-direction" "c2s"
      "--byte-review-threshold" "8"
    )
    ;;
  *)
    echo "Unsupported MODE=${MODE}. Use mqtt, raw, or byte-window." >&2
    exit 2
    ;;
esac

"${GHOSTLINE_ARGS[@]}" > "${OUT_DIR}/ghostline.log" 2>&1 &
GHOSTLINE_PID=$!

sleep 0.5

"${HOST_CMD[@]}" > "${OUT_DIR}/host.log" 2>&1 &
HOST_PID=$!

wait "${HOST_PID}"

sleep 0.5

python3 "${ROOT_DIR}/tests/assert_simulation.py" "${FIXTURE_PATH}" "${OUT_DIR}"

echo "Simulation complete."
echo "Logs:"
echo "  ${OUT_DIR}/host.log"
echo "  ${OUT_DIR}/server.log"
echo "  ${OUT_DIR}/ghostline.log"
echo "  ${OUT_DIR}/ghostline_audit.log"
echo "  ${OUT_DIR}/ghostline_audit.jsonl"
echo "  ${OUT_DIR}/ghostline_actions.log"
echo "  ${OUT_DIR}/ghostline_actions.jsonl"
