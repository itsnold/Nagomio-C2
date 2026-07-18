#!/usr/bin/env bash
set -euo pipefail

TEAMSERVER_URL="${TEAMSERVER_URL:-http://127.0.0.1:18090}"
NAGOMIO_API_TOKEN="${NAGOMIO_API_TOKEN:-smoke-api-token}"
NAGOMIO_AGENT_TOKEN="${NAGOMIO_AGENT_TOKEN:-smoke-agent-token}"
AGENT_ID="${AGENT_ID:-smoke-agent}"
TASK_ID="${TASK_ID:-smoke-task}"
# Comma-separated modes: plaintext, encrypted (default both).
SMOKE_MODES="${SMOKE_MODES:-plaintext,encrypted}"

export NAGOMIO_API_TOKEN
export NAGOMIO_AGENT_TOKEN
export TEAMSERVER_URL
export NAGOMIO_BIND_ADDR="${TEAMSERVER_URL#http://}"
export NAGOMIO_CALLBACK_URL="$TEAMSERVER_URL"
export NAGOMIO_DB_PATH="${NAGOMIO_DB_PATH:-/tmp/nagomio-smoke.db}"
export NAGOMIO_PAYLOAD_DIR="${NAGOMIO_PAYLOAD_DIR:-/tmp/nagomio-smoke-payloads}"
export NAGOMIO_PROJECT_ROOT="${NAGOMIO_PROJECT_ROOT:-$(pwd)}"

run_mode() {
  local mode="$1"
  local wire="false"
  local label="smoke-${mode}"
  local agent_id="${AGENT_ID}-${mode}"
  local task_id="${TASK_ID}-${mode}"
  local db_path="${NAGOMIO_DB_PATH%.db}-${mode}.db"

  if [[ "$mode" == "encrypted" ]]; then
    wire="true"
  elif [[ "$mode" != "plaintext" ]]; then
    echo "unknown smoke mode: $mode" >&2
    return 1
  fi

  rm -f "$db_path" "${db_path}-wal" "${db_path}-shm"
  rm -rf "${NAGOMIO_PAYLOAD_DIR}-${mode}"

  echo "==> smoke mode: $mode (wire_encryption=$wire)"

  NAGOMIO_WIRE_ENCRYPTION="$wire" \
  NAGOMIO_DB_PATH="$db_path" \
  NAGOMIO_PAYLOAD_DIR="${NAGOMIO_PAYLOAD_DIR}-${mode}" \
  cargo run -p teamserver >"/tmp/nagomio-smoke-teamserver-${mode}.log" 2>&1 &
  local server_pid="$!"

  cleanup_server() {
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  }
  trap cleanup_server RETURN

  for _ in $(seq 1 80); do
    if curl -fsS "$TEAMSERVER_URL/health" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
  curl -fsS "$TEAMSERVER_URL/health" >/dev/null

  local artifact_json binary_path
  artifact_json="$(
    TEAMSERVER_URL="$TEAMSERVER_URL" \
    AGENT_ID="$agent_id" \
    LABEL="$label" \
    WIRE_ENCRYPTION="$wire" \
    scripts/build-payload.sh
  )"
  binary_path="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["binary_path"])' <<< "$artifact_json")"

  timeout 8s "$binary_path" >"/tmp/nagomio-smoke-agent-${mode}.log" 2>&1 || true

  AGENT_ID="$agent_id" TASK_ID="$task_id" COMMAND=printf ARGUMENTS_JSON='["smoke-ok"]' \
    scripts/queue-task.sh >/dev/null

  timeout 8s "$binary_path" >"/tmp/nagomio-smoke-agent-task-${mode}.log" 2>&1 || true

  local responses
  responses="$(curl -fsS "$TEAMSERVER_URL/api/tasks/$task_id/responses" \
    -H "Authorization: Bearer $NAGOMIO_API_TOKEN")"

  python3 -c '
import json, sys
mode = sys.argv[1]
responses = json.loads(sys.argv[2])
if not responses or "smoke-ok" not in responses[0].get("output", ""):
    raise SystemExit(f"expected smoke task output was not returned for mode={mode}")
print(f"smoke mode {mode} passed")
' "$mode" "$responses"

  cleanup_server
  trap - RETURN
}

IFS=',' read -r -a modes <<< "$SMOKE_MODES"
for mode in "${modes[@]}"; do
  mode="$(echo "$mode" | xargs)"
  [[ -n "$mode" ]] || continue
  run_mode "$mode"
done

echo "Nagomio smoke test passed (${SMOKE_MODES})"
