#!/usr/bin/env bash
set -euo pipefail

TEAMSERVER_URL="${TEAMSERVER_URL:-http://127.0.0.1:18090}"
NAGOMIO_API_TOKEN="${NAGOMIO_API_TOKEN:-smoke-api-token}"
NAGOMIO_AGENT_TOKEN="${NAGOMIO_AGENT_TOKEN:-smoke-agent-token}"
AGENT_ID="${AGENT_ID:-smoke-agent}"
TASK_ID="${TASK_ID:-smoke-task}"

export NAGOMIO_API_TOKEN
export NAGOMIO_AGENT_TOKEN
export TEAMSERVER_URL
export NAGOMIO_BIND_ADDR="${TEAMSERVER_URL#http://}"
export NAGOMIO_CALLBACK_URL="$TEAMSERVER_URL"
export NAGOMIO_DB_PATH="${NAGOMIO_DB_PATH:-/tmp/nagomio-smoke.db}"
export NAGOMIO_PAYLOAD_DIR="${NAGOMIO_PAYLOAD_DIR:-/tmp/nagomio-smoke-payloads}"
export NAGOMIO_PROJECT_ROOT="${NAGOMIO_PROJECT_ROOT:-$(pwd)}"

rm -f "$NAGOMIO_DB_PATH"
rm -rf "$NAGOMIO_PAYLOAD_DIR"

cargo run -p teamserver > /tmp/nagomio-smoke-teamserver.log 2>&1 &
server_pid="$!"
trap 'kill "$server_pid" 2>/dev/null || true' EXIT

for _ in $(seq 1 40); do
  if curl -fsS "$TEAMSERVER_URL/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

artifact_json="$(TEAMSERVER_URL="$TEAMSERVER_URL" AGENT_ID="$AGENT_ID" LABEL=smoke scripts/build-payload.sh)"
binary_path="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["binary_path"])' <<< "$artifact_json")"

timeout 8s "$binary_path" >/tmp/nagomio-smoke-agent.log 2>&1 || true

AGENT_ID="$AGENT_ID" TASK_ID="$TASK_ID" COMMAND=printf ARGUMENTS_JSON='["smoke-ok"]' scripts/queue-task.sh >/dev/null

timeout 8s "$binary_path" >/tmp/nagomio-smoke-agent-task.log 2>&1 || true

responses="$(curl -fsS "$TEAMSERVER_URL/api/tasks/$TASK_ID/responses" \
  -H "Authorization: Bearer $NAGOMIO_API_TOKEN")"

python3 -c '
import json, sys
responses = json.loads(sys.argv[1])
if not responses or "smoke-ok" not in responses[0].get("output", ""):
    raise SystemExit("expected smoke task output was not returned")
' "$responses"

echo "Nagomio smoke test passed"
