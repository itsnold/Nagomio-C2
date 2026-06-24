#!/usr/bin/env bash
set -euo pipefail

TEAMSERVER_URL="${TEAMSERVER_URL:-http://127.0.0.1:8080}"
AGENT_ID="${AGENT_ID:?AGENT_ID is required}"
TASK_ID="${TASK_ID:-task-$(date +%s)}"
COMMAND="${COMMAND:-whoami}"
ARGUMENTS_JSON="${ARGUMENTS_JSON:-[]}"

auth_args=()
if [[ -n "${NAGOMIO_API_TOKEN:-}" ]]; then
  auth_args=(-H "Authorization: Bearer ${NAGOMIO_API_TOKEN}")
fi

curl -sS -X POST "${TEAMSERVER_URL}/api/tasks" \
  "${auth_args[@]}" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"${AGENT_ID}\",
    \"task\": {
      \"task_id\": \"${TASK_ID}\",
      \"command\": \"${COMMAND}\",
      \"arguments\": ${ARGUMENTS_JSON}
    }
  }"
