#!/usr/bin/env bash
set -euo pipefail

TEAMSERVER_URL="${TEAMSERVER_URL:-http://127.0.0.1:8080}"
CALLBACK_URL="${CALLBACK_URL:-$TEAMSERVER_URL}"
SLEEP_SECONDS="${SLEEP_SECONDS:-5}"
JITTER_PERCENT="${JITTER_PERCENT:-0}"
AGENT_ID="${AGENT_ID:-lab-agent-1}"
AGENT_TOKEN="${AGENT_TOKEN:-${NAGOMIO_AGENT_TOKEN:-}}"
LABEL="${LABEL:-local-lab}"
TARGET_OS="${TARGET_OS:-linux}"
FORMAT="${FORMAT:-executable}"
STEALTH="${STEALTH:-false}"
ANTI_DEBUG="${ANTI_DEBUG:-false}"
ANTI_VM="${ANTI_VM:-false}"
ANTI_SANDBOX="${ANTI_SANDBOX:-false}"
DAEMONIZE="${DAEMONIZE:-false}"
STATIC_RUNTIME="${STATIC_RUNTIME:-false}"
XOR_CONFIG="${XOR_CONFIG:-false}"
XOR_KEY="${XOR_KEY:-90}"
ENCRYPT_PAYLOAD="${ENCRYPT_PAYLOAD:-false}"
WIRE_ENCRYPTION="${WIRE_ENCRYPTION:-false}"

auth_args=()
if [[ -n "${NAGOMIO_API_TOKEN:-}" ]]; then
  auth_args=(-H "Authorization: Bearer ${NAGOMIO_API_TOKEN}")
fi

curl -sS -X POST "${TEAMSERVER_URL}/api/payload/build" \
  "${auth_args[@]}" \
  -H "Content-Type: application/json" \
  -d "{
    \"callback_url\": \"${CALLBACK_URL}\",
    \"sleep_seconds\": ${SLEEP_SECONDS},
    \"jitter_percent\": ${JITTER_PERCENT},
    \"agent_id\": \"${AGENT_ID}\",
    \"agent_token\": \"${AGENT_TOKEN}\",
    \"label\": \"${LABEL}\",
    \"target_os\": \"${TARGET_OS}\",
    \"format\": \"${FORMAT}\",
    \"stealth\": ${STEALTH},
    \"anti_debug\": ${ANTI_DEBUG},
    \"anti_vm\": ${ANTI_VM},
    \"anti_sandbox\": ${ANTI_SANDBOX},
    \"daemonize\": ${DAEMONIZE},
    \"static_runtime\": ${STATIC_RUNTIME},
    \"xor_config\": ${XOR_CONFIG},
    \"xor_key\": ${XOR_KEY},
    \"encrypt_payload\": ${ENCRYPT_PAYLOAD},
    \"wire_encryption\": ${WIRE_ENCRYPTION}
  }"
