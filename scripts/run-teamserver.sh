#!/usr/bin/env bash
set -euo pipefail

export NAGOMIO_BIND_ADDR="${NAGOMIO_BIND_ADDR:-127.0.0.1:8080}"
export NAGOMIO_CALLBACK_URL="${NAGOMIO_CALLBACK_URL:-http://127.0.0.1:8080}"
export NAGOMIO_DB_PATH="${NAGOMIO_DB_PATH:-nagomio.db}"
export NAGOMIO_DEFAULT_SLEEP_SECONDS="${NAGOMIO_DEFAULT_SLEEP_SECONDS:-5}"

if [[ -z "${NAGOMIO_API_TOKEN:-}" ]]; then
  echo "NAGOMIO_API_TOKEN is not set. Operator APIs will not require a token."
fi

cargo run -p teamserver
