# Architecture

## Components

- `teamserver/`: Rust API and persistence layer.
- `tauri-client/`: React + Tauri operator UI.
- `agent/`: C++ agent that handles check-ins and task execution.
- `shared/`: shared Rust types used by the server and UI.
- `scripts/`: local helper scripts for running and smoke-testing the system.

## Runtime flow

1. The agent checks in to `/beacon`.
2. The teamserver returns a queued task, if one exists.
3. The agent executes the task and posts the result to `/response`.
4. The UI polls the API and renders agents, tasks, responses, and payload artifacts.

## Storage

- SQLite is the primary persistence path when `NAGOMIO_DB_PATH` is set.
- A JSON state file can be used as a fallback.
- Payload artifacts are written under `NAGOMIO_PAYLOAD_DIR`.
- Downloaded files are written under `NAGOMIO_DOWNLOAD_DIR`.
- Agent command output is capped at 1 MiB per task.
- File upload/download tasks are capped at 10 MiB per file.
- Agent shell tasks time out after 120 seconds by default. Override with `NAGOMIO_TASK_TIMEOUT_SECONDS`.
