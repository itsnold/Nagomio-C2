# Architecture

## Components

- `teamserver/`: Rust API, persistence worker, and SOCKS5 relay.
- `tauri-client/`: React + Tauri operator UI.
- `agent/`: C++17 agent, profile-driven transport, ChaCha20-Poly1305 wire envelope, post-exploit module registry.
- `shared/`: shared Rust types used by the server and UI.
- `scripts/`: local helper scripts for running and smoke-testing the system.

## Runtime flow

1. The agent `POST`s (or `GET`s) to one of the profile paths. The body is
   sealed with ChaCha20-Poly1305 when wire encryption is enabled. The
   request carries `x-nagomio-ts` + `x-nagomio-nonce` + `x-nagomio-mac` for
   HMAC-SHA256 PSK auth.
2. The teamserver's `handle_beacon` checks the HMAC against the agent's
   `agent_id`, decrypts the body, and either returns a queued task or
   long-polls up to `2 * sleep_seconds` for one to arrive.
 3. The agent executes the task (or dispatches to a built-in module) and
    posts the result to `/response` with its own fresh HMAC.
4. The UI polls the API and renders agents, tasks, responses, and payload
   artifacts. Operator requests are authenticated with the same HMAC scheme
   or a legacy `x-nagomio-token` header.
5. Record and live-stream modules upload binary chunks to
   `/api/upload/stream/<agent_id>/<task_id>`. Live UI windows poll
   `/api/stream/<agent_id>/<task_id>` for the latest frame or audio buffer.
   When the task completes or `stream_stop` is acknowledged, the teamserver
   assembles an MJPEG or WAV artifact under `downloads/<agent>/<task>/`.

## Persistence

- The teamserver's in-memory `Store` is the read path.
- A single background worker drains an `mpsc::UnboundedSender<PersistEvent>`
   and applies point `INSERT` / `UPDATE` / `DELETE` operations to a
   dedicated SQLite connection in WAL mode. The legacy JSON state file
   (used when no `db_path` is set) is debounced into a 5-second checkpoint.
- Cold start: `load_store_from_db` (or `load_store_json`) reconstructs the
   `Store` from SQLite (or the JSON state file).
- A separate re-queue worker walks the `tasks` table every 30s and resets
   any task in `Dispatched` for longer than
   `STALE_DISPATCH_TIMEOUT_SECONDS` (default 600s) back to `Queued`.

## Wire envelope

- AAD = directional context (`nagomio/agent/v1` or `nagomio/server/v1`).
- Key = `HKDF-SHA256(ikm=psk, salt=32 zero bytes, info=ctx)[..32]`.
- 12-byte random nonce, 16-byte Poly1305 tag.
- Single-line JSON envelope `{nonce, ct, tag, ctx}`.

## Modules

`agent/src/modules/registry.cpp` dispatches built-in module names to
`modules/<name>.cpp`. Each module reads `Task.arguments` and returns the JSON
output that goes into `AgentResponse.output`. See `docs/commands.md` for
the full list.

Display/camera recording and streaming share the `stream_common.h` capture and
chunk upload path. Video artifacts use a small `MJPF` container made of a header
plus JPEG frames; microphone artifacts are assembled into WAV files.

## Size limits

- Agent command output is capped at 1 MiB per task.
- File upload/download tasks are capped at 10 MiB per file.
- Agent shell tasks time out after 120 seconds by default. Override with
  `NAGOMIO_TASK_TIMEOUT_SECONDS`.

## Generated local data

- Payload build outputs live under `payloads/` and are ignored by git.
- Downloaded files and media artifacts live under `downloads/` and are ignored by git.
- Local SQLite files and WAL/SHM sidecars are ignored by git.
