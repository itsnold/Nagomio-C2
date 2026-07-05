# Security Notes

## Defaults

- The teamserver binds to `127.0.0.1:8080` by default.
- CORS is restricted to local development and Tauri origins unless overridden.
- `NAGOMIO_API_PSK` and `NAGOMIO_AGENT_PSK` should be set for real deployments;
  `NAGOMIO_API_TOKEN` / `NAGOMIO_AGENT_TOKEN` are accepted as fallbacks.
- Unauthenticated mode is allowed only for loopback binds; non-loopback binds
  require both PSKs to be set unless `NAGOMIO_ALLOW_UNAUTHENTICATED=true` is
  explicitly opted in.

## Environment variables

| Variable | Default | Notes |
|----------|---------|-------|
| `NAGOMIO_BIND_ADDR` | `127.0.0.1:8080` | axum bind address |
| `NAGOMIO_DB_PATH` | `nagomio.db` | SQLite database (WAL mode). Append-only persistence. |
| `NAGOMIO_STATE_FILE` | unset | Legacy JSON state file; debounced checkpoint |
| `NAGOMIO_PROJECT_ROOT` | cwd | Where the teamserver finds `agent/CMakeLists.txt` for payload builds |
| `NAGOMIO_PAYLOAD_DIR` | `payloads` | Where built payloads are stored |
| `NAGOMIO_DOWNLOAD_DIR` | `downloads` | Where agent file downloads are stored |
| `NAGOMIO_CALLBACK_URL` | `http://127.0.0.1:8080` | Default teamserver URL embedded into payloads |
| `NAGOMIO_DEFAULT_SLEEP_SECONDS` | `5` | Default beacon interval |
| `NAGOMIO_API_PSK` | unset | PSK for HMAC operator auth and wire body sealing. `NAGOMIO_API_TOKEN` is a fallback. |
| `NAGOMIO_AGENT_PSK` | unset | PSK for HMAC agent auth and wire body sealing. `NAGOMIO_AGENT_TOKEN` is a fallback. |
| `NAGOMIO_WIRE_ENCRYPTION` | `false` | When true, `/beacon` and `/response` bodies are sealed with ChaCha20-Poly1305. |
| `NAGOMIO_SOCKS_BIND_ADDR` | unset | If set, the teamserver starts a SOCKS5 relay at this address. |
| `NAGOMIO_CORS_ORIGINS` | Tauri dev defaults | Comma-separated allowlist |
| `NAGOMIO_ALLOW_UNAUTHENTICATED` | loopback only | Explicit override for lab deployments |

## Authentication

### Operator (A4/A5)

Every operator API call must carry:

- `Authorization: Bearer <api_psk>` (legacy), **or**
- `x-nagomio-token: <api_psk>` (legacy), **or**
- `x-nagomio-ts: <unix-seconds>` + `x-nagomio-nonce: <random>` +
  `x-nagomio-mac: hex(HMAC-SHA256(api_psk, "operator\n<ts>\n<nonce>"))`

The MAC is verified with `subtle::ConstantTimeEq` to avoid timing side-channels
on token guess. Each `(timestamp, mac)` pair is held in a per-principal LRU
rejected on reuse within the 60s clock skew window.

### Agent (A4)

Every `/beacon` and `/response` POST must carry:

- `x-nagomio-ts` + `x-nagomio-nonce` + `x-nagomio-mac` over the **agent_id** (not
  `agent`). The same constant-time compare and replay cache apply.

The principal in the HMAC is the agent_id from the body. The token is
`NAGOMIO_AGENT_PSK` (or the per-payload `agent_psk`).

## Wire encryption (B1)

When `NAGOMIO_WIRE_ENCRYPTION=1` on the teamserver, `/beacon` and `/response`
HTTP bodies are sealed using ChaCha20-Poly1305 with a key derived from the
PSK via HKDF-SHA256. The directional context strings are
`nagomio/agent/v1` and `nagomio/server/v1` so the two directions use
independent keys.

The wire envelope is a single JSON object:

```json
{
  "nonce": "<base64 12 bytes>",
  "ct":    "<base64 ciphertext>",
  "tag":   "<base64 16 bytes>",
  "ctx":   "nagomio/agent/v1"
}
```

AAD is the `ctx` string. The teamserver rejects requests that are not sealed
when `NAGOMIO_WIRE_ENCRYPTION=1`; both ends must agree.

## Profile / transport (B2)

The agent's on-the-wire shape is configured at build time via
`-DNAGOMIO_PROFILE=<name>`:

- `default` — `POST /beacon`, `POST /response`. UA `NagomioAgent/1.0`.
- `cdn_metrics` — `POST /api/v2/metrics`, `POST /metrics/v1/events`. UA
  `CloudMetrics/1.4`. Body wrapped as `{"batch":[{"m":<beacon>}]}`.
- `analytics` — `POST /track`, `POST /track`. UA `Tracker/2.1`. Body wrapped
  as `{"events":[{<beacon>}]}`.
- `dead_drop` — `GET /dead_drop/<agent_id>`, `POST /response`. UA unchanged.

The teamserver listens on all of `/beacon`, `/api/v2/metrics`, `/track`,
`/metrics/v1/events`, and `/dead_drop/:agent_id`.

## SNI override (B4)

For domain-front style deployments, build the agent with
`-DNAGOMIO_SNI_OVERRIDE=<host>`. On Windows this calls
`WinHttpSetOption(WINHTTP_OPTION_SSL_SERVER_NAME, ...)` so the TLS handshake
advertises the override while the TCP destination and HTTP Host header point
at the actual teamserver. (Linux side: see `agent/src/main.cpp` — not yet
implemented; cpp-httplib's SNI is taken from the connection hostname.)

## AMSI / ETW patching (B5)

When `NAGOMIO_STEALTH=ON` on Windows, the agent patches
`amsi.dll!AmsiScanBuffer` to short-circuit (returns `E_INVALIDARG` so AMSI
treats the input as benign) and `ntdll!EtwEventWrite` to a single `ret`.
Patches are applied via `VirtualProtect` round-trip, leaving no big RWX
window. Run after the anti-debug / anti-VM / anti-sandbox checks and before
the first HTTP request.

## Persistence re-queue (A9)

Tasks that are dispatched but never responded to within
`STALE_DISPATCH_TIMEOUT_SECONDS` (default 600s) are automatically re-queued.
The agent re-receives them on its next beacon. A9 protects against
network-checksum-flipping dead-letter scenarios.

## Audit log (B10)

Every authenticated operator API call emits a row into `audit_log`:

- `id`, `timestamp_unix`, `source_ip`, `action`, `agent_id?`, `task_id?`

`GET /api/audit?since=<unix>&limit=<n>` reads the log for the operator UI.

## SOCKS5 relay (B9)

If `NAGOMIO_SOCKS_BIND_ADDR` is set, the teamserver starts a SOCKS5 listener
on that address. `proxychains curl http://internal-target` pointed at the
listener pushes bytes through the teamserver into the agent's
`socks` module. Used for pivoting into a target's internal network.

## Dead-drop tasking (B11)

The `dead_drop` profile makes the agent `GET /dead_drop/<agent_id>` instead
of `POST /beacon`. Operators can push tasks via
`POST /api/dead_drop/<agent_id>/push` to the teamserver. Useful when the
target network can only reach pull-only CDN URLs.
