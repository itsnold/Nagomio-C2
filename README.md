<div align="center">
  <h1>Nagomio-C2</h1>
  <p><b>A cross-platform Command and Control (C2) framework.</b></p>
  <img src="https://img.shields.io/badge/Language-Rust-orange?style=for-the-badge&logo=rust" alt="Rust" />
  <img src="https://img.shields.io/badge/Language-C++17-blue?style=for-the-badge&logo=c%2B%2B" alt="C++" />
  <img src="https://img.shields.io/badge/Frontend-React/Tauri-61DAFB?style=for-the-badge&logo=react" alt="React" />
  <img src="https://img.shields.io/badge/Database-SQLite-003B57?style=for-the-badge&logo=sqlite" alt="SQLite" />
</div>

<br>

This project was basically a way to actually *learn* systems programming and get some better hands-on experience with rust, and also figure out proper C++ memory management, and generally see how hard it really is to write a C2 from scratch🤩

And yeah obviously it was hard. Cross-compiling across operating systems alone took me longer than I want to admit. But it's been a lot of fun really, and the end result is a C2 where the backend runs on its own, separate from the UI... so you can close the app, come back, and your agents are still doing their thing.

---

## Organization

I tried to keep things modular so future-me doesn't hate present-me:

- **`teamserver/`**: the backend API. Rust + `tokio` + `axum`. This is what the operator talks to, what tracks agents, stores downloaded artifacts, receives stream chunks, and builds payloads. Uses SQLite in WAL mode with an append-only persistence worker, plus a SOCKS5 relay and an audit log.
- **`tauri-client/`**: the operator UI. React 18 + TypeScript, wrapped in Tauri v2. Lists the modules, opens live stream popout windows, renders media artifacts, and lets you pick a callback profile and SNI override at payload-build time. Way lighter than an Electron app, which I appreciate.
- **`agent/`**: the actual implant. Written in C++17 using `cpp-httplib`. Profile-driven transport, ChaCha20-Poly1305 wire envelope, post-exploit module registry. Cross-compiles to Linux and Windows (via MinGW).
- **`shared/`**: a tiny Rust crate that just defines the API types with `serde`, so the frontend and backend never disagree about what the JSON looks like.
- **`scripts/`**: bash scripts I use for local testing and building so I stop typing the same commands.

---

## What the agent can do

It's meant to be lightweight but still useful. It talks over HTTP/HTTPS, pulls down JSON tasks, and returns whatever the task printed.

### Transport & opsec

- **HMAC auth** - every request carries `x-nagomio-ts` + `x-nagomio-nonce` + `x-nagomio-mac` over the agent_id with a per-direction PSK. Replay cache, constant-time compare, 60s clock skew window.
- **Wire encryption** - when enabled, `/beacon` and `/response` bodies are sealed with ChaCha20-Poly1305 keyed off the PSK via HKDF-SHA256.
- **Pluggable callback profiles** - `default`, `cdn_metrics`, `analytics`, `dead_drop`. Each rewrites path, User-Agent, and body template to blend in.
- **SNI override** - Windows only via `WinHttpSetOption`, for domain-front style deployments.
- **Long-poll beacons** - teamserver holds the beacon open until a task is queued, no busy-polling.
- **AMSI / ETW patching** - behind `NAGOMIO_STEALTH` on Windows. Patches `AmsiScanBuffer` and `EtwEventWrite` at startup.
- **Dead-drop tasking** - the `dead_drop` profile makes the agent `GET` instead of `POST`, so it works behind pull-only CDN URLs.
- **SOCKS5 pivot** - the teamserver starts a SOCKS5 listener and forwards bytes through the agent's `socks` module. `proxychains` into the target network.

### Evasions (optional, build-time)

I wanted to understand how AV/EDR tools actually look at software, so I added some configurable evasions you can flip on when building:

- **Anti-Debug**: checks `/proc/self/status` on Linux or `IsDebuggerPresent()` on Windows to bail in analysis environments.
- **Anti-VM**: looks for obvious VM stuff (fewer than 2 cores, under 2GB RAM, known VM processes/MACs).
- **Anti-Sandbox**: checks system uptime, since sandboxes usually spin up and die fast.
- **Daemonize**: drops to the background with `FreeConsole()` (Windows) or `daemon()` (Linux).
- **XOR config**: replaces the plaintext callback URL/token with compile-time XOR so a basic `strings` doesn't immediately give you the server.
- **Randomize UA** - picks one of a set of common User-Agents at startup.
- **Sleep obfuscation** - slices the sleep into jittered sub-second windows instead of a single `sleep()`.
- **Kill date** - Unix epoch after which the agent self-deletes. Build-time validated.

### Post-exploit modules

See [docs/commands.md](docs/commands.md) for full usage.

| Module | What it does |
|--------|---------------|
| `whoami` | username, groups, integrity, elevation as JSON |
| `mem_exec` | `VirtualAlloc` / `mmap` + `CreateThread` shellcode runner |
| `portscan` | TCP connect scan with a port list / range |
| `persist` | `registry` / `schtasks` (Win) or `crontab` / `systemd-user` / `shell-profile` (Linux) |
| `uninstall` | self-delete now or on next reboot |
| `inject` | `CreateRemoteThread` (Win) into a target PID |
| `screenshot` | primary display as base64 BMP (Win) |
| `record_display` | capture the display for N seconds and save an MJPEG artifact |
| `record_camera` | capture the default camera for N seconds and save an MJPEG artifact |
| `record_mic` | capture the default microphone for N seconds and save a WAV artifact |
| `stream_display` | live-stream the display until stopped, then save an MJPEG artifact |
| `stream_camera` | live-stream the default camera until stopped, then save an MJPEG artifact |
| `stream_mic` | live-stream the default microphone until stopped, then save a WAV artifact |
| `stream_stop` | stop an active live stream |
| `clipboard` | current clipboard text (Win) |
| `keylog` | `WH_KEYBOARD_LL` hook (Win) with start / flush |
| `lsass` | `MiniDumpWriteDump` of lsass.exe (Win) |
| `socks` | SOCKS5 byte pump for the teamserver's relay |

### Shell-style commands

- `shell <command line>` - `sh -lc` on Linux, `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command` on Windows.
- File ops: `file_list`, `file_download`, `file_upload`, `file_delete`, `file_rename`, `file_mkdir`.
- Console aliases in the UI: `ls`, `cat`, `download`, `upload`, `rm`, `mv`, `mkdir`, `ps`, `kill`, `net`, `sysinfo`.
- Media aliases in the UI: `stream record display 10 10 70`, `stream live camera 10 70`, `stream live mic`, and `stream stop`.

---

## The payload builder

So the backend has a `/api/payload/build` endpoint that takes whatever OpSec options you ticked in the UI and actually compiles the C++ agent with them.

There's also a shellcode option: pick "Shellcode (.bin)" as the output format and the teamserver builds the agent as a shared library (`.dll`/`.so`), then runs it through [Donut](https://github.com/TheWover/Donut) to turn it into position-independent shellcode, useful if you want to use your own loader.

*(You'll need `donut` on your server's PATH for that one specific feature tho)*

---

## The desktop UI

The Tauri dashboard lets you:

- See all your sessions (🟢 on who's online, who's stale, and who's gone☹️)
- Run tasks through an interactive console - the new modules show up as structured command templates, plus the classic `shell`, `powershell`, `sysinfo`, `ps`, `net` commands.
- Browse the remote filesystem (`ls`, `cat`, `download`, `upload`, `rm`, `mv`, `mkdir`).
- Open live display/camera/mic stream windows and stop streams from the UI.
- Replay saved MJPEG recordings and WAV microphone captures from the task output panel.
- Build new payloads with whatever OpSec flags, profile, SNI override, and wire-encryption toggle you want.

---

## Running it locally

```bash
# 1. start the teamserver
NAGOMIO_DB_PATH=nagomio.db \
NAGOMIO_API_PSK=<random-32-bytes> \
NAGOMIO_AGENT_PSK=<random-32-bytes> \
NAGOMIO_WIRE_ENCRYPTION=1 \
cargo run -p teamserver

# 2. build a payload
cd agent
cmake -S . -B build \
  -DNAGOMIO_DEFAULT_CALLBACK_URL=https://your-ts.example \
  -DNAGOMIO_DEFAULT_AGENT_TOKEN=<same-PSK-as-teamserver> \
  -DNAGOMIO_WIRE_ENCRYPTION=ON \
  -DNAGOMIO_PROFILE=cdn_metrics
cmake --build build

# 3. start the UI
cd ../tauri-client
npm install
npm run dev
```

## Documentation

- `docs/architecture.md` - runtime flow + storage + wire envelope
- `docs/commands.md` - full command / module list
- `docs/security.md` - auth scheme, environment variables, profiles

---

<p align="center">
  <i>Disclaimer: this is purely for learning and understanding how this stuff works under the hood. Please only run it on machines you own or have explicit permission to test ok byebye</i>
</p>
