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

- **`teamserver/`**: the backend API. Rust + `tokio` + `axum`. This is what the operator talks to, what tracks agents, and what builds payloads. Uses SQLite so there's no separate database server to worry about.
- **`tauri-client/`**: the operator UI. React 18 + TypeScript, wrapped in Tauri v2. Way lighter than an Electron app, which I appreciate.
- **`agent/`**: the actual implant. Written in C++17 using `cpp-httplib`. It beacons home, grabs tasks as JSON, runs them, and sends the output back. Cross-compiles to Linux and Windows (via MinGW).
- **`shared/`**: a tiny Rust crate that just defines the API types with `serde`, so the frontend and backend never disagree about what the JSON looks like.
- **`scripts/`**: bash scripts I use for local testing and building so I stop typing the same commands.

---

## What the agent can do

It's meant to be lightweight but still useful. It talks over HTTP/HTTPS, pulls down JSON tasks, and returns whatever the task printed.

### Evasions (optional, build-time)

I wanted to understand how AV/EDR tools actually look at software, so I added some configurable evasions you can flip on when building:

- **Anti-Debug**: checks `/proc/self/status` on Linux or `IsDebuggerPresent()` on Windows to bail in analysis environments.
- **Anti-VM**: looks for obvious VM stuff (fewer than 2 cores, under 2GB RAM, known VM processes/MACs).
- **Anti-Sandbox**: checks system uptime, since sandboxes usually spin up and die fast.
- **Daemonize**: drops to the background with `FreeConsole()` (Windows) or `daemon()` (Linux).
- **XOR config**: replaces the plaintext callback URL/token with compile-time XOR so a basic `strings` doesn't immediately give you the server.

### Commands

The current code handles the shell execution and file-task paths that the UI uses. The full command list lives in [docs/commands.md](docs/commands.md) (`shell`, `powershell`, `sysinfo`, `ps`, `net`, plus file stuff like `ls`, `cat`, `download`, `upload`, `rm`, `mv`, `mkdir`).

---

## The payload builder

So the backend has a `/api/payload/build` endpoint that takes whatever OpSec options you ticked in the UI and actually compiles the C++ agent with them.

There's also a shellcode option: pick "Shellcode (.bin)" as the output format and the teamserver builds the agent as a shared library (`.dll`/`.so`), then runs it through [Donut](https://github.com/TheWover/Donut) to turn it into position-independent shellcode, useful if you want to use your own loader.

*(You'll need `donut` on your server's PATH for that one specific feature tho)*

---

## The desktop UI

The Tauri dashboard lets you:

- See all your sessions ( on who's online, who's stale, and who's gone☹️)
- Run tasks through an interactive console (`shell`, `powershell`, `sysinfo`, `ps`, `net`, and file commands).
- Browse the remote filesystem (`ls`, `cat`, `download`, `upload`, `rm`, `mv`, `mkdir`).
- Build new payloads with whatever OpSec flags you want.

---

## Running it locally

Two steps:

1. **Start the backend:**
   ```bash
   cargo run -p teamserver
   ```
2. **Start the UI:**
   ```bash
   cd tauri-client
   npm install
   npm run dev
   ```

---

<p align="center">
  <i>Disclaimer: this is purely for learning and understanding how this stuff works under the hood. Please only run it on machines you own or have explicit permission to test ok byebye</i>
</p>
