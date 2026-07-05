# Console Commands

## Local commands

- `help [command]`
- `clear`
- `files`
- `console`

## Remote commands

The teamserver's API routes commands by `command` field. Built-in modules
are dispatched to the agent's module registry instead of the shell.
The full set is:

### Shell-style
- `shell <command line>` — run via `sh -lc` on Linux, `cmd /C` on Windows.
- `powershell <command line>` — direct `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command` on Windows (no `cmd.exe` wrapper).

### Discovery
- `sysinfo` — basic system info
- `whoami` — JSON with username, group memberships, integrity level, and elevation status.

### File ops
- `file_list [path]`
- `file_download <path>`
- `file_upload <path> <base64-content>`
- `file_delete <path>`
- `file_rename <source> <destination>`
- `file_mkdir <path>`

### Process
- `ps`, `kill <pid>` (shell-style)
- `mem_exec <base64-shellcode> [mode]` — `mode` is `thread` (default) or `inline`.
- `inject <pid> <base64-shellcode> [mode]` (Windows) — `mode` is `thread` or `hijack`.
- `persist <strategy> [bin]` — strategies: `registry`, `schtasks` (Windows); `crontab`, `systemd-user`, `shell-profile` (Linux).
- `uninstall [mode]` — `now` (default) or `reboot`.

### Network
- `net` (shell-style)
- `portscan <host> <ports> [timeout_ms]` — `ports` is comma-separated, ranges allowed.

### Discovery extras (Windows)
- `screenshot` — base64 BMP of the primary display.
- `clipboard` — current clipboard text.
- `keylog <mode>` — `start` to install the WH_KEYBOARD_LL hook, `flush` to drain the buffer.
- `lsass` — MiniDumpWriteDump of lsass.exe, base64 returned.

### SOCKS (B9)
- `socks` — handled by the teamserver's SOCKS5 relay when the
  agent has been registered for the relay.

Unknown commands are passed through as raw shell execution on the selected agent.
