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
        command: "__nagomio_file_download",
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
  }
];
