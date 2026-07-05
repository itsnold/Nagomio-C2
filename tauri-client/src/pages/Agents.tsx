import React, { useEffect, useMemo, useState } from "react";
import { FaFolderOpen, FaLaptopCode, FaStream, FaTerminal, FaTrash } from "react-icons/fa";
import { FileBrowser } from "../components/FileBrowser";
import { useAppState, statusClass, unixTime, TaskRecord } from "../components/AppContext";
import { platformFromAgentOs } from "../lib/commandCatalog";
import { helpText, parseConsoleCommand } from "../lib/consoleCommands";

type SessionTab = "console" | "files";
type LocalConsoleEntry = {
  id: string;
  input: string;
  output: string;
  createdAt: number;
};
type AgentMenu = {
  x: number;
  y: number;
  agentId: string;
} | null;

export function Agents() {
  const { agents, tasks, responses, api, refresh, setMessage, loading, setLoading } = useAppState();
  const [selectedAgent, setSelectedAgent] = useState("");
  const [consoleInput, setConsoleInput] = useState("");
  const [localEntries, setLocalEntries] = useState<LocalConsoleEntry[]>([
    { id: "welcome", input: "help", output: helpText(), createdAt: Math.floor(Date.now() / 1000) }
  ]);
  const [consoleClearedAt, setConsoleClearedAt] = useState(0);
  const [activeTab, setActiveTab] = useState<SessionTab>("console");
  const [pendingUploadPath, setPendingUploadPath] = useState("");
  const [agentMenu, setAgentMenu] = useState<AgentMenu>(null);

  const activeAgent = useMemo(
    () => agents.find((agent) => agent.registration.agent_id === selectedAgent),
    [agents, selectedAgent]
  );
  const platform = activeAgent ? platformFromAgentOs(activeAgent.registration.os) : "linux";
  const flatResponses = Object.values(responses).flat();
  const agentTasks = tasks
    .filter((task) => task.agent_id === selectedAgent)
    .sort((left, right) => left.created_at_unix - right.created_at_unix);
  const visibleAgentTasks = agentTasks.filter((task) => task.created_at_unix >= consoleClearedAt);
  function remoteCommandLabel(task: TaskRecord): string {
    if (task.task.command === "sh" || task.task.command === "powershell.exe") {
      const script = task.task.arguments[task.task.arguments.length - 1] || task.task.command;
      if (script.includes("Get-CimInstance Win32_OperatingSystem") || script.includes("uname -a; id")) return "sysinfo";
      if (script.includes("ipconfig /all; route print") || script.includes("ip addr; ip route")) return "net";
      if (script.includes("Get-Process") || script === "ps aux") return "ps";
      return script;
    }
    if (task.task.command === "file_list") return `ls ${task.task.arguments[0] || "."}`;
    if (task.task.command === "file_download") return `download ${task.task.arguments[0] || ""}`;
    if (task.task.command === "file_upload") return `upload ${task.task.arguments[0] || ""}`;
    if (task.task.command === "file_delete") return `rm ${task.task.arguments[0] || ""}`;
    if (task.task.command === "file_rename") return `mv ${task.task.arguments[0] || ""} ${task.task.arguments[1] || ""}`;
    if (task.task.command === "file_mkdir") return `mkdir ${task.task.arguments[0] || ""}`;
    return [task.task.command, ...task.task.arguments].join(" ");
  }
  const eventItems = [
    ...agents.map((agent) => ({
      time: agent.last_seen_unix,
      kind: agent.status === "online" ? "checkin" : agent.status,
      text: `${agent.registration.agent_id} ${agent.status} on ${agent.registration.hostname}`
    })),
    ...tasks.map((task) => ({
      time: task.completed_at_unix ?? task.dispatched_at_unix ?? task.created_at_unix,
      kind: task.status,
      text: `${remoteCommandLabel(task)} ${task.status} for ${task.agent_id}`
    })),
    ...flatResponses.map((response) => ({
      time: tasks.find((task) => task.task.task_id === response.task_id)?.completed_at_unix ?? 0,
      kind: response.status,
      text: `${response.agent_id} returned output`
    }))
  ]
    .filter((event) => event.time > 0)
    .sort((left, right) => right.time - left.time)
    .slice(0, 14);

  useEffect(() => {
    if (!selectedAgent && agents.length > 0) {
      setSelectedAgent(agents[0].registration.agent_id);
    }
  }, [agents, selectedAgent]);

  function appendLocalEntry(input: string, output: string) {
    setLocalEntries((current) => [
      ...current,
      { id: `local-${Date.now()}-${current.length}`, input, output, createdAt: Math.floor(Date.now() / 1000) }
    ]);
  }

  async function queueAgentTask(command: string, args: string[], label: string) {
    if (!command.trim()) return;
    if (!selectedAgent) {
      appendLocalEntry(label, "select an agent from the table before sending remote commands");
      return;
    }
    setLoading(true);
    try {
      await api<TaskRecord>("/api/tasks", {
        method: "POST",
        body: JSON.stringify({
          agent_id: selectedAgent,
          task: {
            task_id: `task-${Date.now()}`,
            command,
            arguments: args
          }
        })
      });
      await refresh();
      setMessage(`${label} sent to ${selectedAgent}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Command send failed");
    } finally {
      setLoading(false);
    }
  }

  async function removeAgent(agentId: string) {
    if (!window.confirm(`Remove agent ${agentId} and its local task history?`)) return;
    setLoading(true);
    try {
      await api<unknown>(`/api/agents/${encodeURIComponent(agentId)}`, {
        method: "DELETE"
      });
      if (selectedAgent === agentId) {
        setSelectedAgent("");
      }
      setAgentMenu(null);
      await refresh();
      setMessage(`Removed agent ${agentId}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Agent removal failed");
    } finally {
      setLoading(false);
    }
  }

  async function sendCommand(event: React.FormEvent) {
    event.preventDefault();
    const input = consoleInput.trim();
    if (!input) return;
    setConsoleInput("");

    const result = parseConsoleCommand(input, platform);
    if (result.type === "local") {
      appendLocalEntry(input, result.output);
      return;
    }
    if (result.type === "clear") {
      setLocalEntries([]);
      setConsoleClearedAt(Math.floor(Date.now() / 1000));
      return;
    }
    if (result.type === "switch") {
      setActiveTab(result.tab);
      if (result.output) appendLocalEntry(input, result.output);
      return;
    }
    if (result.type === "upload") {
      setPendingUploadPath(result.remotePath);
      document.getElementById("console-upload-input")?.click();
      appendLocalEntry(input, `select a local file to upload to ${result.remotePath}`);
      return;
    }
    await queueAgentTask(result.task.command, result.task.arguments, result.label);
  }

  async function uploadFromConsole(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !pendingUploadPath) return;
    const content = await file.arrayBuffer();
    const bytes = new Uint8Array(content);
    let binary = "";
    const chunkSize = 0x8000;
    for (let index = 0; index < bytes.length; index += chunkSize) {
      binary += String.fromCharCode(...bytes.slice(index, index + chunkSize));
    }
    await queueAgentTask("file_upload", [pendingUploadPath, window.btoa(binary)], `upload ${file.name}`);
    setPendingUploadPath("");
  }

  function responseFor(taskId: string) {
    return flatResponses.find((response) => response.task_id === taskId);
  }

  function commandText(task: TaskRecord): string {
    return remoteCommandLabel(task);
  }

  function outputText(task: TaskRecord): string {
    const response = responseFor(task.task.task_id);
    if (!response) return "waiting for response...";

    try {
      const parsed = JSON.parse(response.output);
      if (parsed.type === "file_download") {
        return `Downloaded ${parsed.remote_path}\nSaved to ${parsed.saved_path}\nSize: ${parsed.size} bytes`;
      }
      if (parsed.type === "file_upload") {
        return `Uploaded ${parsed.path}\nSize: ${parsed.size} bytes`;
      }
      if (parsed.type === "file_delete") {
        return `Deleted ${parsed.path}\nRemoved entries: ${parsed.removed}`;
      }
      if (parsed.type === "file_rename") {
        return `Renamed ${parsed.source}\nTo ${parsed.destination}`;
      }
      if (parsed.type === "file_mkdir") {
        return `Created directory ${parsed.path}`;
      }
      if (parsed.type === "file_list" && Array.isArray(parsed.entries)) {
        return [
          `Listing ${parsed.path}`,
          "",
          ...parsed.entries.map((entry: { is_dir: boolean; name: string; size: number }) =>
            `${entry.is_dir ? "[dir] " : "      "}${String(entry.name).padEnd(38)} ${entry.is_dir ? "-" : `${entry.size} bytes`}`
          )
        ].join("\n");
      }
      return JSON.stringify(parsed, null, 2);
    } catch {
      return response.output;
    }
  }

  const consoleRows = [
    ...localEntries.map((entry) => ({ type: "local" as const, time: entry.createdAt, entry })),
    ...visibleAgentTasks.map((task) => ({ type: "task" as const, time: task.created_at_unix, task }))
  ].sort((left, right) => left.time - right.time);

  return (
    <div className="page agents-page operations-grid" onClick={() => setAgentMenu(null)}>
      <section className="panel agents-table-panel">
        <div className="panel-title">
          <FaLaptopCode size={18} />
          <h2>Agents</h2>
        </div>
        <div className="table-wrapper">
          <table className="app-table allow-select compact">
            <thead>
              <tr>
                <th>Status</th>
                <th>Agent</th>
                <th>Host / OS</th>
                <th>Arch</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((agent) => (
                <tr
                  key={agent.registration.agent_id}
                  className={selectedAgent === agent.registration.agent_id ? "selected" : ""}
                  onClick={() => setSelectedAgent(agent.registration.agent_id)}
                  onContextMenu={(event) => {
                    event.preventDefault();
                    setSelectedAgent(agent.registration.agent_id);
                    setAgentMenu({
                      x: event.clientX,
                      y: event.clientY,
                      agentId: agent.registration.agent_id
                    });
                  }}
                >
                  <td><span className={`pill ${statusClass[agent.status]}`}>{agent.status.toUpperCase()}</span></td>
                  <td className="code">{agent.registration.agent_id}</td>
                  <td>{agent.registration.hostname} / {agent.registration.os}</td>
                  <td>{agent.registration.architecture}</td>
                  <td>{unixTime(agent.last_seen_unix)}</td>
                </tr>
              ))}
              {agents.length === 0 ? (
                <tr>
                  <td colSpan={5} className="empty-cell">No agents have checked in.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        {agentMenu ? (
          <div className="context-menu" style={{ left: agentMenu.x, top: agentMenu.y }}>
            <button type="button" onClick={() => removeAgent(agentMenu.agentId)}>
              <FaTrash size={12} /> Remove Agent
            </button>
          </div>
        ) : null}
      </section>

      <section className="panel event-viewer-panel">
        <div className="panel-title">
          <FaStream size={18} />
          <h2>Event Viewer</h2>
        </div>
        <div className="event-list">
          {eventItems.map((event, index) => (
            <div className="event-row" key={`${event.time}-${index}`}>
              <time>{unixTime(event.time)}</time>
              <span className={`event-kind ${event.kind}`}>{event.kind}</span>
              <p>{event.text}</p>
            </div>
          ))}
          {eventItems.length === 0 ? <div className="empty-state">No activity yet.</div> : null}
        </div>
      </section>

      <section className="panel session-panel">
        <div className="session-tabs">
          <button className={activeTab === "console" ? "active" : ""} type="button" onClick={() => setActiveTab("console")}>
            <FaTerminal size={13} /> Console
          </button>
          <button className={activeTab === "files" ? "active" : ""} type="button" onClick={() => setActiveTab("files")}>
            <FaFolderOpen size={13} /> File Explorer
          </button>
          <div className="session-target">
            {activeAgent ? `${activeAgent.registration.hostname} / ${activeAgent.registration.os}` : "no agent selected"}
          </div>
        </div>

        {activeTab === "console" ? (
          <div className="console-session">
            <div className="console-output code">
              {consoleRows.map((row) => row.type === "local" ? (
                <div className="console-entry local" key={row.entry.id}>
                  <div className="console-line meta">
                    <span>{unixTime(row.entry.createdAt)}</span>
                    <span className="event-kind success">local</span>
                  </div>
                  <div className="console-line prompt">
                    <span>operator &gt;</span>
                    <strong>{row.entry.input}</strong>
                  </div>
                  <pre>{row.entry.output}</pre>
                </div>
              ) : (
                <div className="console-entry" key={row.task.task.task_id}>
                  <div className="console-line meta">
                    <span>{unixTime(row.task.created_at_unix)}</span>
                    <span className={`event-kind ${row.task.status}`}>{row.task.status}</span>
                  </div>
                  <div className="console-line prompt">
                    <span>{activeAgent?.registration.hostname ?? (selectedAgent || "agent")} &gt;</span>
                    <strong>{commandText(row.task)}</strong>
                  </div>
                  <pre>{outputText(row.task)}</pre>
                </div>
              ))}
              {consoleRows.length === 0 ? <div className="empty-state">Send a command to start a session log.</div> : null}
            </div>

            <form className="console-command-bar prompt-bar" onSubmit={sendCommand}>
              <span className="console-prompt-label">{activeAgent?.registration.hostname ?? (selectedAgent || "agent")} &gt;</span>
              <input
                value={consoleInput}
                onChange={(event) => setConsoleInput(event.target.value)}
                placeholder="help, whoami, shell ipconfig, ls C:\\Users, download C:\\Temp\\a.txt"
                spellCheck={false}
                autoComplete="off"
                autoFocus
              />
              <input id="console-upload-input" type="file" onChange={uploadFromConsole} hidden />
            </form>
          </div>
        ) : (
          <FileBrowser
            agentId={selectedAgent}
            platform={platform}
            tasks={tasks}
            responses={responses}
            loading={loading}
            queueTask={queueAgentTask}
            embedded
          />
        )}
      </section>
    </div>
  );
}
