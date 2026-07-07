import React, { useEffect, useMemo, useState } from "react";
import { FaFolderOpen, FaLaptopCode, FaStream, FaTerminal, FaTrash } from "react-icons/fa";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import { FileBrowser } from "../components/FileBrowser";
import { useAppState, statusClass, unixTime, TaskRecord } from "../components/AppContext";
import { platformFromAgentOs } from "../lib/commandCatalog";
import { helpText, parseConsoleCommand } from "../lib/consoleCommands";

function useLiveStreamAutoClose(liveStreams: Record<string, { agentId: string; taskId: string; type: string }>, tasks: TaskRecord[], setLiveStreams: React.Dispatch<React.SetStateAction<Record<string, { agentId: string; taskId: string; type: string }>>>, setMessage: (v: string) => void) {
  useEffect(() => {
    let cancelled = false;
    (async () => {
      for (const meta of Object.values(liveStreams)) {
        const task = tasks.find((t) => t.task.task_id === meta.taskId);
        if (!task) continue;
        if (task.status === "completed" || task.status === "failed") {
          try { (await WebviewWindow.getByLabel(`live-${meta.taskId}`))?.close(); } catch { /* ignore */ }
          if (cancelled) return;
          setLiveStreams((prev) => { const n = { ...prev }; delete n[meta.taskId]; return n; });
          setMessage(`live ${meta.type.replace("stream_", "")} stream ended`);
        }
      }
    })();
    return () => { cancelled = true; };
  }, [tasks, liveStreams, setLiveStreams, setMessage]);
}

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
  const { agents, tasks, responses, api, refresh, setMessage, loading, setLoading, baseUrl, apiToken } = useAppState();
  const [selectedAgent, setSelectedAgent] = useState("");
  const [consoleInput, setConsoleInput] = useState("");
  const [localEntries, setLocalEntries] = useState<LocalConsoleEntry[]>([
    { id: "welcome", input: "help", output: helpText(), createdAt: Math.floor(Date.now() / 1000) }
  ]);
  const [consoleClearedAt, setConsoleClearedAt] = useState(0);
  const [activeTab, setActiveTab] = useState<SessionTab>("console");
  const [pendingUploadPath, setPendingUploadPath] = useState("");
  const [agentMenu, setAgentMenu] = useState<AgentMenu>(null);
  const [liveStreams, setLiveStreams] = useState<Record<string, { agentId: string; taskId: string; type: string }>>({});

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
  useLiveStreamAutoClose(liveStreams, tasks, setLiveStreams, setMessage);
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
    if (task.task.command === "whoami") return "whoami";
    if (task.task.command === "mem_exec") return `mem_exec ${(task.task.arguments[0] || "").slice(0, 24)}…`;
    if (task.task.command === "portscan") return `portscan ${task.task.arguments[0] || ""} ${task.task.arguments[1] || ""}`;
    if (task.task.command === "persist") return `persist ${(task.task.arguments[0] || "").slice(0, 24)}`;
    if (task.task.command === "uninstall") return `uninstall ${task.task.arguments[0] || ""}`;
    if (task.task.command === "socks") return `socks ${(task.task.arguments[0] || "").slice(0, 24)}`;
    if (task.task.command === "screenshot") return "screenshot";
    if (task.task.command === "clipboard") return "clipboard";
    if (task.task.command === "keylog") return `keylog ${task.task.arguments[0] || ""}`;
    if (task.task.command === "inject") return `inject ${task.task.arguments[0] || ""} ${(task.task.arguments[1] || "").slice(0, 24)}…`;
    if (task.task.command === "lsass") return "lsass";
    if (task.task.command === "record_display") return `record display ${task.task.arguments.slice(0, 3).join(" ") || ""}`;
    if (task.task.command === "record_camera") return `record camera ${task.task.arguments.slice(0, 3).join(" ") || ""}`;
    if (task.task.command === "record_mic") return `record mic ${task.task.arguments[0] || ""}`;
    if (task.task.command === "stream_display") return "stream display (live)";
    if (task.task.command === "stream_camera") return "stream camera (live)";
    if (task.task.command === "stream_mic") return "stream mic (live)";
    if (task.task.command === "stream_stop") return "stream stop";
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

  async function queueAgentTask(command: string, args: string[], label: string, liveType?: string) {
    if (!command.trim()) return;
    if (!selectedAgent) {
      appendLocalEntry(label, "select an agent from the table before sending remote commands");
      return;
    }
    setLoading(true);
    try {
      const taskId = `task-${Date.now()}`;
      await api<TaskRecord>("/api/tasks", {
        method: "POST",
        body: JSON.stringify({
          agent_id: selectedAgent,
          task: {
            task_id: taskId,
            command,
            arguments: args
          }
        })
      });
      if (liveType) {
        const meta = { agentId: selectedAgent, taskId, type: liveType };
        setLiveStreams((prev) => ({ ...prev, [taskId]: meta }));
        openLiveStreamWindow(meta, baseUrl, apiToken);
      }
      await refresh();
      setMessage(`${label} sent to ${selectedAgent}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Command send failed");
    } finally {
      setLoading(false);
    }
  }

  async function stopLiveStream(taskId: string) {
    const meta = liveStreams[taskId];
    if (!meta) return;
    try {
      await api<TaskRecord>("/api/tasks", {
        method: "POST",
        body: JSON.stringify({
          agent_id: meta.agentId,
          task: { task_id: `task-${Date.now()}`, command: "stream_stop", arguments: [] }
        })
      });
      setMessage(`stream stop sent to ${meta.agentId}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "stop failed");
    }
    try {
      (await WebviewWindow.getByLabel(`live-${taskId}`))?.close();
    } catch { /* ignore */ }
    setLiveStreams((prev) => {
      const next = { ...prev };
      delete next[taskId];
      return next;
    });
    await refresh();
  }

  function openLiveStreamWindow(meta: { agentId: string; taskId: string; type: string }, base: string, token: string) {
    const label = `live-${meta.taskId}`;
    const params = new URLSearchParams({
      agentId: meta.agentId,
      taskId: meta.taskId,
      type: meta.type,
      baseUrl: base,
      token: token,
    });
    const url = `${window.location.origin}/live?${params.toString()}`;
    const win = new WebviewWindow(label, {
      url,
      title: `NAGOMIO · Live ${meta.type.replace("stream_", "")} · ${meta.taskId.slice(0, 12)}`,
      width: 760,
      height: 560,
      resizable: true,
      minimizable: true,
      maximizable: true,
    });
    win.once("tauri://error", (e) => setMessage(`live window error: ${String((e as { payload?: unknown }).payload)}`));
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
    const liveTypes = ["stream_display", "stream_camera", "stream_mic"];
    const liveType = liveTypes.includes(result.task.command) ? result.task.command : undefined;
    await queueAgentTask(result.task.command, result.task.arguments, result.label, liveType);
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
      if (parsed.type === "screenshot_bmp") {
        return `Screenshot ${parsed.width}×${parsed.height} (${parsed.size} bytes)\nSaved to ${parsed.saved_path}`;
      }
      if (parsed.type === "stream_started") {
        return `Live stream started (${parsed.type}). Frames are shown in the live viewer above and saved to artifacts when you click Stop.`;
      }
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

  function parsedOutput(task: TaskRecord): unknown | null {
    const response = responseFor(task.task.task_id);
    if (!response) return null;
    try {
      return JSON.parse(response.output);
    } catch {
      return null;
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
                  <TaskOutputView
                    task={row.task}
                    parsed={parsedOutput(row.task) as ParsedResponse | null}
                    fallback={outputText(row.task)}
                  />
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

type ParsedResponse = {
  type?: string;
  width?: number;
  height?: number;
  size?: number;
  saved_path?: string;
  filename?: string;
  path?: string;
  remote_path?: string;
  source?: string;
  destination?: string;
  removed?: number;
  duration_s?: number;
  fps?: number;
  frame_count?: number;
  elapsed_ms?: number;
  sample_rate?: number;
  channels?: number;
  bits_per_sample?: number;
  [key: string]: unknown;
};

function TaskOutputView({ task, parsed, fallback }: { task: TaskRecord; parsed: ParsedResponse | null; fallback: string }) {
  const { apiBlob } = useAppState();
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [imageError, setImageError] = useState<string | null>(null);
  const [audioUrl, setAudioUrl] = useState<string | null>(null);
  const [streamFrames, setStreamFrames] = useState<string[] | null>(null);
  const [currentFrame, setCurrentFrame] = useState(0);
  const [streamError, setStreamError] = useState<string | null>(null);

  const isScreenshot = parsed?.type === "screenshot_bmp" && typeof parsed.saved_path === "string";
  const isStreamVideo = (parsed?.type === "stream_display" || parsed?.type === "stream_camera" || parsed?.type === "record_display" || parsed?.type === "record_camera") && typeof parsed.saved_path === "string";
  const isStreamAudio = (parsed?.type === "stream_mic" || parsed?.type === "record_mic") && typeof parsed.saved_path === "string";
  const playbackFps = (() => {
    const frames = typeof parsed?.frame_count === "number" ? parsed.frame_count : 0;
    const elapsedMs = typeof parsed?.elapsed_ms === "number" ? parsed.elapsed_ms : 0;
    if (frames > 0 && elapsedMs > 0) return frames / (elapsedMs / 1000);
    const fps = typeof parsed?.fps === "number" ? parsed.fps : 0;
    if (fps > 0) return fps;
    const duration = typeof parsed?.duration_s === "number" ? parsed.duration_s : 0;
    if (frames > 0 && duration > 0) return frames / duration;
    return 10;
  })();

  const artifactKey = useMemo(() => {
    if (!isScreenshot && !isStreamVideo && !isStreamAudio) return null;
    const saved = String(parsed!.saved_path);
    const segments = saved.split(/[\\/]/).filter(Boolean);
    const filename = segments.pop() || "unknown";
    const taskId = segments.pop() || task.task.task_id;
    const agentId = segments.pop() || task.agent_id;
    return `/api/artifacts/${encodeURIComponent(agentId)}/${encodeURIComponent(taskId)}/${encodeURIComponent(filename)}`;
  }, [isScreenshot, isStreamVideo, isStreamAudio, parsed, task.task.task_id, task.agent_id]);

  useEffect(() => {
    if (!artifactKey) {
      setImageUrl((prev) => { if (prev) URL.revokeObjectURL(prev); return null; });
      setAudioUrl((prev) => { if (prev) URL.revokeObjectURL(prev); return null; });
      setStreamFrames(null);
      setCurrentFrame(0);
      setImageError(null);
      setStreamError(null);
      return;
    }
    let cancelled = false;

    if (isStreamVideo) {
      setStreamError(null);
      apiBlob(artifactKey)
        .then(async (blob) => {
          if (cancelled) return;
          const buf = await blob.arrayBuffer();
          const view = new DataView(buf);
          let off = 0;
          const magic = String.fromCharCode(...new Uint8Array(buf, off, 4));
          off += 4;
          if (magic !== "MJPF") {
            setStreamError("invalid MJPEG stream");
            return;
          }
          const frameCount = view.getUint32(off, false); off += 4;
          const width = view.getUint32(off, false); off += 4;
          const height = view.getUint32(off, false); off += 4;
          const frames: string[] = [];
          for (let i = 0; i < frameCount && off < buf.byteLength; i++) {
            const size = view.getUint32(off, false); off += 4;
            const jpegBytes = new Uint8Array(buf, off, size);
            off += size;
            const blob = new Blob([jpegBytes], { type: "image/jpeg" });
            const url = URL.createObjectURL(blob);
            frames.push(url);
          }
          if (cancelled) { frames.forEach((u) => URL.revokeObjectURL(u)); return; }
          setStreamFrames(frames);
          setCurrentFrame(0);
        })
        .catch((err: Error) => {
          if (cancelled) return;
          setStreamError(err.message || "failed to load stream");
        });
    } else if (isStreamAudio) {
      setStreamError(null);
      apiBlob(artifactKey)
        .then((blob) => {
          if (cancelled) return;
          setAudioUrl((prev) => { if (prev) URL.revokeObjectURL(prev); return URL.createObjectURL(blob); });
        })
        .catch((err: Error) => {
          if (cancelled) return;
          setStreamError(err.message || "failed to load audio");
        });
    } else {
      setImageError(null);
      apiBlob(artifactKey)
        .then((blob) => {
          if (cancelled) return;
          setImageUrl((prev) => { if (prev) URL.revokeObjectURL(prev); return URL.createObjectURL(blob); });
        })
        .catch((err: Error) => {
          if (cancelled) return;
          setImageError(err.message || "failed to load screenshot");
        });
    }

    return () => { cancelled = true; };
  }, [artifactKey, apiBlob, isStreamVideo, isStreamAudio, isScreenshot]);

  useEffect(() => {
    if (!streamFrames || streamFrames.length === 0) return;
    const interval = window.setInterval(() => {
      setCurrentFrame((prev) => (prev + 1) % streamFrames.length);
    }, Math.max(1, 1000 / playbackFps));
    return () => window.clearInterval(interval);
  }, [streamFrames, playbackFps]);

  useEffect(() => {
    return () => {
      setImageUrl((prev) => { if (prev) URL.revokeObjectURL(prev); return null; });
      setAudioUrl((prev) => { if (prev) URL.revokeObjectURL(prev); return null; });
      setStreamFrames((prev) => {
        if (prev) prev.forEach((u) => URL.revokeObjectURL(u));
        return null;
      });
    };
  }, []);

  if (isScreenshot) {
    return (
      <div className="task-output-screenshot">
        <div className="task-output-screenshot-meta">
          {parsed!.width}×{parsed!.height} · {parsed!.size} bytes · saved to <code>{String(parsed!.saved_path)}</code>
        </div>
        {imageError ? <div className="task-output-error">{imageError}</div> : null}
        {imageUrl ? (
          <a href={imageUrl} download={`screenshot-${task.task.task_id}.bmp`} target="_blank" rel="noreferrer">
            <img className="task-output-image" src={imageUrl} alt={`screenshot from ${task.agent_id}`} />
          </a>
        ) : imageError ? null : (
          <div className="task-output-loading">loading screenshot…</div>
        )}
      </div>
    );
  }

  if (isStreamVideo) {
    const duration = (() => {
      if (typeof parsed!.duration_s === "number" && parsed!.duration_s > 0) return `${parsed!.duration_s}s`;
      if (typeof parsed!.elapsed_ms === "number" && parsed!.elapsed_ms > 0) return `${(parsed!.elapsed_ms / 1000).toFixed(1)}s`;
      return `${(Number(parsed!.frame_count || 0) / playbackFps).toFixed(1)}s`;
    })();
    return (
      <div className="task-output-screenshot">
        <div className="task-output-screenshot-meta">
          {parsed!.width}×{parsed!.height} · {duration} @ {playbackFps.toFixed(1)}fps · {parsed!.frame_count} frames · {parsed!.size} bytes · saved to <code>{String(parsed!.saved_path)}</code>
        </div>
        {streamError ? <div className="task-output-error">{streamError}</div> : null}
        {streamFrames && streamFrames.length > 0 ? (
          <div style={{ position: "relative" }}>
            <img
              className="task-output-image"
              src={streamFrames[currentFrame]}
              alt={`stream frame ${currentFrame + 1}/${streamFrames.length}`}
            />
            <div style={{ marginTop: 4, fontSize: 11, color: "#888" }}>
              frame {currentFrame + 1}/{streamFrames.length}
            </div>
          </div>
        ) : streamError ? null : (
          <div className="task-output-loading">loading stream frames…</div>
        )}
      </div>
    );
  }

  if (isStreamAudio) {
    return (
      <div className="task-output-screenshot">
        <div className="task-output-screenshot-meta">
          {parsed!.duration_s}s · {parsed!.sample_rate}Hz · {parsed!.channels}ch · {parsed!.bits_per_sample}bit · {parsed!.size} bytes · saved to <code>{String(parsed!.saved_path)}</code>
        </div>
        {streamError ? <div className="task-output-error">{streamError}</div> : null}
        {audioUrl ? (
          <audio controls style={{ marginTop: 8, width: "100%", maxWidth: 480 }}>
            <source src={audioUrl} type="audio/wav" />
          </audio>
        ) : streamError ? null : (
          <div className="task-output-loading">loading audio…</div>
        )}
      </div>
    );
  }

  return <pre>{fallback}</pre>;
}
