import React, { useEffect, useMemo, useState } from "react";
import {
  FaDownload,
  FaFile,
  FaFileAlt,
  FaFileArchive,
  FaFileCode,
  FaFileImage,
  FaFilePdf,
  FaFolder,
  FaFolderPlus,
  FaLevelUpAlt,
  FaRedo,
  FaTrash,
  FaUpload
} from "react-icons/fa";
import { AgentResponse, TaskRecord, unixTime } from "./AppContext";
import { AgentPlatform } from "../lib/commandCatalog";

type FileEntry = {
  name: string;
  path: string;
  is_dir: boolean;
  size: number;
};

type FileBrowserProps = {
  agentId: string;
  platform: AgentPlatform;
  tasks: TaskRecord[];
  responses: Record<string, AgentResponse[]>;
  loading: boolean;
  queueTask: (command: string, args: string[], label: string) => Promise<void>;
  embedded?: boolean;
};

type ContextMenu = {
  x: number;
  y: number;
  entry: FileEntry;
} | null;

function toBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error);
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result as ArrayBuffer);
      let binary = "";
      const chunkSize = 0x8000;
      for (let index = 0; index < bytes.length; index += chunkSize) {
        binary += String.fromCharCode(...bytes.slice(index, index + chunkSize));
      }
      resolve(window.btoa(binary));
    };
    reader.readAsArrayBuffer(file);
  });
}

function joinRemotePath(basePath: string, name: string, platform: AgentPlatform): string {
  const separator = platform === "windows" ? "\\" : "/";
  if (!basePath || basePath === ".") return name;
  return `${basePath.replace(/[\\/]+$/, "")}${separator}${name}`;
}

function parentPath(path: string, platform: AgentPlatform): string {
  const separator = platform === "windows" ? "\\" : "/";
  const normalized = path.replace(/[\\/]+$/, "");
  if (platform === "windows") {
    if (/^[A-Za-z]:$/.test(normalized)) {
      return `${normalized}\\`;
    }

    const index = Math.max(normalized.lastIndexOf("/"), normalized.lastIndexOf("\\"));
    if (index <= 2) {
      return `${normalized.slice(0, 2)}\\`;
    }
    return normalized.slice(0, index);
  }

  const index = Math.max(normalized.lastIndexOf("/"), normalized.lastIndexOf("\\"));
  if (index <= 0) return separator;
  return normalized.slice(0, index);
}

function fileIcon(entry: FileEntry) {
  if (entry.is_dir) return <FaFolder className="file-icon folder" size={15} />;
  const lower = entry.name.toLowerCase();
  if (/\.(png|jpg|jpeg|gif|bmp|webp|svg)$/.test(lower)) return <FaFileImage className="file-icon image" size={15} />;
  if (/\.pdf$/.test(lower)) return <FaFilePdf className="file-icon pdf" size={15} />;
  if (/\.(zip|rar|7z|tar|gz|bz2|xz)$/.test(lower)) return <FaFileArchive className="file-icon archive" size={15} />;
  if (/\.(js|ts|tsx|jsx|rs|cpp|c|h|hpp|py|ps1|sh|bat|cmd|json|html|css|xml|yaml|yml)$/.test(lower)) {
    return <FaFileCode className="file-icon code-file" size={15} />;
  }
  if (/\.(txt|md|log|csv|ini|conf)$/.test(lower)) return <FaFileAlt className="file-icon text-file" size={15} />;
  return <FaFile className="file-icon" size={15} />;
}

export function FileBrowser({ agentId, platform, tasks, responses, loading, queueTask, embedded = false }: FileBrowserProps) {
  const [currentPath, setCurrentPath] = useState(platform === "windows" ? "C:\\" : ".");
  const [menu, setMenu] = useState<ContextMenu>(null);

  useEffect(() => {
    setCurrentPath(platform === "windows" ? "C:\\" : ".");
    setMenu(null);
  }, [agentId, platform]);

  const listState = useMemo(() => {
    const responseList = Object.values(responses).flat();
    const listTasks = tasks
      .filter((task) => task.agent_id === agentId && task.task.command === "__nagomio_file_list")
      .sort((left, right) => right.created_at_unix - left.created_at_unix);

    for (const task of listTasks) {
      const response = responseList.find((item) => item.task_id === task.task.task_id);
      if (!response) {
        return { pending: true, path: task.task.arguments[0] || currentPath, entries: [] as FileEntry[], updated: task.created_at_unix };
      }
      try {
        const parsed = JSON.parse(response.output);
        if (parsed.type === "file_list" && Array.isArray(parsed.entries)) {
          const entries = parsed.entries as FileEntry[];
          entries.sort((left, right) => Number(right.is_dir) - Number(left.is_dir) || left.name.localeCompare(right.name));
          return { pending: false, path: parsed.path as string, entries, updated: task.completed_at_unix ?? task.created_at_unix };
        }
      } catch {
        return { pending: false, path: task.task.arguments[0] || currentPath, entries: [] as FileEntry[], updated: task.completed_at_unix ?? task.created_at_unix };
      }
    }

    return { pending: false, path: currentPath, entries: [] as FileEntry[], updated: null as number | null };
  }, [agentId, currentPath, responses, tasks]);

  async function list(path = currentPath) {
    setCurrentPath(path);
    await queueTask("__nagomio_file_list", [path], `List ${path}`);
  }

  async function upload(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    const content = await toBase64(file);
    const remotePath = joinRemotePath(currentPath, file.name, platform);
    await queueTask("__nagomio_file_upload", [remotePath, content], `Upload ${file.name}`);
  }

  async function rename(entry: FileEntry) {
    const nextName = window.prompt("Rename to", entry.name);
    if (!nextName?.trim()) return;
    await queueTask("__nagomio_file_rename", [entry.path, joinRemotePath(currentPath, nextName.trim(), platform)], `Rename ${entry.name}`);
  }

  async function remove(entry: FileEntry) {
    if (!window.confirm(`Delete ${entry.path}?`)) return;
    await queueTask("__nagomio_file_delete", [entry.path], `Delete ${entry.name}`);
  }

  async function mkdir() {
    const name = window.prompt("Directory name");
    if (!name?.trim()) return;
    await queueTask("__nagomio_file_mkdir", [joinRemotePath(currentPath, name.trim(), platform)], `Create ${name.trim()}`);
  }

  const Wrapper = embedded ? "div" : "section";

  return (
    <Wrapper className={embedded ? "file-browser-view" : "panel file-browser-panel"} onClick={() => setMenu(null)}>
      {!embedded ? (
        <div className="panel-title split-title">
          <div>
            <FaFolderPlus size={18} />
            <h2>File Browser</h2>
          </div>
          <span className="panel-meta">{listState.pending ? "pending" : `updated ${unixTime(listState.updated)}`}</span>
        </div>
      ) : null}

      <div className="file-toolbar">
        <button type="button" disabled={!agentId || loading} onClick={() => list(parentPath(currentPath, platform))}>
          <FaLevelUpAlt size={12} /> Up
        </button>
        <input value={currentPath} onChange={(event) => setCurrentPath(event.target.value)} />
        <button type="button" disabled={!agentId || loading} onClick={() => list()}>
          <FaRedo size={12} /> Refresh
        </button>
        <button type="button" disabled={!agentId || loading} onClick={mkdir}>
          <FaFolderPlus size={12} /> New Folder
        </button>
        <label className={`upload-button ${!agentId || loading ? "disabled" : ""}`}>
          <FaUpload size={12} /> Upload
          <input type="file" disabled={!agentId || loading} onChange={upload} />
        </label>
      </div>

      <div className="file-table">
        <table className="app-table compact allow-select">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Size</th>
            </tr>
          </thead>
          <tbody>
            {listState.entries.map((entry) => (
              <tr
                key={entry.path}
                onDoubleClick={() => entry.is_dir && list(entry.path)}
                onContextMenu={(event) => {
                  event.preventDefault();
                  setMenu({ x: event.clientX, y: event.clientY, entry });
                }}
              >
                <td className="code file-name-cell">{fileIcon(entry)}<span>{entry.name}</span></td>
                <td>{entry.is_dir ? "Directory" : "File"}</td>
                <td>{entry.is_dir ? "-" : entry.size.toLocaleString()}</td>
              </tr>
            ))}
            {listState.entries.length === 0 ? (
              <tr>
                <td colSpan={3} className="empty-cell">Queue a refresh to load this path.</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      {menu ? (
        <div className="context-menu" style={{ left: menu.x, top: menu.y }}>
          {menu.entry.is_dir ? (
            <button type="button" onClick={() => list(menu.entry.path)}>Open</button>
          ) : (
            <button type="button" onClick={() => queueTask("__nagomio_file_download", [menu.entry.path], `Download ${menu.entry.name}`)}>
              <FaDownload size={12} /> Download
            </button>
          )}
          <button type="button" onClick={() => rename(menu.entry)}>Rename</button>
          <button type="button" onClick={() => remove(menu.entry)}><FaTrash size={12} /> Delete</button>
        </div>
      ) : null}
    </Wrapper>
  );
}
