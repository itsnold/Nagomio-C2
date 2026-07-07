import { createContext, useContext, useState, useEffect, useMemo, useRef, useCallback, ReactNode } from "react";

export type AgentStatus = "online" | "stale" | "offline";
export type TaskStatus = "queued" | "dispatched" | "completed" | "failed";
export type ConnectionState = "online" | "syncing" | "offline";
export type NotificationKind = "success" | "error" | "info" | "warning";

export type AppNotification = {
  id: string;
  kind: NotificationKind;
  title: string;
  detail?: string;
  createdAt: number;
};

export type AgentSummary = {
  registration: {
    agent_id: string;
    hostname: string;
    os: string;
    architecture: string;
  };
  first_seen_unix: number;
  last_seen_unix: number;
  status: AgentStatus;
};

export type TaskRecord = {
  agent_id: string;
  task: {
    task_id: string;
    command: string;
    arguments: string[];
  };
  status: TaskStatus;
  created_at_unix: number;
  dispatched_at_unix: number | null;
  completed_at_unix: number | null;
};

export type AgentResponse = {
  agent_id: string;
  task_id: string | null;
  output: string;
  status: string;
};

export type PayloadArtifact = {
  build_id: string;
  label: string | null;
  binary_path: string;
  callback_url: string;
  sleep_seconds: number;
  jitter_percent: number;
  agent_id: string | null;
  agent_token_configured: boolean;
  stealth: boolean;
  anti_debug: boolean;
  anti_vm?: boolean;
  anti_sandbox?: boolean;
  daemonize: boolean;
  static_runtime: boolean;
  xor_config: boolean;
  xor_key: number;
  target_os: string;
  run_args: string[];
  created_at_unix: number;
  kill_date_epoch?: number;
  ua_randomize?: boolean;
  sleep_obfuscate?: boolean;
  encrypt_payload?: boolean;
  wire_encryption?: boolean;
  profile?: string;
  sni_override?: string | null;
};

export type AuditEntry = {
  id: number;
  timestamp_unix: number;
  source_ip: string;
  action: string;
  agent_id: string | null;
  task_id: string | null;
};

export type OperationsStats = {
  agentsTotal: number;
  agentsOnline: number;
  agentsStale: number;
  agentsOffline: number;
  tasksQueued: number;
  tasksDispatched: number;
  tasksCompleted: number;
  tasksFailed: number;
};

interface AppState {
  baseUrl: string;
  setBaseUrl: (val: string) => void;
  apiToken: string;
  setApiToken: (val: string) => void;
  agents: AgentSummary[];
  tasks: TaskRecord[];
  responses: Record<string, AgentResponse[]>;
  payloads: PayloadArtifact[];
  setPayloads: React.Dispatch<React.SetStateAction<PayloadArtifact[]>>;
  message: string;
  setMessage: (val: string) => void;
  connectionState: ConnectionState;
  connectionError: string | null;
  lastSyncAt: number | null;
  latencyMs: number | null;
  stats: OperationsStats;
  notifications: AppNotification[];
  notify: (notification: Omit<AppNotification, "id" | "createdAt">) => void;
  dismissNotification: (id: string) => void;
  loading: boolean;
  setLoading: (val: boolean) => void;
  refresh: () => Promise<void>;
  api: <T>(path: string, init?: RequestInit) => Promise<T>;
  apiBlob: (path: string) => Promise<Blob>;
}

const AppContext = createContext<AppState | undefined>(undefined);

export function AppProvider({ children }: { children: ReactNode }) {
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:8080");
  const [apiToken, setApiToken] = useState("");
  const [agents, setAgents] = useState<AgentSummary[]>([]);
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [responses, setResponses] = useState<Record<string, AgentResponse[]>>({});
  const [payloads, setPayloads] = useState<PayloadArtifact[]>([]);
  const [message, setMessage] = useState("Not connected");
  const [connectionState, setConnectionState] = useState<ConnectionState>("offline");
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [lastSyncAt, setLastSyncAt] = useState<number | null>(null);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [loading, setLoading] = useState(false);
  const refreshInFlight = useRef(false);
  const lastRefreshError = useRef<string | null>(null);

  const headers = useMemo(() => {
    const result: Record<string, string> = { "Content-Type": "application/json" };
    if (apiToken.trim()) result.Authorization = `Bearer ${apiToken.trim()}`;
    return result;
  }, [apiToken]);

  const api = useCallback(async function api<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${baseUrl}${path}`, {
      ...init,
      headers: {
        ...headers,
        ...(init?.headers ?? {})
      }
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `${response.status} ${response.statusText}`);
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return response.json() as Promise<T>;
  }, [baseUrl, headers]);

  const apiBlob = useCallback(async function apiBlob(path: string): Promise<Blob> {
    const response = await fetch(`${baseUrl}${path}`, { headers });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `${response.status} ${response.statusText}`);
    }
    return response.blob();
  }, [baseUrl, headers]);

  function notify(notification: Omit<AppNotification, "id" | "createdAt">) {
    const item: AppNotification = {
      ...notification,
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      createdAt: Date.now()
    };
    setNotifications((current) => [item, ...current].slice(0, 5));
    window.setTimeout(() => {
      setNotifications((current) => current.filter((existing) => existing.id !== item.id));
    }, notification.kind === "error" ? 9000 : 6000);
  }

  function dismissNotification(id: string) {
    setNotifications((current) => current.filter((notification) => notification.id !== id));
  }

  function pushMessage(val: string) {
    setMessage(val);
    const lower = val.toLowerCase();
    const kind: NotificationKind = lower.includes("fail") || lower.includes("error") || lower.includes("refused")
      ? "error"
      : lower.includes("clear")
        ? "info"
        : "success";
    notify({ kind, title: val });
  }

  async function refresh() {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    const startedAt = performance.now();
    setConnectionState((current) => current === "online" ? "syncing" : current);
    setLoading(true);
    try {
      const [nextAgents, nextTasks, nextResponses, nextPayloads] = await Promise.all([
        api<AgentSummary[]>("/api/agents"),
        api<TaskRecord[]>("/api/tasks"),
        api<Record<string, AgentResponse[]>>("/api/responses"),
        api<PayloadArtifact[]>("/api/payload/artifacts")
      ]);
      setAgents(nextAgents);
      setTasks(nextTasks);
      setResponses(nextResponses);
      setPayloads(nextPayloads);
      setMessage("Connected to Teamserver");
      setConnectionState("online");
      setConnectionError(null);
      setLastSyncAt(Date.now());
      setLatencyMs(Math.round(performance.now() - startedAt));
      lastRefreshError.current = null;
    } catch (error) {
      const nextError = error instanceof Error ? error.message : "Request failed";
      setMessage(nextError);
      setConnectionState("offline");
      setConnectionError(nextError);
      setLatencyMs(null);
      if (lastRefreshError.current !== nextError) {
        notify({ kind: "error", title: "Teamserver unavailable", detail: nextError });
        lastRefreshError.current = nextError;
      }
    } finally {
      refreshInFlight.current = false;
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => window.clearInterval(timer);
  }, [baseUrl, apiToken]);

  const stats = useMemo<OperationsStats>(() => ({
    agentsTotal: agents.length,
    agentsOnline: agents.filter((agent) => agent.status === "online").length,
    agentsStale: agents.filter((agent) => agent.status === "stale").length,
    agentsOffline: agents.filter((agent) => agent.status === "offline").length,
    tasksQueued: tasks.filter((task) => task.status === "queued").length,
    tasksDispatched: tasks.filter((task) => task.status === "dispatched").length,
    tasksCompleted: tasks.filter((task) => task.status === "completed").length,
    tasksFailed: tasks.filter((task) => task.status === "failed").length
  }), [agents, tasks]);

  return (
    <AppContext.Provider value={{ baseUrl, setBaseUrl, apiToken, setApiToken, agents, tasks, responses, payloads, setPayloads, message, setMessage: pushMessage, connectionState, connectionError, lastSyncAt, latencyMs, stats, notifications, notify, dismissNotification, loading, setLoading, refresh, api, apiBlob }}>
      {children}
    </AppContext.Provider>
  );
}

export function useAppState() {
  const context = useContext(AppContext);
  if (context === undefined) {
    throw new Error("useAppState must be used within an AppProvider");
  }
  return context;
}

export const statusClass = {
  online: "good",
  stale: "warn",
  offline: "muted",
  queued: "muted",
  dispatched: "warn",
  completed: "good",
  failed: "bad"
};

export function unixTime(value: number | null): string {
  if (!value) return "-";
  return new Date(value * 1000).toLocaleString();
}
