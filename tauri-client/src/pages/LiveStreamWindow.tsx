import { useEffect, useRef, useState } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";

type Params = {
  agentId: string;
  taskId: string;
  type: string;
  baseUrl: string;
  token: string;
};

function readParams(): Params | null {
  const search = new URLSearchParams(window.location.search);
  const agentId = search.get("agentId");
  const taskId = search.get("taskId");
  const type = search.get("type");
  const baseUrl = search.get("baseUrl");
  const token = search.get("token");
  if (!agentId || !taskId || !type || !baseUrl) return null;
  return { agentId, taskId, type, baseUrl, token: token ?? "" };
}

export function LiveStreamWindow() {
  const params = readParams();
  const [frameUrl, setFrameUrl] = useState<string | null>(null);
  const [audioUrl, setAudioUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stopping, setStopping] = useState(false);
  const [ended, setEnded] = useState(false);
  const frameUrlRef = useRef<string | null>(null);
  const audioUrlRef = useRef<string | null>(null);

  const isVideo = params?.type === "stream_display" || params?.type === "stream_camera";
  const label = params ? params.type.replace("stream_", "") : "";

  useEffect(() => {
    frameUrlRef.current = frameUrl;
  }, [frameUrl]);
  useEffect(() => {
    audioUrlRef.current = audioUrl;
  }, [audioUrl]);

  useEffect(() => {
    if (frameUrlRef.current) URL.revokeObjectURL(frameUrlRef.current);
    if (audioUrlRef.current) URL.revokeObjectURL(audioUrlRef.current);
  }, []);

  const stoppedRef = useRef(false);

  useEffect(() => {
    if (!params) {
      setError("missing stream parameters");
      return;
    }
    let cancelled = false;
    let timer = 0;
    let consecutiveErrors = 0;
    let sawFrame = false;
    const startedAt = Date.now();
    const headers: Record<string, string> = {};
    if (params.token.trim()) headers.Authorization = `Bearer ${params.token.trim()}`;

    const poll = async () => {
      if (stoppedRef.current || cancelled) return;
      try {
        const response = await fetch(
          `${params.baseUrl}/api/stream/${encodeURIComponent(params.agentId)}/${encodeURIComponent(params.taskId)}`,
          { headers }
        );
        if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
        const blob = await response.blob();
        if (cancelled || stoppedRef.current) return;
        const url = URL.createObjectURL(blob);
        if (isVideo) {
          setFrameUrl((prev) => { if (prev) URL.revokeObjectURL(prev); return url; });
        } else {
          setAudioUrl((prev) => { if (prev) URL.revokeObjectURL(prev); return url; });
        }
        sawFrame = true;
        setError(null);
        consecutiveErrors = 0;
      } catch (err) {
        if (cancelled || stoppedRef.current) return;
        consecutiveErrors += 1;
        const waitedMs = Date.now() - startedAt;
        if (!sawFrame && waitedMs < 30000) {
          setError("waiting for first frame");
          return;
        }
        if (sawFrame && consecutiveErrors < 4) {
          return;
        }
        if (consecutiveErrors >= 4) {
          stoppedRef.current = true;
          setEnded(true);
          setError(err instanceof Error ? err.message : "stream ended");
          return;
        }
      } finally {
        if (!cancelled && !stoppedRef.current) {
          timer = window.setTimeout(poll, 200);
        }
      }
    };
    poll();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleStop() {
    if (!params || stopping || stoppedRef.current) return;
    stoppedRef.current = true;
    setStopping(true);
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (params.token.trim()) headers.Authorization = `Bearer ${params.token.trim()}`;
    try {
      await fetch(`${params.baseUrl}/api/tasks`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          agent_id: params.agentId,
          task: { task_id: `task-${Date.now()}`, command: "stream_stop", arguments: [] },
        }),
      });
    } catch { /* ignore */ }
    setEnded(true);
  }

  async function handleClose() {
    if (!ended) {
      await handleStop();
    }
    getCurrentWebviewWindow().close().catch(() => { /* ignore */ });
  }

  if (!params) {
    return <div className="live-window-error">missing stream parameters</div>;
  }

  return (
    <div className="live-window-root">
      <header className="live-window-header">
        <span className="live-dot" /> Live {label} · {params.taskId.slice(0, 12)}
        <div className="live-window-actions">
          {!ended ? (
            <button type="button" className="live-stop-btn" onClick={handleStop} disabled={stopping}>
              {stopping ? "stopping…" : "Stop"}
            </button>
          ) : null}
          <button type="button" className="live-close-btn" onClick={handleClose}>
            Close
          </button>
        </div>
      </header>
      <div className="live-window-body">
        {error && ended ? (
          <div className="task-output-error">stream ended · {error}</div>
        ) : error && !frameUrl && !audioUrl ? (
          <div className="task-output-loading">{error}…</div>
        ) : isVideo ? (
          frameUrl ? (
            <img className="live-window-image" src={frameUrl} alt={`live ${label}`} />
          ) : (
            <div className="task-output-loading">connecting to live stream…</div>
          )
        ) : audioUrl ? (
          <audio controls autoPlay src={audioUrl} className="live-window-audio" />
        ) : (
          <div className="task-output-loading">connecting to live stream…</div>
        )}
      </div>
    </div>
  );
}
