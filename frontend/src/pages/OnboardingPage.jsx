import React, { useCallback, useEffect, useState } from "react";
import { PageHeader, GlassCard, CodeBlock, Empty, PlainBadge, PulseDot } from "../components/ui";
import { getAgents, mintAgent, revokeAgent, isPreview, apiOrigin } from "../lib/api";

// Point the generated config at the host the API is actually deployed on —
// window.location.origin is wrong for tunnel/tunnel-fronted deploys and
// becomes unusable garbage on the GitHub Pages preview.
const HOST_HINT = apiOrigin || "https://<your-trinetra-host>";

function fmtAgo(iso) {
  if (!iso) return "never used";
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return "—";
  const delta = Math.max(0, Math.round((Date.now() - then.getTime()) / 1000));
  if (delta < 60) return "just now";
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}

const OS_TABS = [
  { id: "macos", label: "macOS" },
  { id: "linux", label: "Linux" },
  { id: "windows", label: "Windows" },
];

// Each tab's collector block keeps ONLY the platform's collector enabled so
// the shipped config doesn't try (and fail) to initialize others.
const COLLECTOR_BLOCK = {
  macos: `  macos_unified_log:
    enabled: true
    log_levels: [critical, error, warning, notice, info]
  macos_system_log:
    enabled: true
  linux_journald:
    enabled: false
  windows_event_log:
    enabled: false
  file_log:
    enabled: false`,
  linux: `  linux_journald:
    enabled: true
    log_levels: [critical, error, warning, notice, info]
  macos_unified_log:
    enabled: false
  macos_system_log:
    enabled: false
  windows_event_log:
    enabled: false
  file_log:
    enabled: false`,
  windows: `  windows_event_log:
    enabled: true
    channels: [Security, System, Application]
  macos_unified_log:
    enabled: false
  macos_system_log:
    enabled: false
  linux_journald:
    enabled: false
  file_log:
    enabled: false`,
};

const INSTALL_CMDS = {
  macos: `# from the systemlog-agent repo
python3 -m venv .venv && .venv/bin/pip install -e .
# paste the config.yaml below, then run (optionally via launchd):
.venv/bin/log-agent --config /etc/trinetra-agent.yaml`,
  linux: `# from the systemlog-agent repo
python3 -m venv .venv && .venv/bin/pip install -e .
mkdir -p /etc/trinetra && cp config.yaml /etc/trinetra/config.yaml
# paste the config.yaml below (edit /etc/trinetra/config.yaml), then as root:
cat > /etc/systemd/system/systemlog-agent.service <<'EOF'
[Unit]
Description=System Log Agent (Trinetra)
After=network-online.target

[Service]
ExecStart=/opt/systemlog-agent/.venv/bin/log-agent --config /etc/trinetra/config.yaml
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now systemlog-agent`,
  windows: `# from the systemlog-agent repo (PowerShell, admin)
python -m venv .venv; .venv\\Scripts\\pip install -e .
# paste the config.yaml below next to the agent, then register as a service:
.venv\\Scripts\\log-agent --service install
.venv\\Scripts\\log-agent --service start`,
};

export default function OnboardingPage() {
  const [agents, setAgents] = useState(null);
  const [error, setError] = useState(null);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [minted, setMinted] = useState(null); // { token_id, token, client_id }
  const [tab, setTab] = useState("macos");

  const load = useCallback(() => {
    if (isPreview) { setAgents([]); return; }
    getAgents()
      .then((d) => setAgents(d.agents || []))
      .catch((e) => setError(e.response?.data?.detail || e.message));
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleMint = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await mintAgent(label.trim());
      setMinted(res);
      setLabel("");
      load();
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    } finally {
      setBusy(false);
    }
  };

  const handleRevoke = async (tokenId) => {
    if (!window.confirm(`Revoke token ${tokenId}?\nMachines using it will be rejected at the next heartbeat/ingest.`)) return;
    try {
      await revokeAgent(tokenId);
      if (minted?.token_id === tokenId) setMinted(null);
      load();
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    }
  };

  const clientId = minted?.client_id || label.trim() || "my-machine";
  const token = minted?.token || "<YOUR-TOKEN>";
  const snippet = buildConfigSnippet({ origin: HOST_HINT, token, label: clientId, os: tab });

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Fleet · Onboarding"
        title={
          <>
            Onboard <span className="text-grad-emerald">machines</span>
          </>
        }
        sub="Mint a per-machine token and drop the generated config onto the agent. Agents appear in the fleet once they send their first heartbeat."
        actions={
          <PlainBadge cls="!text-emerald-300">
            <PulseDot /> 3 target platforms
          </PlainBadge>
        }
      />

      {isPreview && (
        <div className="rounded-xl border border-white/5 bg-white/[0.03] px-4 py-3 text-[11px] leading-relaxed text-slate-400">
          Preview builds are read-only — minting tokens requires the live TriNetra API.
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-rose-500/25 bg-rose-500/[0.07] px-4 py-3 text-[11px] text-rose-200">
          <span className="mono font-semibold tracking-widest text-rose-300">ERROR</span> {error}
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        {/* ------------------------------------------------ mint token */}
        <GlassCard title="1 · Mint a machine token">
          <div className="space-y-3">
            <div>
              <label className="eyebrow mb-1.5 block">Machine label (friendly name)</label>
              <div className="flex gap-2">
                <input
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleMint()}
                  placeholder="e.g. workshop-mbp, prod-api-01"
                  disabled={isPreview || busy}
                  className="field mono flex-1 px-3 py-2 text-[12px]"
                />
                <button
                  onClick={handleMint}
                  disabled={isPreview || busy}
                  className="btn-primary shrink-0"
                >
                  {busy ? "MINTING…" : "Generate token"}
                </button>
              </div>
              <p className="mt-1 text-[10px] text-slate-600">
                Shown exactly once — the dashboard only stores a hash. The machine's first heartbeat binds it to this name in the fleet.
              </p>
            </div>

            {minted && (
              <div className="space-y-3 rounded-xl border border-amber-500/30 bg-amber-500/[0.07] p-3 anim-fadeup">
                <p className="mono text-[11px] font-semibold uppercase tracking-widest text-amber-300">
                  Copy this token now — it won't be shown again
                </p>
                <div className="flex items-center gap-2">
                  <code className="mono flex-1 overflow-x-auto rounded-md border border-white/10 bg-black/40 px-3 py-2 text-[11px] text-amber-100">
                    {minted.token}
                  </code>
                  <CopyButton text={minted.token} label="Copy" />
                </div>
                <div className="flex flex-wrap gap-2 text-[10px] text-slate-500">
                  <span className="mono">token id: {minted.token_id}</span>
                  {minted.client_id && <span className="mono">client: {minted.client_id}</span>}
                </div>
              </div>
            )}
          </div>
        </GlassCard>

        {/* ------------------------------------------------ active tokens */}
        <GlassCard
          title="2 · Active machine tokens"
          right={<button onClick={load} className="text-[10px] uppercase tracking-widest text-slate-500 transition hover:text-emerald-300">refresh</button>}
        >
          {agents === null ? (
            <p className="text-[13px] text-slate-500">Loading tokens…</p>
          ) : agents.length === 0 ? (
            <Empty
              title="No machine tokens yet"
              hint="Mint one in step 1, or agents can keep using the shared token configured on the server."
            />
          ) : (
            <div className="space-y-2">
              {agents.map((a) => {
                const revoked = a.enabled === 0;
                return (
                  <div
                    key={a.token_id}
                    className={`glass-row flex flex-wrap items-center gap-3 px-3 py-2.5 ${revoked ? "opacity-50" : ""}`}
                  >
                    <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${revoked ? "bg-rose-400" : (a.client_id ? "bg-emerald-400" : "bg-slate-600")}`} />
                    <div className="min-w-0 flex-1">
                      <p className={`mono truncate text-[12px] font-semibold ${revoked ? "text-slate-500 line-through" : "text-slate-200"}`}>
                        {(a.label && `${a.label}`) || <span className="text-slate-500">(untitled)</span>}
                      </p>
                      <p className="mono truncate text-[10px] text-slate-500">
                        {a.token_id} · {revoked
                          ? <span className="text-rose-400/80">revoked</span>
                          : (a.client_id ? `bound to ${a.client_id}` : "unbound")}
                      </p>
                    </div>
                    <span className="mono text-[10px] text-slate-600">used {fmtAgo(a.last_used || a.last_used_at || a.created_at)}</span>
                    {revoked ? (
                      <PlainBadge cls="!text-rose-300">revoked</PlainBadge>
                    ) : (
                      !isPreview && (
                        <button
                          onClick={() => handleRevoke(a.token_id)}
                          className="rounded-md border border-rose-500/30 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-widest text-rose-300 transition hover:bg-rose-500/10"
                        >
                          revoke
                        </button>
                      )
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </GlassCard>
      </div>

      {/* ------------------------------------------------ install snippets */}
      <GlassCard
        title="3 · Install agent (pick your platform)"
        right={
          <div className="flex items-center gap-1.5">
            {OS_TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`chip ${tab === t.id ? "chip-on" : ""}`}
              >
                {t.label}
              </button>
            ))}
          </div>
        }
      >
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-3">
            <div>
              <p className="eyebrow mb-1.5">Install &amp; run</p>
              <CodeBlock>{INSTALL_CMDS[tab]}</CodeBlock>
            </div>
            <p className="text-[11px] leading-relaxed text-slate-500">
              Replace the server URL and token in step 1's config below. The agent heartbeats to{" "}
              <code className="mono text-slate-400">/api/agent/heartbeat</code> automatically — no extra config needed.
              Network hiccups are buffered and retried with exponential backoff, so no logs are lost on a flaky link.
            </p>
          </div>
          <div>
            <p className="eyebrow mb-1.5">config.yaml ← paste over the shipped one</p>
            <CodeBlock maxH="max-h-72">
              <CopyButton text={snippet} label="Copy config" float />
              {snippet}
            </CodeBlock>
          </div>
        </div>
      </GlassCard>
    </div>
  );
}

function buildConfigSnippet({ origin, token, label, os }) {
  return `# systemlog-agent config.yaml — forwarding ${label} to TriNetra
agent:
  hostname_override: "${label}"      # unique machine name shown in the fleet
  poll_interval: 10
  heartbeat_interval: 60             # keeps this box "online" in the dashboard

collectors:
${COLLECTOR_BLOCK[os]}

output:
  type: "http"
  url: "${origin}/api/ingest-events"
  auth_token: "${token}"             # per-machine token from step 1
# the heartbeat URL is derived from url automatically

service:
  macos:
    program: "/usr/local/bin/log-agent"
    run_at_load: true
    keep_alive: true
`;
}

function CopyButton({ text, label = "Copy", float = false }) {
  const [copied, setCopied] = useState(false);
  const copy = async (e) => {
    e?.preventDefault();
    e?.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button
      onClick={copy}
      className={`rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-widest text-emerald-300 transition hover:bg-emerald-500/20 ${
        float ? "sticky top-1 z-10 float-right ml-2" : "shrink-0"
      }`}
    >
      {copied ? "Copied ✓" : label}
    </button>
  );
}