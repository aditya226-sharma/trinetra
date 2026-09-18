import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getDashboard, getClients, getTasks, createTask, patchTask, streamEvents } from "../lib/api";
import { SeverityBadge, LiveBadge, PulseDot, SectionTitle, Empty } from "../components/ui";
import { Donut, Sparkline, ScoreRing } from "../components/charts";

const DONUT_COLORS = ["#34d399", "#22d3ee", "#818cf8", "#fbbf24", "#f472b6", "#f87171", "#60a5fa"];

const PIPELINE = [
  { id: "normalize", label: "Normalize" },
  { id: "dedup", label: "Dedup" },
  { id: "modules", label: "Modules A·B·C" },
  { id: "analyze", label: "Analyzer" },
];

const STATUS_LANES = [
  { key: "open", label: "open", tone: "text-rose-400 border-rose-500/30" },
  { key: "investigation", label: "investigation", tone: "text-amber-400 border-amber-500/30" },
  { key: "closed", label: "closed", tone: "text-emerald-400 border-emerald-500/30" },
];

export default function DashboardPage({ role = "", clientScope = "" }) {
  const [data, setData] = useState(null);
  const [clients, setClients] = useState([]);
  const [error, setError] = useState(null);
  const scoped = Boolean(clientScope) && role !== "admin";
  const adminOnly = role === "admin";

  useEffect(() => {
    let alive = true;
    const tick = () => {
      getDashboard()
        .then((d) => alive && setData(d))
        .catch((e) => alive && setError(e.message));
      // Client list is admin-only: scoped viewers must not fetch (or see) the
      // whole estate's client roster, even if they never render it.
      if (adminOnly) {
        getClients()
          .then((d) => alive && setClients(d.clients || []))
          .catch(() => {});
      }
    };
    tick();
    const id = setInterval(tick, 10000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [adminOnly]);

  if (error) return <div className="text-sm text-rose-400">Failed to load dashboard: {error}</div>;
  if (!data) return <div className="text-slate-500">Loading dashboard…</div>;

  if (scoped || data.scope) {
    return (
      <ScopedDashboard
        data={data}
        scope={data.scope || clientScope}
      />
    );
  }

  return <AdminOverview data={data} clients={clients} />;
}

/* ================================================================== scoped view */
function ScopedDashboard({ data, scope }) {
  const s = data.stats || {};
  const incidents = data.incidents || { open: [], investigation: [], closed: [], stats: {} };
  const threats = data.threat_detections || {};
  const findings = (data.findings || []).slice(-6).reverse();
  const threatVals = Object.values(threats).map(Number);
  const { toast, dismiss } = useLiveChannel(scope);

  const totalIncidents = (incidents.open?.length || 0) + (incidents.investigation?.length || 0) + (incidents.closed?.length || 0);

  return (
    <div className="space-y-6">
      <LiveToast toast={toast} onDismiss={dismiss} />
      {/* scoped portal banner — unmistakably different from the admin command center */}
      <div className="anim-fadeup">
        <div className="flex items-center gap-3 rounded-xl border border-cyan-400/25 bg-gradient-to-r from-cyan-500/10 via-sky-500/5 to-transparent px-5 py-4">
          <span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-400/10 text-xl text-[#67e8f9]">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 01-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 011-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 011.52 0C14.51 3.81 17 5 19 5a1 1 0 011 1z" />
            </svg>
          </span>
          <div className="min-w-0 flex-1">
            <p className="mono text-[10px] uppercase tracking-[0.22em] text-cyan-300">Client portal · scoped workspace</p>
            <h1 className="mt-0.5 text-[22px] font-bold leading-tight tracking-tight text-slate-50">
              <span className="text-[#67e8f9]">{scope}</span>
              <span className="text-slate-400"> · this workspace</span>
            </h1>
            <p className="mt-1 max-w-2xl text-[12.5px] leading-relaxed text-slate-400">
              You are signed in as a <b className="mono text-cyan-200">viewer</b> scoped to{" "}
              <b className="mono text-cyan-200">{scope}</b> — you only see this client's telemetry,
              incidents and SOC tasks. <span className="text-slate-500">Read-only view · managed by the SOC team.</span>
            </p>
          </div>
          <span className="mono shrink-0 rounded-md border border-cyan-400/30 bg-black/30 px-2.5 py-1 text-[10px] uppercase tracking-[0.18em] text-cyan-200">
            scope: {scope}
          </span>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-[10.5px] text-slate-500">
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" /> <b className="mono text-cyan-300">{s.events ?? 0}</b> normalized events
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-400" /> <b className="mono text-amber-300">{s.findings ?? 0}</b> findings
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-rose-400" /> <b className="mono text-rose-300">{totalIncidents}</b> incidents
          </span>
          <span className="ml-auto"><LiveBadge text="Live · 10s" /></span>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <KpiCard label="Events this client" value={s.events ?? 0} sub={`dedup ${Math.round((data.dedup_rate || 0) * 100)}%`} tone="emerald" icon={<ChartIcon />} delay={0} />
        <KpiCard label="Findings" value={s.findings ?? 0} sub="on this workspace" tone="danger" icon={<ThreatIcon />} delay={60} />
        <KpiCard label="Open incidents" value={incidents.open?.length ?? 0} sub="awaiting SOC triage" tone="danger" icon={<GraphIcon />} delay={120} />
        <KpiCard label="Investigation" value={incidents.investigation?.length ?? 0} sub="actively worked" tone="violet" icon={<DedupIcon />} delay={180} />
      </div>

      {/* tasks assigned by the SOC team */}
      <section className="glass p-5 anim-fadeup !border-cyan-400/20 !bg-cyan-950/10">
        <SectionTitle
          right={<span className="mono text-[10px] uppercase tracking-widest text-cyan-300/70">from the SOC team → you</span>}
        >
          Tasks assigned to {scope}
        </SectionTitle>
        <ClientTasks clientId={scope} initial={data.tasks} />
      </section>

      {/* incident board */}
      <section className="glass p-5 anim-fadeup">
        <SectionTitle
          right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">{scope} only</span>}
        >
          Incidents on this workspace
        </SectionTitle>
        <IncidentBoard incidents={incidents} />
      </section>

      {/* threat radar + findings */}
      <div className="grid gap-6 lg:grid-cols-2">
        <section className="glass p-5 anim-fadeup">
          <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">this workspace</span>}>
            Threat radar
          </SectionTitle>
          {Object.keys(threats).length === 0 ? (
            <Empty title="No detections for this client" hint="Detections appear here as flow heuristics fire on this client's traffic." />
          ) : (
            <div className="space-y-3">
              {Object.entries(threats).map(([threat, count], i) => {
                const max = Math.max(...threatVals, 1);
                return (
                  <div key={threat} className="feed-in" style={{ animationDelay: `${i * 60}ms` }}>
                    <div className="mb-1 flex items-center justify-between text-[12px]">
                      <span className="mono text-slate-200">{threat}</span>
                      <span className="mono text-[11px] text-rose-300">{count} hits</span>
                    </div>
                    <div className="relative h-2 overflow-hidden rounded-full bg-white/5">
                      <div className="bar-grow h-full rounded-full" style={{ width: `${(count / max) * 100}%`, background: "linear-gradient(90deg,#0e7490,#22d3ee,#f43f5e)", boxShadow: "0 0 12px rgba(34,211,238,0.4)" }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <section className="glass p-5 anim-fadeup">
          <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">analyzer verdict feed</span>}>
            Latest findings
          </SectionTitle>
          {findings.length === 0 ? (
            <Empty title="No findings yet" hint="Verdicts appear here as the analyzer resolves module findings." />
          ) : (
            <div className="space-y-2">
              {findings.map((f, i) => (
                <FindingRow key={`${f.threat_class}-${f.timestamp}-${i}`} f={f} i={i} sevStrip={sevStrip} />
              ))}
            </div>
          )}
        </section>
      </div>

      {/* read-only footer note */}
      <p className="mono text-center text-[9.5px] uppercase tracking-[0.2em] text-slate-600">
        TriNetra client portal · restricted to {scope} · questions? contact your SOC team
      </p>
    </div>
  );

  function sevStrip(sev) {
    const known = ["critical", "high", "medium", "warning", "error", "info", "low"];
    return `sev-${(known.includes(sev) ? sev : "info")}`;
  }
}

/* ================================================================== admin view */
function AdminOverview({ data, clients }) {
  const s = data.stats || {};
  const threats = data.threat_detections || {};
  const findings = (data.findings || []).slice(-6).reverse();
  const vpn = data.vpn?.profiles || [];
  const incidents = data.incidents || { open: [], investigation: [], closed: [], stats: {} };
  const g = data.graph_summary || {};
  const top = clients.slice().sort((a, b) => (b.events ?? 0) - (a.events ?? 0));
  const eventsSpark = top.map((c) => c.events);
  const threatVals = Object.values(threats).map(Number);
  const { toast, dismiss } = useLiveChannel("");

  return (
    <div className="space-y-6">
      <LiveToast toast={toast} onDismiss={dismiss} />
      {/* header */}
      <div className="anim-fadeup">
        <p className="eyebrow mb-1.5">Command center</p>
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-slate-50">
              Security <span className="text-grad-emerald">overview</span>
            </h1>
            <p className="mt-1 max-w-2xl text-[13px] leading-relaxed text-slate-400">
              Multi-domain intelligence over{" "}
              <b className="mono text-emerald-300">{s.events ?? 0}</b> normalized events with{" "}
              <b className="mono text-amber-300">{s.findings ?? 0}</b> module findings and{" "}
              <b className="mono text-rose-300">{s.alerts_sent ?? 0}</b> alerts fanned out.
            </p>
          </div>
          <LiveBadge text="Live · 10s" />
        </div>
      </div>

      {/* pipeline strip */}
      <div className="glass flex flex-wrap items-center gap-x-2 gap-y-3 px-5 py-4 anim-fadeup">
        {PIPELINE.map((p, i) => (
          <React.Fragment key={p.id}>
            {i > 0 && <span className="text-slate-600">›</span>}
            <span className="flex items-center gap-2">
              <PulseDot />
              <span className="mono text-[11px] uppercase tracking-widest text-emerald-300">{p.label}</span>
            </span>
          </React.Fragment>
        ))}
        <span className="ml-auto mono text-[11px] text-slate-500">
          {top.length} feeds reporting · graph {g.nodes}N/{g.edges}E
        </span>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <KpiCard label="Events ingested" value={s.events ?? 0} sub={`${s.raw_lines ?? 0} raw lines · ${Math.round((data.dedup_rate || 0) * 100)}% dedup`} tone="emerald" icon={<ChartIcon />} spark={{ values: eventsSpark, color: "#34d399" }} delay={0} />
        <KpiCard label="Deduplication rate" value={`${Math.round((data.dedup_rate || 0) * 100)}%`} sub="fingerprint-based corpus" tone="cyan" icon={<DedupIcon />} delay={60} />
        <KpiCard label="Module findings" value={s.findings ?? 0} sub={`${s.alerts_sent ?? 0} alerts sent to analyst queue`} tone="danger" icon={<ThreatIcon />} spark={{ values: threatVals.length ? threatVals : [1], color: "#f43f5e" }} delay={120} />
        <KpiCard label="Entity graph" value={`${g.nodes ?? 0}N / ${g.edges ?? 0}E`} sub={`${g.threatened?.length || 0} assets impacted`} tone="violet" icon={<GraphIcon />} spark={{ values: top.map((c) => c.events), color: "#22d3ee" }} delay={180} />
      </div>

      {/* incident board */}
      <section className="glass p-5 anim-fadeup">
        <SectionTitle
          right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">admin · every client's incidents</span>}
        >
          Incident board
        </SectionTitle>
        <IncidentBoard incidents={incidents} />
      </section>

      {/* assign tasks to clients */}
      <section className="glass p-5 anim-fadeup">
        <SectionTitle
          right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">appears on the client's own dashboard</span>}
        >
          Assign a task to a client
        </SectionTitle>
        <AdminTaskManage clients={clients} initial={data.tasks} />
      </section>

      {/* radar + clients */}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <section className="glass p-5 anim-fadeup">
            <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">Module A · flow heuristics</span>}>
              Threat radar
            </SectionTitle>
            {Object.keys(threats).length === 0 ? (
              <Empty title="No detections recorded" hint="Detections appear here as flow heuristics fire on live agent traffic." />
            ) : (
              <div className="space-y-3">
                {Object.entries(threats).map(([threat, count], i) => {
                  const max = Math.max(...threatVals, 1);
                  return (
                    <div key={threat} className="feed-in" style={{ animationDelay: `${i * 60}ms` }}>
                      <div className="mb-1 flex items-center justify-between text-[12px]">
                        <span className="mono text-slate-200">{threat}</span>
                        <span className="mono text-[11px] text-rose-300">{count} hits</span>
                      </div>
                      <div className="relative h-2 overflow-hidden rounded-full bg-white/5">
                        <div className="bar-grow h-full rounded-full" style={{ width: `${(count / max) * 100}%`, background: "linear-gradient(90deg,#059669,#10b981,#f43f5e)", boxShadow: "0 0 12px rgba(244,63,94,0.5)" }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          {/* latest findings */}
          <section className="glass p-5 anim-fadeup">
            <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">analyzer verdict feed</span>}>
              Latest findings
            </SectionTitle>
            {findings.length === 0 ? (
              <Empty title="No findings yet" hint="Verdicts appear here as the analyzer resolves module findings." />
            ) : (
              <div className="space-y-2">
                {findings.map((f, i) => (
                  <FindingRow key={`${f.threat_class}-${f.timestamp}-${i}`} f={f} i={i} sevStrip={sevStrip} />
                ))}
              </div>
            )}
          </section>
        </div>

        {/* clients + donut */}
        <section className="glass p-5 anim-fadeup lg:row-span-1">
          <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">GET /api/clients</span>}>
            Feed share
          </SectionTitle>
          {top.length === 0 ? (
            <Empty title="No clients reporting" hint="Sensors will appear here once data flows." />
          ) : (
            <>
              <div className="flex justify-center pb-2">
                <Donut size={172} thickness={17} centerValue={s.events ?? 0} centerLabel="events" segments={top.map((c, i) => ({ value: c.events ?? 0, color: DONUT_COLORS[i % DONUT_COLORS.length] }))} />
              </div>
              <div className="mt-2 space-y-1.5">
                {top.map((c, i) => (
                  <div key={c.client_id} className="flex items-center gap-2 text-[12px]">
                    <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: DONUT_COLORS[i % DONUT_COLORS.length], boxShadow: `0 0 8px ${DONUT_COLORS[i % DONUT_COLORS.length]}` }} />
                    <span className="mono truncate text-slate-300">{c.client_id}</span>
                    <span className="text-[10px] text-slate-600">{(c.source_types || [c.source_type]).filter(Boolean).join(", ")}</span>
                    <span className="ml-auto mono tabular-nums text-slate-500">{c.events ?? 0}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </section>
      </div>

      {/* VPN assessment */}
      <section className="glass p-5 anim-fadeup">
        <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">Module B · IPsec posture</span>}>
          VPN / IPsec gateway assessment
        </SectionTitle>
        {vpn.length === 0 ? (
          <Empty title="No tunnel/IPsec posture yet" hint="Live agent tunnel posture or Module B PCAP assessments populate this." />
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {vpn.map((p, i) => {
              const tone = p.risk_level === "critical" ? "#f43f5e" : p.risk_level === "high" ? "#fb923c" : p.risk_level === "medium" ? "#fbbf24" : "#34d399";
              return (
                <div key={p.interface || p.file || i} className="glass-row flex items-center gap-4 p-4 feed-in" style={{ animationDelay: `${i * 70}ms` }}>
                  <ScoreRing score={p.security_score ?? p.score ?? 0} tone={tone} label="score" />
                  <div className="min-w-0 flex-1">
                    <p className="mono truncate text-[13px] text-slate-100">{p.file}</p>
                    <SeverityBadge severity={p.risk_level} />
                    <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-0.5 text-[10.5px] text-slate-400">
                      <span>IKEv{p.ike_version}</span>
                      <span>{p.encryption}/{p.key_length}</span>
                      <span>DH {p.dh_group}</span>
                      <span>PFS {p.pfs}</span>
                      <span>PRF {p.prf || "—"}</span>
                      <span>{p.sa_lifetime}s life</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );

  function sevStrip(sev) {
    const known = ["critical", "high", "medium", "warning", "error", "info", "low"];
    return `sev-${(known.includes(sev) ? sev : "info")}`;
  }
}

/* ================================================================== shared pieces */
function IncidentBoard({ incidents }) {
  const lanes = STATUS_LANES.map((l) => ({
    ...l,
    items: incidents[l.key] || [],
  }));
  return (
    <div>
      <div className="mb-4 grid grid-cols-3 gap-3">
        {lanes.map((l) => (
          <div key={l.key} className="rounded-xl border border-white/5 bg-black/30 p-3">
            <div className={`mb-2 flex items-center justify-between mono text-[10px] uppercase tracking-widest ${l.tone.split(" ")[0]} ${l.tone.split(" ")[1]}`}>
              <span>{l.label}</span>
              <span>{l.items.length}</span>
            </div>
            <div className="space-y-2">
              {l.items.length === 0 ? (
                <p className="mono text-[10px] text-slate-600">—</p>
              ) : (
                l.items.slice(0, 6).map((c) => (
                  <Link
                    key={c.id}
                    to={`/incidents/${c.id}`}
                    className="block w-full rounded-lg border border-white/5 bg-white/[0.03] p-2 text-left transition hover:border-emerald-500/30"
                  >
                    <div className="flex items-center gap-1.5">
                      <SeverityBadge severity={c.severity} />
                      <span className="mono truncate text-[11px] text-slate-200">{c.threat_class}</span>
                    </div>
                    <p className="mono mt-1 truncate text-[9.5px] uppercase tracking-widest text-slate-500">
                      {c.client_id || "—"} · {c.source_kind || "flow"}
                      {c.assignee && <span className="text-emerald-300"> @{c.assignee}</span>}
                    </p>
                    <span className="mono mt-1 block text-[9px] uppercase tracking-widest text-cyan-300/70 hover:text-cyan-200">open incident →</span>
                  </Link>
                ))
              )}
            </div>
</div>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ live alerts */
function useLiveChannel(clientScope) {
  const [toast, setToast] = useState(null);
  const [bumps, setBumps] = useState(0);
  useEffect(() => {
    const stop = streamEvents({
      onEvent: (ev) => {
        if (ev?.type === "task") {
          const t = ev.task || {};
          if (clientScope && t.client_id && t.client_id !== clientScope) return;
          setToast({ icon: "task", title: `New task · ${t.title || "assigned work"}`, detail: `${t.priority || ""} · for ${t.client_id || "you"}`, ts: new Date().toLocaleTimeString() });
          setBumps((n) => n + 1);
        } else if (ev?.type === "case") {
          const c = ev.case || {};
          if (clientScope && c.client_id && c.client_id !== clientScope) return;
          setToast({ icon: "case", title: `Incident ${c.status} · ${c.threat_class || "update"}`, detail: `${c.id ? c.id.slice(0, 8) : ""} · ${c.client_id || ""}`, ts: new Date().toLocaleTimeString() });
          setBumps((n) => n + 1);
        }
      },
    });
    return stop;
  }, [clientScope]);
  return { toast, dismiss: () => setToast(null), bumps };
}

function LiveToast({ toast, onDismiss }) {
  if (!toast) return null;
  const tone = toast.icon === "task" ? "border-cyan-500/40" : "border-rose-500/40";
  return (
    <div className={`fixed right-4 top-20 z-50 flex w-80 max-w-[calc(100vw-2rem)] items-start gap-3 rounded-xl border bg-black/85 p-3 shadow-2xl backdrop-blur anim-fadeup ${tone}`}>
      <span className={`mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg text-[13px] ${toast.icon === "task" ? "bg-cyan-500/15 text-cyan-300" : "bg-rose-500/15 text-rose-300"}`}>
        {toast.icon === "task" ? "⚑" : "◉"}
      </span>
      <div className="min-w-0 flex-1">
        <p className="mono text-[11.5px] font-semibold text-slate-100">{toast.title}</p>
        <p className="mono mt-0.5 truncate text-[10px] text-slate-400">{toast.detail}</p>
        <p className="mono mt-1 text-[9px] uppercase tracking-widest text-slate-600">{toast.ts}</p>
      </div>
      <button onClick={onDismiss} className="text-slate-600 transition hover:text-slate-300">✕</button>
    </div>
  );
}

/* ------------------------------------------------------------------ tasks */
const PRIORITY_TONES = {
  P1: "text-rose-300 border-rose-500/40 bg-rose-500/10",
  P2: "text-amber-300 border-amber-500/40 bg-amber-500/10",
  P3: "text-cyan-300 border-cyan-500/40 bg-cyan-500/10",
  P4: "text-slate-400 border-slate-500/40 bg-slate-500/10",
};

function TaskPriority({ priority }) {
  return <span className={`mono rounded border px-1.5 py-0.5 text-[10px] font-semibold ${PRIORITY_TONES[priority] || PRIORITY_TONES.P3}`}>{priority}</span>;
}

function TaskRow({ task, onPatch, canPatch }) {
  const [note, setNote] = useState("");
  const overdue = task.due_at && task.status !== "done" && task.due_at.slice(0, 10) < new Date().toISOString().slice(0, 10);
  const nextStatus = task.status === "todo" ? "in_progress" : task.status === "in_progress" ? "done" : "todo";
  return (
    <div className={`glass-row p-3 ${overdue ? "border-rose-500/30" : ""}`}>
      <div className="flex items-start gap-2">
        {canPatch && (
          <button
            onClick={() => onPatch(task.id, { status: nextStatus })}
            className="mt-0.5 grid h-4 w-4 shrink-0 cursor-pointer place-items-center rounded-full border border-slate-600 text-slate-500 transition hover:border-emerald-400 hover:text-emerald-300"
            title={`Mark ${nextStatus}`}
          >
            {task.status === "done" && <span className="text-[9px]">✓</span>}
          </button>
        )}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="mono text-[12.5px] text-slate-100">{task.title}</span>
            <TaskPriority priority={task.priority} />
            <span className="mono rounded border border-white/10 px-1.5 py-0.5 text-[9px] uppercase tracking-widest text-slate-400">{task.status}</span>
            {overdue && <span className="mono rounded border border-rose-500/40 px-1.5 py-0.5 text-[9px] uppercase tracking-widest text-rose-300">overdue</span>}
          </div>
          {task.description && <p className="mono mt-1 truncate text-[10.5px] text-slate-500">{task.description}</p>}
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10.5px] text-slate-500">
            {task.due_at && <span className="mono">{task.due_at.slice(0, 10)} due</span>}
            {task.linked_case_id && (
              <Link to={`/incidents/${task.linked_case_id}`} className="mono text-cyan-300 underline-offset-2 hover:underline">incident {task.linked_case_id.slice(0, 8)}</Link>
            )}
            {task.created_by && <span className="mono text-slate-600">by {task.created_by}</span>}
          </div>
          {canPatch && (
            <div className="mt-2 flex items-center gap-2">
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && note.trim()) { onPatch(task.id, { note: note.trim() }); setNote(""); } }}
                placeholder="add a note (enter to post)"
                className="flex-1 rounded border border-white/10 bg-black/30 px-2 py-1 text-[11px] text-slate-200 outline-none placeholder:text-slate-600"
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ClientTasks({ clientId, initial }) {
  const [tasks, setTasks] = useState([]);
  const [done, setDone] = useState([]);
  const [patched, setPatched] = useState(0);
  useEffect(() => {
    getTasks().then((d) => {
      const all = d.list || [];
      setTasks(all.filter((t) => t.status !== "done"));
      setDone(all.filter((t) => t.status === "done"));
    }).catch(() => {});
  }, [patched]);
  const patch = (id, body) => {
    patchTask(id, body)
      .then(() => setPatched((n) => n + 1))
      .catch(() => {});
  };
  const all = [...tasks, ...done];
  return (
    <div className="mt-2">
      {all.length === 0 ? (
        <Empty title="No tasks assigned" hint={initial?.total ? `It looks like everything's handled · ${initial.total} total` : "The SOC team will post remediation tasks here."} />
      ) : (
        <div className="space-y-2">
          {tasks.map((t) => <TaskRow key={t.id} task={t} onPatch={patch} canPatch />)}
          {done.length > 0 && (
            <details className="mt-2">
              <summary className="mono cursor-pointer text-[10px] uppercase tracking-widest text-slate-500">completed · {done.length}</summary>
              <div className="mt-2 space-y-2">
                {done.map((t) => <TaskRow key={t.id} task={t} onPatch={patch} canPatch />)}
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

function AdminTaskManage({ clients, initial }) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState("P3");
  const [due, setDue] = useState("");
  const [clientId, setClientId] = useState("");
  const [busy, setBusy] = useState(false);
  const [openTasks, setOpenTasks] = useState([]);
  const [flash, setFlash] = useState("");
  const [patched, setPatched] = useState(0);
  useEffect(() => {
    getTasks({ status: "open" }).then((d) => setOpenTasks(d.list || [])).catch(() => {});
  }, [patched]);
  const submit = (e) => {
    e.preventDefault();
    if (!title.trim() || !clientId) return;
    setBusy(true);
    createTask({ title: title.trim(), description, priority, due_at: due, client_id: clientId })
      .then(() => {
        setTitle(""); setDescription(""); setDue(""); setClientId("");
        setFlash(`task assigned to ${clientId}`);
        setPatched((n) => n + 1);
        setTimeout(() => setFlash(""), 3200);
      })
      .catch((err) => setFlash(err?.message || "assign failed"))
      .finally(() => setBusy(false));
  };
  const patch = (id, body) => patchTask(id, body).then(() => setPatched((n) => n + 1)).catch(() => {});
  return (
    <div className="mt-2 grid gap-6 lg:grid-cols-2">
      <div className="rounded-xl border border-white/5 bg-black/30 p-4">
        {flash && <p className="mono mb-3 text-[11px] text-emerald-300">✓ {flash}</p>}
        <form onSubmit={submit} className="space-y-3">
          <input value={title} onChange={(e) => setTitle(e.target.value)} required
            placeholder="Task title · what needs to be done"
            className="w-full rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-[12.5px] text-slate-100 outline-none placeholder:text-slate-600 focus:border-emerald-500/50" />
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2}
            placeholder="Instructions / context for the client"
            className="w-full resize-none rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-[12px] text-slate-200 outline-none placeholder:text-slate-600 focus:border-emerald-500/50" />
          <div className="grid gap-3 sm:grid-cols-3">
            <select value={clientId} onChange={(e) => setClientId(e.target.value)} required
              className="rounded-lg border border-white/10 bg-black/30 px-2 py-2 text-[12px] text-slate-100 outline-none focus:border-emerald-500/50">
              <option value="">assign to…</option>
              {clients.map((c) => <option key={c.client_id} value={c.client_id}>{c.client_id}</option>)}
            </select>
            <select value={priority} onChange={(e) => setPriority(e.target.value)}
              className="rounded-lg border border-white/10 bg-black/30 px-2 py-2 text-[12px] text-slate-100 outline-none focus:border-emerald-500/50">
              {["P1", "P2", "P3", "P4"].map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
            <input type="date" value={due} onChange={(e) => setDue(e.target.value)}
              className="rounded-lg border border-white/10 bg-black/30 px-2 py-2 text-[12px] text-slate-100 outline-none focus:border-emerald-500/50" />
          </div>
          <button disabled={busy} className="btn-primary mono w-full !py-2 text-[11px]">
            {busy ? "assigning…" : "assign task →"}
          </button>
        </form>
      </div>
      <div>
        <p className="eyebrow mb-2">Open tasks · every client</p>
        {openTasks.length === 0 ? (
          <Empty title="No open tasks" hint="Assign work to a client and it appears here + on their dashboard." />
        ) : (
          <div className="space-y-2">
            {openTasks.map((t) => (
              <TaskRow key={t.id} task={t} onPatch={patch} canPatch />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ local pieces */
function KpiCard({ label, value, sub, tone, icon, spark, delay }) {
  const tones = { emerald: "glow-emerald", cyan: "glow-cyan", danger: "glow-red", violet: "glow-cyan" };
  return (
    <div className={`glass p-4 anim-fadeup ${tones[tone]}`} style={{ animationDelay: `${delay}ms` }}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="eyebrow truncate">{label}</p>
          <p className="mono mt-1.5 text-[24px] font-bold leading-none text-slate-50">{value}</p>
          <p className="mt-2 text-[11px] leading-snug text-slate-500">{sub}</p>
        </div>
        <span className={`grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-white/10 bg-white/5 text-emerald-300 ${tone === "danger" ? "!text-rose-300" : ""}`}>{icon}</span>
      </div>
      {spark && <div className="mt-3"><Sparkline data={spark.values} color={spark.color} width={140} /></div>}
    </div>
  );
}

const ChartIcon = () => (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
    <path d="M4 19h16M7 16v-4M12 16V8M17 16v-6" />
  </svg>
);
const DedupIcon = () => (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
    <path d="M8 7h12M8 12h12M8 17h12M3 7h.01M3 12h.01M3 17h.01" />
  </svg>
);
const ThreatIcon = () => (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 3l8 5v6c0 4-3.4 6.4-8 7-4.6-.6-8-3-8-7V8l8-5z" />
    <path d="M12 10v4M12 17h.01" />
  </svg>
);
const GraphIcon = () => (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <circle cx="6" cy="6" r="2.4" /><circle cx="18" cy="7" r="2.4" /><circle cx="10" cy="18" r="2.4" />
    <path d="M8.2 7l7.6.6M7 8.2l1.8 8.4M15.8 8.7l-5 7.2" strokeWidth="1.3" />
  </svg>
);