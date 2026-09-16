import React, { useEffect, useState } from "react";
import { getDashboard, getClients, getIncidentDetail } from "../lib/api";
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

  useEffect(() => {
    let alive = true;
    const tick = () => {
      getDashboard()
        .then((d) => alive && setData(d))
        .catch((e) => alive && setError(e.message));
      getClients()
        .then((d) => alive && setClients(d.clients || []))
        .catch(() => {});
    };
    tick();
    const id = setInterval(tick, 10000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  if (error) return <div className="text-sm text-rose-400">Failed to load dashboard: {error}</div>;
  if (!data) return <div className="text-slate-500">Loading dashboard…</div>;

  if (scoped || data.scope) {
    return (
      <ScopedDashboard
        data={data}
        scope={data.scope || clientScope}
        role={role}
      />
    );
  }

  return <AdminOverview data={data} clients={clients} />;
}

/* ================================================================== scoped view */
function ScopedDashboard({ data, scope, role }) {
  const s = data.stats || {};
  const incidents = data.incidents || { open: [], investigation: [], closed: [], stats: {} };
  const threats = data.threat_detections || {};
  const findings = (data.findings || []).slice(-6).reverse();
  const threatVals = Object.values(threats).map(Number);
  const [openId, setOpenId] = useState(null);
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(false);

  const openIncident = (id) => {
    setOpenId(id);
    if (!id) { setIncident(null); return; }
    setLoading(true);
    getIncidentDetail(id)
      .then((d) => setIncident(d))
      .catch(() => setIncident(null))
      .finally(() => setLoading(false));
  };

  const totalIncidents = (incidents.open?.length || 0) + (incidents.investigation?.length || 0) + (incidents.closed?.length || 0);

  return (
    <div className="space-y-6">
      {/* header */}
      <div className="anim-fadeup">
        <p className="eyebrow mb-1.5">Client workspace · individual dashboard</p>
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-slate-50">
              <span className="mono text-emerald-300">{scope}</span>
              <span className="text-slate-400"> · overview</span>
            </h1>
            <p className="mt-1 max-w-2xl text-[13px] leading-relaxed text-slate-400">
              What this client sees:{" "}
              <b className="mono text-emerald-300">{s.events ?? 0}</b> normalized events,{" "}
              <b className="mono text-amber-300">{s.findings ?? 0}</b> findings and{" "}
              <b className="mono text-rose-300">{totalIncidents}</b> incidents.
            </p>
          </div>
          <LiveBadge text="Live · 10s" />
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <KpiCard label="Events (this client)" value={s.events ?? 0} sub={`dedup ${Math.round((data.dedup_rate || 0) * 100)}%`} tone="emerald" icon={<ChartIcon />} delay={0} />
        <KpiCard label="Findings" value={s.findings ?? 0} sub={`alerts on this workspace`} tone="danger" icon={<ThreatIcon />} delay={60} />
        <KpiCard label="Open incidents" value={incidents.open?.length ?? 0} sub="awaiting triage" tone="danger" icon={<GraphIcon />} delay={120} />
        <KpiCard label="Investigation" value={incidents.investigation?.length ?? 0} sub="actively worked" tone="violet" icon={<DedupIcon />} delay={180} />
      </div>

      {/* incident board */}
      <section className="glass p-5 anim-fadeup">
        <SectionTitle
          right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">who investigated, who is involved</span>}
        >
          Incident board
        </SectionTitle>
        <IncidentBoard incidents={incidents} openId={openId} onOpen={openIncident} loading={loading} incident={incident} role={role} />
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
                      <div className="bar-grow h-full rounded-full" style={{ width: `${(count / max) * 100}%`, background: "linear-gradient(90deg,#059669,#10b981,#f43f5e)", boxShadow: "0 0 12px rgba(244,63,94,0.5)" }} />
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
    </div>
  );
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
  const [openId, setOpenId] = useState(null);
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(false);

  const openIncident = (id) => {
    setOpenId(id);
    if (!id) { setIncident(null); return; }
    setLoading(true);
    getIncidentDetail(id)
      .then((d) => setIncident(d))
      .catch(() => setIncident(null))
      .finally(() => setLoading(false));
  };

  return (
    <div className="space-y-6">
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
        <IncidentBoard incidents={incidents} openId={openId} onOpen={openIncident} loading={loading} incident={incident} role="admin" />
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
function IncidentBoard({ incidents, openId, onOpen, loading, incident, role }) {
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
                  <button
                    key={c.id}
                    onClick={() => onOpen(openId === c.id ? null : c.id)}
                    className={`block w-full rounded-lg border border-white/5 bg-white/[0.03] p-2 text-left transition hover:border-emerald-500/30 ${openId === c.id ? "!border-emerald-500/40" : ""}`}
                  >
                    <div className="flex items-center gap-1.5">
                      <SeverityBadge severity={c.severity} />
                      <span className="mono truncate text-[11px] text-slate-200">{c.threat_class}</span>
                    </div>
                    <p className="mono mt-1 truncate text-[9.5px] uppercase tracking-widest text-slate-500">
                      {c.client_id || "—"} · {c.source_kind || "flow"}
                      {c.assignee && <span className="text-emerald-300"> @{c.assignee}</span>}
                    </p>
                  </button>
                ))
              )}
            </div>
          </div>
        ))}
      </div>

      {openId && <IncidentDrawer incident={incident} loading={loading} role={role} />}
    </div>
  );
}

function IncidentDrawer({ incident, loading, role }) {
  if (loading) return <div className="mono text-[11px] text-slate-500">Loading incident detail…</div>;
  if (!incident) return <div className="mono text-[11px] text-rose-400">Failed to load incident context.</div>;
  const involved = incident.involved || [];
  const graph = incident.graph || { nodes: [], edges: [] };
  const timeline = incident.timeline || [];
  const c = incident.case || {};
  const canAct = role === "admin";
  return (
    <div className="rounded-xl border border-emerald-500/20 bg-black/40 p-4 anim-fadeup">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="mono text-[14px] font-semibold text-slate-100">{c.threat_class}</span>
        <SeverityBadge severity={c.severity} />
        <StatusBadge status={c.status} />
        {c.client_id && <span className="mono rounded border border-violet-500/30 bg-violet-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-violet-300">{c.client_id}</span>}
        {c.assignee && <span className="mono text-[10.5px] text-emerald-300">investigator @{c.assignee}</span>}
      </div>
      <p className="mono text-[11px] uppercase tracking-widest text-slate-500">{c.message || "—"}</p>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <p className="eyebrow mb-2">Involved parties · who is implicated</p>
          {involved.length === 0 ? (
            <p className="text-[11.5px] text-slate-500">No entity attribution recorded.</p>
          ) : (
            <div className="space-y-1.5">
              {involved.map((e, i) => (
                <div key={`${e.kind}-${e.value}-${i}`} className="glass-row flex items-center gap-2 p-2.5">
                  <span className={`h-2 w-2 shrink-0 rounded-full ${entityDot(e.kind)}`} />
                  <span className="mono text-[10px] uppercase tracking-widest text-slate-500">{e.kind}</span>
                  <span className="mono truncate text-[12px] text-slate-200">{e.label || e.value}</span>
                  {typeof e.events === "number" && <span className="ml-auto mono text-[10.5px] text-slate-500">{e.events} events</span>}
                </div>
              ))}
            </div>
          )}

          <p className="eyebrow mb-2 mt-4">Incident graph</p>
          <IncidentGraph graph={graph} />
        </div>

        <div>
          <p className="eyebrow mb-2">Who did what · investigators</p>
          {timeline.length === 0 ? (
            <p className="text-[11.5px] text-slate-500">No activity recorded yet.</p>
          ) : (
            <div className="space-y-1">
              {timeline.map((t, ti) => (
                <p key={ti} className="mono text-[10.5px] text-slate-500">
                  <span className="text-slate-600">{t.ts}</span>{" "}
                  <span className={t.action === "created" ? "text-slate-400" : "text-emerald-300"}>{t.action}</span>
                  {" by "}<span className="text-slate-400">{t.actor}</span>
                  {t.detail && <span className="text-slate-500"> — {t.detail}</span>}
                  {t.note && <span className="text-amber-300/80"> (“{t.note}”)</span>}
                </p>
              ))}
            </div>
          )}

          {(Object.keys(incident.evidence || {}).length > 0 || (c.evidence && Object.keys(c.evidence).length > 0)) && (
            <>
              <p className="eyebrow mb-2 mt-4">Evidence</p>
              {Object.values(incident.evidence || c.evidence || {}).slice(0, 5).map((ev, i) => {
                if (typeof ev !== "object") return <p key={i} className="mono text-[10.5px] text-slate-500">{String(ev)}</p>;
                return (
                  <div key={i} className="glass-row mb-1.5 p-2.5">
                    <p className="mono text-[10px] uppercase tracking-widest text-cyan-300">{ev.event_type || ev.threat_class || ev.kind || `evidence ${i + 1}`}</p>
                    <p className="mono mt-0.5 truncate text-[10.5px] text-slate-400">{String(ev.summary || ev.message || ev.src_ip || ev.dst_ip || JSON.stringify(ev)).slice(0, 90)}</p>
                  </div>
                );
              })}
            </>
          )}
        </div>
      </div>
      {!canAct && <p className="mono mt-3 text-[10px] uppercase tracking-widest text-slate-500">read-only view — manage this incident in the alert queue</p>}
    </div>
  );
}

function IncidentGraph({ graph }) {
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  if (nodes.length === 0) return <div className="glass-row border border-white/5 p-3 text-[11px] text-slate-500">No graph data for this incident yet.</div>;
  const rows = nodes.map((n, i) => ({ node: n, x: 18 + (i % 3) * 130 + (i % 2) * 18, y: 22 + Math.floor(i / 3) * 56 + (i % 2) * 12 }));
  return (
    <div className="rounded-lg border border-white/5 bg-black/40 p-2">
      <svg viewBox="0 0 300 150" className="w-full">
        {edges.map((e, i) => {
          const a = rows.find((r) => r.node.id === e.source);
          const b = rows.find((r) => r.node.id === e.target);
          if (!a || !b) return null;
          return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={e.threat ? "#f43f5e" : "#334155"} strokeWidth={e.threat ? 1.6 : 1} strokeDasharray={e.threat ? "2 2" : undefined} />;
        })}
        {rows.map(({ node, x, y }) => (
          <g key={node.id}>
            <circle cx={x} cy={y} r={node.threatened || node.kind === "threat" ? 7 : 5} fill={node.color || "#6366f1"} opacity="0.9" />
            <text x={x + 9} y={y + 3} fontSize="7.5" fill="#cbd5e1" className="mono">{node.label}</text>
          </g>
        ))}
      </svg>
      <p className="mono text-[9.5px] uppercase tracking-widest text-slate-600">{nodes.length} nodes · {edges.length} edges</p>
    </div>
  );
}

function FindingRow({ f, i, sevStrip }) {
  const alert = f.alert || f;
  const verdict = f.analysis?.verdict || alert.verdict;
  const storeDecision = f.analysis?.store_decision || alert.store_decision;
  const key = f.flow_id || f.alert?.flow_id || `${f.threat_class}-${f.timestamp}-${i}`;
  return (
    <div key={key} className="glass-row flex items-center gap-3 p-3 feed-in" style={{ animationDelay: `${i * 60}ms` }}>
      <span className={`sev-strip ${sevStrip(alert.severity)}`} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="mono text-[12.5px] text-slate-100">{alert.threat_class}</span>
          <span className="mono text-[10px] text-slate-500">conf {alert.confidence}</span>
        </div>
        <p className="mono mt-0.5 text-[10px] uppercase tracking-widest text-slate-500">
          {verdict ? `${verdict} · ${storeDecision}` : "awaiting analyzer verdict"}
        </p>
      </div>
      <SeverityBadge severity={alert.severity} />
    </div>
  );
}

function StatusBadge({ status }) {
  const map = {
    open: "text-rose-300 border-rose-500/30 bg-rose-500/10",
    investigation: "text-amber-300 border-amber-500/30 bg-amber-500/10",
    closed: "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
    acknowledged: "text-amber-300 border-amber-500/30 bg-amber-500/10",
    resolved: "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
  };
  return <span className={`mono rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-widest ${map[status] || ""}`}>{status}</span>;
}

const entityDot = (kind) => {
  const m = { ip: "bg-indigo-500", user: "bg-emerald-500", domain: "bg-cyan-500", client: "bg-violet-500", proc: "bg-amber-500" };
  return m[kind] || "bg-slate-500";
};

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