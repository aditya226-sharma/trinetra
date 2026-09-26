import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getDashboard, getClients, getTasks, createTask, patchTask, streamEvents } from "../lib/api";
import { SeverityBadge, SeverityDot, LiveBadge, PulseDot, SectionTitle, Empty, severityRank, severityHex } from "../components/ui";
import { Donut, Sparkline, ScoreRing } from "../components/charts";

const DONUT_COLORS = ["#a855f7", "#ec4899", "#c084fc", "#f472b6", "#7c3aed", "#d8b4fe", "#a78bfa"];

const REVIEW_LIMIT = 6;

// Timestamp fields vary by source, so try the plausible ones in order. The
// live dashboard payload stamps both findings and incidents with `timestamp`.
function recency(item) {
  for (const k of ["timestamp", "ts", "created_at", "opened_at", "detected_at", "updated_at"]) {
    const v = item?.[k];
    if (v) {
      const t = Date.parse(v);
      if (!Number.isNaN(t)) return t;
    }
  }
  return 0;
}

function humanize(value) {
  return String(value)
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^./, (c) => c.toUpperCase());
}

function relativeTime(ms) {
  if (!ms) return null;
  const secs = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

// Findings and incidents from /api/dashboard are identified by `threat_class`
// (e.g. "port_scan"); they carry no title field, so fall back to it before
// giving up, otherwise every row renders as "Untitled finding".
function reviewTitle(item, source) {
  const direct = item?.title || item?.rule || item?.name || item?.summary || item?.reason;
  if (direct) return direct;
  if (item?.threat_class) return humanize(item.threat_class);
  if (source === "incident") return item?.id ? `Incident ${humanize(item.id).slice(0, 8)}` : "Incident";
  return "Unclassified finding";
}

function reviewSubject(item) {
  return item?.client_id || item?.client_name || item?.entity || item?.host || item?.src_ip || "";
}

// "Needs Review" merges open findings and open incidents into one ranked queue:
// severity first, then recency. Derived from endpoints the dashboard already
// fetches, so it costs no extra request and needs no backend change.
//
// A live estate is dominated by whichever detector is noisiest, so a plain
// top-N was six near-identical "Dga dns" rows that gave an analyst no sense of
// breadth. CLASS_CAP keeps at most N rows per threat class so the queue shows
// spread, while the severity-then-recency order is untouched: the cap only ever
// defers a row, and deferred rows are backfilled in rank order if slots remain.
const CLASS_CAP = 3;

function buildReviewQueue({ findings = [], incidents = [] }) {
  const rows = [
    ...findings.map((f) => ({ item: f, source: "finding" })),
    ...incidents.map((i) => ({ item: i, source: "incident" })),
  ];
  const ranked = rows
    .map((r) => ({
      ...r,
      severity: String(r.item?.severity || "info").toLowerCase(),
      title: reviewTitle(r.item, r.source),
      subject: reviewSubject(r.item),
      when: recency(r.item),
      ago: relativeTime(recency(r.item)),
    }))
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || b.when - a.when);

  const picked = [];
  const deferred = [];
  const perClass = new Map();
  const keyOf = (row) => row.item?.threat_class || row.title;
  for (const row of ranked) {
    const cls = keyOf(row);
    const seen = perClass.get(cls) || 0;
    if (seen < CLASS_CAP) {
      perClass.set(cls, seen + 1);
      picked.push(row);
    } else {
      deferred.push(row);
    }
    if (picked.length === REVIEW_LIMIT) break;
  }
  // Backfill in rank order, but only with classes still under the cap: padding
  // with the very rows the cap deferred would defeat it. The panel can then end
  // up shorter than REVIEW_LIMIT, which is honest — six copies of one finding
  // is less use to an analyst than two.
  for (const row of deferred) {
    if (picked.length === REVIEW_LIMIT) break;
    const cls = keyOf(row);
    if ((perClass.get(cls) || 0) < CLASS_CAP) {
      perClass.set(cls, (perClass.get(cls) || 0) + 1);
      picked.push(row);
    }
  }
  return picked;
}

const PIPELINE = [
  { id: "normalize", label: "Normalize" },
  { id: "dedup", label: "Dedup" },
  { id: "modules", label: "Modules A·B·C" },
  { id: "analyze", label: "Analyzer" },
];

const STATUS_LANES = [
  { key: "open", label: "open", tone: "text-pink-500 border-pink-500/30" },
  { key: "investigation", label: "investigation", tone: "text-purple-400 border-purple-500/30" },
  { key: "closed", label: "closed", tone: "text-violet-500 border-violet-600/30" },
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
      if (document.hidden) return;
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
    const id = setInterval(tick, 30000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [adminOnly]);

  if (error) return <div className="text-sm text-pink-500">Failed to load dashboard: {error}</div>;
  if (!data) return <div className="text-violet-300">Loading dashboard…</div>;

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
        <div className="flex items-center gap-3 rounded-xl border border-violet-500/25 bg-gradient-to-r from-violet-600/10 via-purple-500/5 to-transparent px-5 py-4">
          <span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-violet-500/30 bg-violet-500/10 text-xl text-[#ddd6fe]">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 01-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 011-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 011.52 0C14.51 3.81 17 5 19 5a1 1 0 011 1z" />
            </svg>
          </span>
          <div className="min-w-0 flex-1">
            <p className="mono text-[10px] uppercase tracking-[0.22em] text-violet-300">Client portal · scoped workspace</p>
            <h1 className="mt-0.5 text-[22px] font-bold leading-tight tracking-tight text-slate-50">
              <span className="text-[#ddd6fe]">{scope}</span>
              <span className="text-violet-200"> · this workspace</span>
            </h1>
            <p className="mt-1 max-w-2xl text-[12.5px] leading-relaxed text-violet-200">
              You are signed in as a <b className="mono text-violet-200">viewer</b> scoped to{" "}
              <b className="mono text-violet-200">{scope}</b> — you only see this client's telemetry,
              incidents and SOC tasks. <span className="text-violet-300">Read-only view · managed by the SOC team.</span>
            </p>
          </div>
          <span className="mono shrink-0 rounded-md border border-violet-500/30 bg-black/30 px-2.5 py-1 text-[10px] uppercase tracking-[0.18em] text-violet-200">
            scope: {scope}
          </span>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-[10.5px] text-violet-300">
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-violet-500" /> <b className="mono text-violet-300">{s.events ?? 0}</b> normalized events
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-purple-400" /> <b className="mono text-purple-300">{s.findings ?? 0}</b> findings
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-pink-500" /> <b className="mono text-pink-300">{totalIncidents}</b> incidents
          </span>
          <span className="ml-auto"><LiveBadge text="Live · 10s" /></span>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <KpiCard label="Events this client" value={s.events ?? 0} sub={`dedup ${Math.round((data.dedup_rate || 0) * 100)}%`} tone="calm" icon={<ChartIcon />} delay={0} />
        <KpiCard label="Findings" value={s.findings ?? 0} sub="on this workspace" tone="danger" icon={<ThreatIcon />} delay={60} />
        <KpiCard label="Open incidents" value={incidents.open?.length ?? 0} sub="awaiting SOC triage" tone="danger" icon={<GraphIcon />} delay={120} />
        <KpiCard label="Investigation" value={incidents.investigation?.length ?? 0} sub="actively worked" tone="brand" icon={<DedupIcon />} delay={180} />
      </div>

      <NeedsReview rows={buildReviewQueue({ findings: data.findings || [], incidents: incidents.open || [] })} />

      {/* tasks assigned by the SOC team */}
      <section className="glass p-5 anim-fadeup !border-violet-500/20 !bg-violet-950/10">
        <SectionTitle
          right={<span className="mono text-[10px] uppercase tracking-widest text-violet-300/70">from the SOC team → you</span>}
        >
          Tasks assigned to {scope}
        </SectionTitle>
        <ClientTasks clientId={scope} initial={data.tasks} />
      </section>

      {/* incident board */}
      <section className="glass p-5 anim-fadeup">
        <SectionTitle
          right={<span className="mono text-[10px] uppercase tracking-widest text-violet-300">{scope} only</span>}
        >
          Incidents on this workspace
        </SectionTitle>
        <IncidentBoard incidents={incidents} />
      </section>

      {/* threat radar + findings */}
      <div className="grid gap-6 lg:grid-cols-2">
        <section className="glass p-5 anim-fadeup">
          <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-violet-300">this workspace</span>}>
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
                      <span className="mono text-[11px] text-pink-300">{count} hits</span>
                    </div>
                    <div className="relative h-2 overflow-hidden rounded-full bg-white/5">
                      <div className="bar-grow h-full rounded-full" style={{ width: `${(count / max) * 100}%`, background: "linear-gradient(90deg,#7c3aed,#a855f7,#ec4899)", boxShadow: "0 0 12px rgba(168, 85, 247,0.4)" }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <section className="glass p-5 anim-fadeup">
          <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-violet-300">analyzer verdict feed</span>}>
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
      <p className="mono text-center text-[9.5px] uppercase tracking-[0.2em] text-violet-400">
        TriNetra client portal · restricted to {scope} · questions? contact your SOC team
      </p>
    </div>
  );

  function sevStrip(sev) {
    const known = ["critical", "high", "medium", "warning", "error", "info", "low"];
    return `sev-${(known.includes(sev) ? sev : "info")}`;
  }
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
          <span className="mono text-[10px] text-violet-300">conf {alert.confidence}</span>
        </div>
        <p className="mono mt-0.5 text-[10px] uppercase tracking-widest text-violet-300">
          {verdict ? `${verdict} · ${storeDecision}` : "awaiting analyzer verdict"}
        </p>
      </div>
      <SeverityBadge severity={alert.severity} />
    </div>
  );
}

/* ================================================================== needs review */
function NeedsReview({ rows }) {
  const critical = rows.filter((r) => r.severity === "critical" || r.severity === "high").length;

  return (
    <section className="glass p-5 anim-fadeup">
      <SectionTitle
        right={
          <span className="mono text-[10px] uppercase tracking-widest text-[#a78bc4]">
            {critical > 0 ? `${critical} high priority` : `${rows.length} queued`}
          </span>
        }
      >
        Needs Review
      </SectionTitle>

      {rows.length === 0 ? (
        <Empty title="Queue is clear" hint="Open findings and incidents needing triage appear here, highest severity first." />
      ) : (
        <ul className="mt-1 space-y-2">
          {rows.map((r, i) => {
            const hex = severityHex(r.severity);
            const to = r.source === "incident" ? "/alerts" : "/graph";
            return (
              <li key={`${r.source}-${r.item?.id || r.item?.flow_id || i}`}>
                <Link
                  to={to}
                  className="glass-row flex items-center gap-3 px-3.5 py-3 no-underline"
                >
                  <span
                    aria-hidden="true"
                    className="h-9 w-[3px] shrink-0 rounded-full"
                    style={{ background: hex, boxShadow: `0 0 12px ${hex}99` }}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-2">
                      <SeverityDot severity={r.severity} />
                      <span className="truncate text-[13px] font-medium text-[#f5f0fb]">{r.title}</span>
                    </span>
                    {(r.subject || r.ago) && (
                      <span className="mono mt-0.5 flex items-center gap-2 text-[10px] uppercase tracking-wider text-[#a78bc4]">
                        {r.subject && <span className="truncate">{r.subject}</span>}
                        {r.subject && r.ago && <span aria-hidden="true" className="text-violet-400">·</span>}
                        {r.ago && (
                          <time className="shrink-0" dateTime={new Date(r.when).toISOString()}>
                            {r.ago}
                          </time>
                        )}
                      </span>
                    )}
                  </span>
                  <span className="hidden shrink-0 sm:block">
                    <SeverityBadge severity={r.severity} />
                  </span>
                  <svg
                    aria-hidden="true"
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="#a78bc4"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className="shrink-0"
                  >
                    <path d="M9 18l6-6-6-6" />
                  </svg>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </section>
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
  // Only clients that actually reported get a ring segment. A registered but
  // silent sensor has no share, and colouring it like a reporting one made the
  // legend lie about which slice was which.
  const active = top.filter((c) => (c.events ?? 0) > 0);
  const activeIds = new Set(active.map((c) => c.client_id));
  const feedSegments = active.map((c, i) => ({ value: c.events, color: DONUT_COLORS[i % DONUT_COLORS.length] }));
  // Centre the ring on the segments it actually draws so the two can never
  // disagree when the store total and the per-client sum drift apart.
  const feedTotal = feedSegments.reduce((acc, x) => acc + x.value, 0);
  const feedColor = (c) => {
    const i = active.findIndex((x) => x.client_id === c.client_id);
    return i < 0 ? "rgba(167, 139, 196,0.25)" : DONUT_COLORS[i % DONUT_COLORS.length];
  };
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
            <p className="mt-1 max-w-2xl text-[13px] leading-relaxed text-violet-200">
              Multi-domain intelligence over{" "}
              <b className="mono text-violet-300">{s.events ?? 0}</b> normalized events with{" "}
              <b className="mono text-purple-300">{s.findings ?? 0}</b> module findings and{" "}
              <b className="mono text-pink-300">{s.alerts_sent ?? 0}</b> alerts fanned out.
            </p>
          </div>
          <LiveBadge text="Live · 10s" />
        </div>
      </div>

      {/* pipeline strip */}
      <div className="glass flex flex-wrap items-center gap-x-2 gap-y-3 px-5 py-4 anim-fadeup">
        {PIPELINE.map((p, i) => (
          <React.Fragment key={p.id}>
            {i > 0 && <span className="text-violet-400">›</span>}
            <span className="flex items-center gap-2">
              <PulseDot />
              <span className="mono text-[11px] uppercase tracking-widest text-violet-300">{p.label}</span>
            </span>
          </React.Fragment>
        ))}
        <span className="ml-auto mono text-[11px] text-violet-300">
          {top.length} feeds reporting · graph {g.nodes}N/{g.edges}E
        </span>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <KpiCard label="Events ingested" value={s.events ?? 0} sub={`${s.raw_lines ?? 0} raw lines · ${Math.round((data.dedup_rate || 0) * 100)}% dedup`} tone="calm" icon={<ChartIcon />} spark={{ values: eventsSpark, color: "#a855f7" }} delay={0} />
        <KpiCard label="Deduplication rate" value={`${Math.round((data.dedup_rate || 0) * 100)}%`} sub="fingerprint-based corpus" tone="brand" icon={<DedupIcon />} delay={60} />
        <KpiCard label="Module findings" value={s.findings ?? 0} sub={`${s.alerts_sent ?? 0} alerts sent to analyst queue`} tone="danger" icon={<ThreatIcon />} spark={{ values: threatVals.length ? threatVals : [1], color: "#ec4899" }} delay={120} />
        <KpiCard label="Entity graph" value={`${g.nodes ?? 0}N / ${g.edges ?? 0}E`} sub={`${g.threatened?.length || 0} assets impacted`} tone="info" icon={<GraphIcon />} spark={{ values: top.map((c) => c.events), color: "#a855f7" }} delay={180} />
      </div>

      <NeedsReview rows={buildReviewQueue({ findings: data.findings || [], incidents: incidents.open || [] })} />

      {/* incident board */}
      <section className="glass p-5 anim-fadeup">
        <SectionTitle
          right={<span className="mono text-[10px] uppercase tracking-widest text-violet-300">admin · every client's incidents</span>}
        >
          Incident board
        </SectionTitle>
        <IncidentBoard incidents={incidents} />
      </section>

      {/* assign tasks to clients */}
      <section className="glass p-5 anim-fadeup">
        <SectionTitle
          right={<span className="mono text-[10px] uppercase tracking-widest text-violet-300">appears on the client's own dashboard</span>}
        >
          Assign a task to a client
        </SectionTitle>
        <AdminTaskManage clients={clients} initial={data.tasks} />
      </section>

      {/* radar + clients */}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <section className="glass p-5 anim-fadeup">
            <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-violet-300">Module A · flow heuristics</span>}>
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
                        <span className="mono text-[11px] text-pink-300">{count} hits</span>
                      </div>
                      <div className="relative h-2 overflow-hidden rounded-full bg-white/5">
                        <div className="bar-grow h-full rounded-full" style={{ width: `${(count / max) * 100}%`, background: "linear-gradient(90deg,#7c3aed,#a855f7,#ec4899)", boxShadow: "0 0 12px rgba(236, 72, 153,0.5)" }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          {/* latest findings */}
          <section className="glass p-5 anim-fadeup">
            <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-violet-300">analyzer verdict feed</span>}>
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
          <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-violet-300">GET /api/clients</span>}>
            Feed share
          </SectionTitle>
          {top.length === 0 ? (
            <Empty title="No clients reporting" hint="Sensors will appear here once data flows." />
          ) : (
            <>
              <div className="flex justify-center pb-2">
                <Donut
                  size={172}
                  thickness={17}
                  centerValue={feedTotal}
                  centerLabel={active.length < top.length ? "events · active" : "events"}
                  segments={feedSegments}
                />
              </div>
              <div className="mt-2 space-y-1.5">
                {top.map((c) => {
                  const color = feedColor(c);
                  return (
                    <div key={c.client_id} className="flex items-center gap-2 text-[12px]">
                      <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
                      <span className="mono truncate text-slate-300">{c.client_id}</span>
                      <span className="text-[10px] text-violet-400">{(c.source_types || [c.source_type]).filter(Boolean).join(", ")}</span>
                      {!activeIds.has(c.client_id) && (
                        <span className="text-[9.5px] uppercase tracking-wider text-violet-400">silent</span>
                      )}
                      <span className="ml-auto mono tabular-nums text-violet-300">{c.events ?? 0}</span>
                    </div>
                  );
                })}
              </div>
              {active.length < top.length && (
                <p className="mt-2 text-[10.5px] text-violet-400">
                  {top.length - active.length} registered sensor{top.length - active.length === 1 ? "" : "s"} reported no events and {top.length - active.length === 1 ? "is" : "are"} excluded from the ring.
                </p>
              )}
            </>
          )}
        </section>
      </div>

      {/* VPN assessment */}
      <section className="glass p-5 anim-fadeup">
        <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-violet-300">Module B · IPsec posture</span>}>
          VPN / IPsec gateway assessment
        </SectionTitle>
        {vpn.length === 0 ? (
          <Empty title="No tunnel/IPsec posture yet" hint="Live agent tunnel posture or Module B PCAP assessments populate this." />
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {vpn.map((p, i) => {
              const tone = p.risk_level === "critical" ? "#ec4899" : p.risk_level === "high" ? "#f472b6" : p.risk_level === "medium" ? "#c084fc" : "#d8b4fe";
              return (
                <div key={p.interface || p.file || i} className="glass-row flex items-center gap-4 p-4 feed-in" style={{ animationDelay: `${i * 70}ms` }}>
                  <ScoreRing score={p.security_score ?? p.score ?? 0} tone={tone} label="score" />
                  <div className="min-w-0 flex-1">
                    <p className="mono truncate text-[13px] text-slate-100">{p.file}</p>
                    <SeverityBadge severity={p.risk_level} />
                    <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-0.5 text-[10.5px] text-violet-200">
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
                <p className="mono text-[10px] text-violet-400">—</p>
              ) : (
                l.items.slice(0, 6).map((c) => (
                  <Link
                    key={c.id}
                    to={`/incidents/${c.id}`}
                    className="block w-full rounded-lg border border-white/5 bg-white/[0.03] p-2 text-left transition hover:border-violet-600/30"
                  >
                    <div className="flex items-center gap-1.5">
                      <SeverityBadge severity={c.severity} />
                      <span className="mono truncate text-[11px] text-slate-200">{c.threat_class}</span>
                    </div>
                    <p className="mono mt-1 truncate text-[9.5px] uppercase tracking-widest text-violet-300">
                      {c.client_id || "—"} · {c.source_kind || "flow"}
                      {c.assignee && <span className="text-violet-300"> @{c.assignee}</span>}
                    </p>
                    <span className="mono mt-1 block text-[9px] uppercase tracking-widest text-violet-300/70 hover:text-violet-200">open incident →</span>
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
  const tone = toast.icon === "task" ? "border-violet-600/40" : "border-pink-500/40";
  return (
    <div className={`fixed right-4 top-20 z-50 flex w-80 max-w-[calc(100vw-2rem)] items-start gap-3 rounded-xl border bg-black/85 p-3 shadow-2xl backdrop-blur anim-fadeup ${tone}`}>
      <span className={`mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg text-[13px] ${toast.icon === "task" ? "bg-violet-600/15 text-violet-300" : "bg-pink-500/15 text-pink-300"}`}>
        {toast.icon === "task" ? "⚑" : "◉"}
      </span>
      <div className="min-w-0 flex-1">
        <p className="mono text-[11.5px] font-semibold text-slate-100">{toast.title}</p>
        <p className="mono mt-0.5 truncate text-[10px] text-violet-200">{toast.detail}</p>
        <p className="mono mt-1 text-[9px] uppercase tracking-widest text-violet-400">{toast.ts}</p>
      </div>
      <button onClick={onDismiss} className="text-violet-400 transition hover:text-slate-300">✕</button>
    </div>
  );
}

/* ------------------------------------------------------------------ tasks */
const PRIORITY_TONES = {
  P1: "text-pink-300 border-pink-500/40 bg-pink-500/10",
  P2: "text-purple-300 border-purple-500/40 bg-purple-500/10",
  P3: "text-violet-300 border-violet-600/40 bg-violet-600/10",
  P4: "text-violet-200 border-violet-300/40 bg-[#2e1f4a]",
};

function TaskPriority({ priority }) {
  return <span className={`mono rounded border px-1.5 py-0.5 text-[10px] font-semibold ${PRIORITY_TONES[priority] || PRIORITY_TONES.P3}`}>{priority}</span>;
}
export { TaskPriority, NeedsReview, buildReviewQueue };


export function TaskRow({ task, onPatch, canPatch }) {
  const [note, setNote] = useState("");
  const overdue = task.due_at && task.status !== "done" && task.due_at.slice(0, 10) < new Date().toISOString().slice(0, 10);
  const nextStatus = task.status === "todo" ? "in_progress" : task.status === "in_progress" ? "done" : "todo";
  return (
    <div className={`glass-row p-3 ${overdue ? "border-pink-500/30" : ""}`}>
      <div className="flex items-start gap-2">
        {canPatch && (
          <button
            onClick={() => onPatch(task.id, { status: nextStatus })}
            className="mt-0.5 grid h-4 w-4 shrink-0 cursor-pointer place-items-center rounded-full border border-violet-400 text-violet-300 transition hover:border-violet-500 hover:text-violet-300"
            title={`Mark ${nextStatus}`}
          >
            {task.status === "done" && <span className="text-[9px]">✓</span>}
          </button>
        )}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="mono text-[12.5px] text-slate-100">{task.title}</span>
            <TaskPriority priority={task.priority} />
            <span className="mono rounded border border-white/10 px-1.5 py-0.5 text-[9px] uppercase tracking-widest text-violet-200">{task.status}</span>
            {overdue && <span className="mono rounded border border-pink-500/40 px-1.5 py-0.5 text-[9px] uppercase tracking-widest text-pink-300">overdue</span>}
          </div>
          {task.description && <p className="mono mt-1 truncate text-[10.5px] text-violet-300">{task.description}</p>}
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10.5px] text-violet-300">
            {task.due_at && <span className="mono">{task.due_at.slice(0, 10)} due</span>}
            {task.linked_case_id && (
              <Link to={`/incidents/${task.linked_case_id}`} className="mono text-violet-300 underline-offset-2 hover:underline">incident {task.linked_case_id.slice(0, 8)}</Link>
            )}
            {task.created_by && <span className="mono text-violet-400">by {task.created_by}</span>}
          </div>
          {canPatch && (
            <div className="mt-2 flex items-center gap-2">
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && note.trim()) { onPatch(task.id, { note: note.trim() }); setNote(""); } }}
                placeholder="add a note (enter to post)"
                className="flex-1 rounded border border-white/10 bg-black/30 px-2 py-1 text-[11px] text-slate-200 outline-none placeholder:text-violet-400"
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function ClientTasks({ clientId, initial }) {
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
              <summary className="mono cursor-pointer text-[10px] uppercase tracking-widest text-violet-300">completed · {done.length}</summary>
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

export function AdminTaskManage({ clients, initial }) {
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
        {flash && <p className="mono mb-3 text-[11px] text-violet-300">✓ {flash}</p>}
        <form onSubmit={submit} className="space-y-3">
          <input value={title} onChange={(e) => setTitle(e.target.value)} required
            placeholder="Task title · what needs to be done"
            className="w-full rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-[12.5px] text-slate-100 outline-none placeholder:text-violet-400 focus:border-violet-600/50" />
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2}
            placeholder="Instructions / context for the client"
            className="w-full resize-none rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-[12px] text-slate-200 outline-none placeholder:text-violet-400 focus:border-violet-600/50" />
          <div className="grid gap-3 sm:grid-cols-3">
            <select value={clientId} onChange={(e) => setClientId(e.target.value)} required
              className="rounded-lg border border-white/10 bg-black/30 px-2 py-2 text-[12px] text-slate-100 outline-none focus:border-violet-600/50">
              <option value="">assign to…</option>
              {clients.map((c) => <option key={c.client_id} value={c.client_id}>{c.client_id}</option>)}
            </select>
            <select value={priority} onChange={(e) => setPriority(e.target.value)}
              className="rounded-lg border border-white/10 bg-black/30 px-2 py-2 text-[12px] text-slate-100 outline-none focus:border-violet-600/50">
              {["P1", "P2", "P3", "P4"].map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
            <input type="date" value={due} onChange={(e) => setDue(e.target.value)}
              className="rounded-lg border border-white/10 bg-black/30 px-2 py-2 text-[12px] text-slate-100 outline-none focus:border-violet-600/50" />
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
  // Glow + icon tint derive from the same tone so a card reads as one object.
  // The palette is one hue family, so the four cards are separated by tint
  // rather than hue: three calm purple steps and one urgent pink.
  const tones = {
    calm: { glow: "glow-cyan", icon: "text-[#a78bfa]" },
    brand: { glow: "glow-cyan", icon: "text-[#a855f7]" },
    info: { glow: "glow-cyan", icon: "text-[#c084fc]" },
    danger: { glow: "glow-red", icon: "text-[#ec4899]" },
  };
  const t = tones[tone] || tones.brand;
  return (
    <div className={`glass p-4 anim-fadeup ${t.glow}`} style={{ animationDelay: `${delay}ms` }}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="eyebrow truncate">{label}</p>
          <p className="mono mt-1.5 text-[24px] font-bold leading-none text-[#f5f0fb]">{value}</p>
          <p className="mt-2 text-[11px] leading-snug text-[#a78bc4]">{sub}</p>
        </div>
        <span className={`grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-white/10 bg-white/5 ${t.icon}`}>{icon}</span>
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