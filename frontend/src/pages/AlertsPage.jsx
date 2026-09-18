import React, { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { caseAction, getCases, getIncidentDetail } from "../lib/api";
import { PageHeader, LiveBadge, SeverityBadge, CodeBlock, Empty, PlainBadge } from "../components/ui";

const POLL_MS = 5000;
const STATUS_FILTERS = ["", "unresolved", "open", "investigation", "closed"];
const SEVERS = ["", "critical", "high", "warning", "info"];
const KINDS = ["", "flow", "watch", "block", "rule"];
const SORTS = ["newest", "oldest", "severity", "hits"];

export default function AlertsPage({ role }) {
  const canTriage = role === "admin" || role === "analyst";
  const [data, setData] = useState({ cases: [], stats: null });
  const [statusFilter, setStatusFilter] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [kindFilter, setKindFilter] = useState("");
  const [assigneeFilter, setAssigneeFilter] = useState("");
  const [sortBy, setSortBy] = useState("newest");
  const [sel, setSel] = useState({});
  const [expandedId, setExpandedId] = useState(null);
  const [assignees, setAssignees] = useState({});
  const [notes, setNotes] = useState({});
  const [busy, setBusy] = useState({});
  const [bulkBusy, setBulkBusy] = useState(false);
  const [error, setError] = useState(null);
  const [incidentData, setIncidentData] = useState(null);
  const [incidentLoading, setIncidentLoading] = useState(false);
  const reqSeq = useRef(0);

  const fetchCases = () => {
    const my = ++reqSeq.current;
    return getCases({ limit: 500, status: statusFilter || undefined, severity: sevFilter || undefined })
      .then((d) => { if (my === reqSeq.current) { setData(d); setError(null); } })
      .catch((e) => { if (my === reqSeq.current) setError(e.message); });
  };

  useEffect(() => {
    let alive = true;
    const tick = () => {
      const my = ++reqSeq.current;
      return getCases({ limit: 500, status: statusFilter || undefined, severity: sevFilter || undefined })
        .then((d) => { if (alive && my === reqSeq.current) { setData(d); setError(null); } })
        .catch((e) => alive && setError(e.message));
    };
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => { alive = false; clearInterval(id); };
  }, [statusFilter, sevFilter]);

  const { cases, stats } = data;
  const statsSev = stats?.unresolved_by_severity || {};

  const refresh = (fresh) => {
    if (fresh) { setData(fresh); return; }
    fetchCases();
  };

  const act = async (id, action, extra = {}) => {
    setBusy((b) => ({ ...b, [id]: action }));
    try {
      await caseAction(id, { action, ...extra });
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    } finally {
      setBusy((b) => { const n = { ...b }; delete n[id]; return n; });
    }
    refresh();
  };

  const actAll = async (action, extra = {}) => {
    const ids = Object.keys(sel).filter((k) => sel[k]);
    if (!ids.length) return;
    setBulkBusy(true);
    let failed = 0;
    for (const id of ids) {
      try { await caseAction(id, { action, ...extra }); } catch { failed += 1; }
    }
    setBulkBusy(false);
    setSel({});
    if (failed) setError(`${failed} case(s) failed — check permission.`);
    refresh();
  };

  const baseQueue = statusFilter ? cases : cases.filter((c) => c.status !== "closed");

  const visible = useMemo(() => {
    let out = baseQueue;
    if (kindFilter) out = out.filter((c) => (c.source_kind || "") === kindFilter);
    if (assigneeFilter) {
      if (assigneeFilter === "unassigned") out = out.filter((c) => !c.assignee);
      else out = out.filter((c) => (c.assignee || "") === assigneeFilter);
    }
    const sevRank = { critical: 0, high: 1, warning: 2, error: 3, info: 4, low: 5 };
    const ts = (c) => (c.last_seen || c.timestamp || "");
    const sorted = [...out];
    if (sortBy === "newest") sorted.sort((a, b) => ts(b).localeCompare(ts(a)));
    else if (sortBy === "oldest") sorted.sort((a, b) => ts(a).localeCompare(ts(b)));
    else if (sortBy === "severity") sorted.sort((a, b) => (sevRank[a.severity] ?? 6) - (sevRank[b.severity] ?? 6));
    else if (sortBy === "hits") sorted.sort((a, b) => (b.hits || 0) - (a.hits || 0));
    return sorted;
  }, [baseQueue, kindFilter, assigneeFilter, sortBy]);

  const selectedIds = Object.keys(sel).filter((k) => sel[k]);
  const assigneeChoices = [...new Set(cases.map((c) => c.assignee).filter(Boolean))];

  const exportCsv = () => {
    const head = ["id", "threat_class", "severity", "status", "kind", "source_value", "assignee", "hits", "created", "last_seen", "message"];
    const rows = [head];
    for (const c of visible) {
      rows.push([c.id, c.threat_class, c.severity, c.status, c.source_kind || "", c.source_value || "", c.assignee || "", c.hits || "", c.timestamp || "", c.last_seen || "", String(c.message || "").replace(/\n/g, " ")]);
    }
    const blob = new Blob([rows.map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n")], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `trinetra-cases-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const openIncident = (id) => {
    setExpandedId(id);
    if (!id) { setIncidentData(null); return; }
    setIncidentLoading(true);
    getIncidentDetail(id)
      .then((d) => setIncidentData(d))
      .catch(() => setIncidentData(null))
      .finally(() => setIncidentLoading(false));
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="soc · alert cases · triage lifecycle"
        title="Alert queue"
        sub="Every pipeline verdict and policy hit becomes a durable case — investigate, assign, close, and annotate. External delivery fans out at your configured severity floor."
        actions={
          <div className="flex items-center gap-2">
            <LiveBadge text={`Poll 5s · ${stats?.total ?? 0} cases`} />
            {!canTriage && <PlainBadge cls="!text-slate-400">read-only</PlainBadge>}
          </div>
        }
      />

      {/* case counters */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-5 anim-fadeup">
        <Tile label="total cases" value={stats?.total ?? 0} tone="tone-slate" />
        <Tile label="open" value={stats?.by_status?.open ?? 0} tone="tone-danger" />
        <Tile label="investigation" value={stats?.by_status?.investigation ?? 0} tone="tone-warn" />
        <Tile label="closed" value={stats?.by_status?.closed ?? 0} tone="tone-info" />
        <Tile label="critical open" value={statsSev.critical ?? 0} tone="tone-danger" />
      </div>

      {error && <div className="text-sm text-rose-400">{error}</div>}

      {/* filters */}
      <div className="flex flex-wrap items-center gap-2 anim-fadeup">
        <span className="eyebrow mr-1">STATUS</span>
        {STATUS_FILTERS.map((s) => (
          <button key={s || "all"} onClick={() => setStatusFilter(s)} className={`chip ${statusFilter === s ? "chip-on" : ""}`}>
            {s === "" ? "live queue" : s}
          </button>
        ))}
        <span className="eyebrow ml-4 mr-1">SEVERITY</span>
        {SEVERS.map((s) => (
          <button key={s || "all"} onClick={() => setSevFilter(s)} className={`chip ${sevFilter === s ? "chip-on" : ""}`}>
            {s === "" ? "all" : s}
          </button>
        ))}
        <span className="eyebrow ml-4 mr-1">KIND</span>
        <select value={kindFilter} onChange={(e) => setKindFilter(e.target.value)} className="field mono px-2 py-1.5 text-[10.5px]">
          {KINDS.map((k) => <option key={k} value={k}>{k === "" ? "all kinds" : k}</option>)}
        </select>
        <span className="eyebrow ml-3 mr-1">ASSIGNEE</span>
        <select value={assigneeFilter} onChange={(e) => setAssigneeFilter(e.target.value)} className="field mono px-2 py-1.5 text-[10.5px]">
          <option value="">anyone</option>
          {assigneeChoices.map((a) => <option key={a} value={a}>@{a}</option>)}
          <option value="unassigned">unassigned</option>
        </select>
        <span className="eyebrow ml-3 mr-1">SORT</span>
        <select value={sortBy} onChange={(e) => setSortBy(e.target.value)} className="field mono px-2 py-1.5 text-[10.5px]">
          {SORTS.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <div className="ml-auto flex items-center gap-2">
          {canTriage && selectedIds.length > 0 && (
            <>
              <button onClick={() => actAll("investigate")} disabled={bulkBusy} className="btn-primary mono !px-3 !py-1.5 text-[10.5px]">
                {bulkBusy ? "…" : `investigate ${selectedIds.length}`}
              </button>
              <button onClick={() => actAll("close")} disabled={bulkBusy} className="btn-primary mono !px-3 !py-1.5 text-[10.5px] !bg-rose-500/90 hover:!bg-rose-400">
                {bulkBusy ? "…" : `close ${selectedIds.length}`}
              </button>
            </>
          )}
          <button onClick={exportCsv} className="btn-ghost mono !px-3 !py-1.5 text-[10.5px]">export csv ({visible.length})</button>
        </div>
      </div>

      {visible.length === 0 ? (
        <Empty title="Queue is clear" hint="Verdicts and policy hits land here as cases; nothing matches your filters right now." />
      ) : (
        <div className="relative space-y-3 pl-6 anim-fadeup">
          <span className="absolute bottom-2 left-[7px] top-2 w-px bg-gradient-to-b from-emerald-500/40 via-white/10 to-transparent" aria-hidden />
          {visible.map((c, i) => {
            const open = expandedId === c.id;
            return (
              <div key={c.id} className="relative feed-in" style={{ animationDelay: `${i * 35}ms` }}>
                <span className={`absolute -left-6 top-4 h-3 w-3 rounded-full border-2 border-[#05080f] ${dotCls(c.severity)} ${c.severity === "critical" ? "pulse-dot-red" : ""}`} />
                <div className={`glass-row overflow-hidden ${open ? "border-emerald-500/30" : ""}`}>
                  <button onClick={() => openIncident(open ? null : c.id)} className="flex w-full items-center gap-3 p-4 text-left">
                    {canTriage && (
                      <span
                        role="checkbox"
                        aria-checked={!!sel[c.id]}
                        tabIndex={0}
                        onClick={(e) => { e.stopPropagation(); setSel((s) => ({ ...s, [c.id]: !s[c.id] })); }}
                        onKeyDown={(e) => { if (e.key === "Enter") { e.stopPropagation(); setSel((s) => ({ ...s, [c.id]: !s[c.id] })); } }}
                        onMouseDown={(e) => e.stopPropagation()}
                        className={`grid h-4 w-4 shrink-0 place-items-center rounded border text-[9px] ${sel[c.id] ? "border-emerald-400 bg-emerald-500 text-white" : "border-white/20"}`}
                      >
                        {sel[c.id] ? "✓" : ""}
                      </span>
                    )}
                    <span className={`sev-strip ${stripCls(c.severity)}`} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="mono text-[13.5px] font-semibold text-slate-100">{c.threat_class}</span>
                        <SeverityBadge severity={c.severity} />
                        <StatusBadge status={c.status} />
                        <PlainBadge cls="!text-cyan-300">{c.source_kind}</PlainBadge>
                        {c.hits > 1 && <PlainBadge cls="!text-slate-300">hits {c.hits}</PlainBadge>}
                      </div>
                      <p className="mono mt-1 text-[11px] uppercase tracking-widest text-slate-500">
                        {c.message || c.threat_class} · {c.source_value || "—"} {c.timestamp && ` · ${c.timestamp}`}
                        {c.assignee && <span className="text-emerald-300"> · @{c.assignee}</span>}
                      </p>
                    </div>
                    <span className="text-slate-600 transition group-hover:text-emerald-300">{open ? "−" : "+"}</span>
                  </button>

                  {open && (
                    <div className="border-t border-white/5 bg-black/30 p-4">
                      <div className="mb-3 flex flex-wrap items-center gap-2">
                        {!canTriage ? (
                          <span className="mono text-[10.5px] uppercase tracking-widest text-slate-500">read-only queue — an admin or analyst owns this case</span>
                        ) : (
                          <>
                            {c.status === "open" && <ActionBtn onClick={() => act(c.id, "investigate")} busy={busy[c.id]} label="Investigate" />}
                            {c.status === "investigation" && (
                              <>
                                <ActionBtn onClick={() => act(c.id, "close")} busy={busy[c.id]} label="Close" variant="danger" />
                                <ActionBtn onClick={() => act(c.id, "uninvestigate")} busy={busy[c.id]} label="Back to open" variant="ghost" />
                              </>
                            )}
                            {c.status === "closed" && <ActionBtn onClick={() => act(c.id, "reopen")} busy={busy[c.id]} label="Reopen" variant="ghost" />}
                            {c.status === "open" && <ActionBtn onClick={() => act(c.id, "close")} busy={busy[c.id]} label="Close" variant="danger" />}
                            <input
                              value={assignees[c.id] || ""}
                              onChange={(e) => setAssignees((a) => ({ ...a, [c.id]: e.target.value }))}
                              placeholder="assign to…"
                              className="field mono w-40 px-3 py-1.5 text-[11px]"
                            />
                            <ActionBtn onClick={() => act(c.id, "assign", { assignee: assignees[c.id] || "" })} label="Assign" variant="ghost" />
                            <input
                              value={notes[c.id] || ""}
                              onChange={(e) => setNotes((a) => ({ ...a, [c.id]: e.target.value }))}
                              placeholder="add note…"
                              className="field mono w-56 px-3 py-1.5 text-[11px]"
                              onKeyDown={(e) => { if (e.key === "Enter" && notes[c.id]) { act(c.id, "note", { note: notes[c.id] }); setNotes((a) => ({ ...a, [c.id]: "" })); } }}
                            />
                          </>
                        )}
                      </div>

                      <p className="eyebrow mb-2">Supporting evidence</p>
                      <CodeBlock maxH="max-h-48">{JSON.stringify(c.evidence || {}, null, 2)}</CodeBlock>

                      {(c.timeline?.length || 0) > 0 && (
                        <>
                          <p className="eyebrow mb-2 mt-4">Activity timeline · who did what</p>
                          <div className="space-y-1">
                            {c.timeline.map((t, ti) => (
                              <p key={ti} className="mono text-[10.5px] text-slate-500">
                                <span className="text-slate-600">{t.ts}</span>{"  "}
                                <span className={t.action === "created" ? "text-slate-400" : "text-emerald-300"}>{t.action}</span>
                                {" by "}<span className="text-slate-400">{t.actor}</span>
                                {t.detail && <span className="text-slate-500"> — {t.detail}</span>}
                                {t.note && <span className="text-amber-300/80"> (“{t.note}”)</span>}
                              </p>
                            ))}
                          </div>
                        </>
                      )}

                      <IncidentPanel data={incidentData} loading={incidentLoading} />
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function IncidentPanel({ data, loading }) {
  if (loading) return <p className="eyebrow mt-4">Loading incident context…</p>;
  if (!data) return null;
  const { case: incident, involved = [], graph = { nodes: [], edges: [] } } = data;
  return (
    <div className="mt-4">
      <Link to={`/incidents/${incident?.id || ""}`} className="mono text-[10.5px] text-cyan-300 underline-offset-2 hover:underline">
        open dedicated incident view →
      </Link>
      <div className="mt-3 grid gap-4 lg:grid-cols-2">
      <div>
        <p className="eyebrow mb-2">Involved parties · who is implicated</p>
        {involved.length === 0 ? (
          <p className="text-[11.5px] text-slate-500">No entity attribution recorded for this incident.</p>
        ) : (
          <div className="space-y-1.5">
            {involved.map((e, i) => (
              <div key={`${e.kind}-${e.value}-${i}`} className="glass-row flex items-center gap-2 p-2.5">
                <span className={`h-2 w-2 shrink-0 rounded-full ${kindDot(e.kind)}`} />
                <span className="mono text-[10px] uppercase tracking-widest text-slate-500">{e.kind}</span>
                <span className="mono truncate text-[12px] text-slate-200">{e.label || e.value}</span>
                {typeof e.events === "number" && (
                  <span className="ml-auto mono text-[10.5px] text-slate-500">{e.events} events</span>
                )}
              </div>
            ))}
          </div>
        )}

        <p className="eyebrow mb-2 mt-4">Incident graph</p>
        <IncidentGraph graph={graph} />

        {Array.isArray(incident?.timeline) && incident.timeline.length > 0 && (
          <>
            <p className="eyebrow mb-2 mt-4">Investigators · activity trail</p>
            <div className="space-y-1">
              {incident.timeline.map((t, ti) => (
                <p key={ti} className="mono text-[10.5px] text-slate-500">
                  <span className="text-slate-600">{t.ts}</span>{" "}
                  <span className={t.action === "created" ? "text-slate-400" : "text-emerald-300"}>{t.action}</span>
                  {" by "}<span className="text-slate-400">{t.actor}</span>
                  {t.detail && <span className="text-slate-500"> — {t.detail}</span>}
                </p>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
    </div>
  );
}

function IncidentGraph({ graph }) {
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  if (nodes.length === 0) {
    return <div className="glass-row border border-white/5 p-3 text-[11px] text-slate-500">No graph data for this incident yet.</div>;
  }
  const rows = nodes.map((n, i) => ({
    node: n,
    x: 18 + (i % 3) * 130 + (i % 2) * 18,
    y: 22 + Math.floor(i / 3) * 56 + (i % 2) * 12,
  }));
  const byId = {};
  nodes.forEach((n) => { byId[n.id] = n; });
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

const kindDot = (kind) => {
  const m = { ip: "bg-indigo-500", user: "bg-emerald-500", domain: "bg-cyan-500", client: "bg-violet-500", proc: "bg-amber-500" };
  return m[kind] || "bg-slate-500";
};

function ActionBtn({ onClick, busy, label, variant = "primary" }) {
  const cls = {
    primary: "btn-primary mono !px-3 !py-1.5 text-[10.5px]",
    danger: "btn-primary mono !px-3 !py-1.5 text-[10.5px] !bg-rose-500/90 hover:!bg-rose-400",
    ghost: "btn-ghost mono !px-3 !py-1.5 text-[10.5px]",
  }[variant];
  return (
    <button onClick={onClick} disabled={busy} className={cls}>
      {busy ? "…" : label}
    </button>
  );
}

function StatusBadge({ status }) {
  const map = {
    open: "text-rose-300 border-rose-500/30 bg-rose-500/10",
    investigation: "text-amber-300 border-amber-500/30 bg-amber-500/10",
    closed: "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
  };
  return (
    <span className={`mono rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-widest ${map[status] || ""}`}>
      {status}
    </span>
  );
}

function Tile({ label, value, tone }) {
  const tones = {
    "tone-danger": "text-grad-danger glow-red text-[24px] mono font-bold",
    "tone-warn": "text-[24px] mono font-bold text-amber-300",
    "tone-info": "text-[24px] mono font-bold text-sky-300",
    "tone-slate": "text-[24px] mono font-bold text-slate-200",
  };
  return (
    <div className={`glass p-4 ${tone === "tone-danger" ? "glow-red" : ""}`}>
      <p className={`${tones[tone]} leading-none`}>{value}</p>
      <p className="eyebrow mt-2">{label}</p>
    </div>
  );
}

const stripCls = (sev) => {
  const m = { critical: "sev-critical", high: "sev-high", medium: "sev-warning", warning: "sev-warning", error: "sev-error", info: "sev-info", low: "sev-info" };
  return m[sev] || "sev-info";
};
const dotCls = (sev) => {
  const m = { critical: "bg-rose-500", high: "bg-orange-500", warning: "bg-amber-400", error: "bg-violet-500", info: "bg-sky-500", low: "bg-sky-500" };
  return m[sev] || "bg-sky-500";
};