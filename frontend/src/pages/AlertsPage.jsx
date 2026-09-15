import React, { useEffect, useMemo, useState } from "react";
import { caseAction, getCases } from "../lib/api";
import { PageHeader, LiveBadge, SeverityBadge, CodeBlock, Empty, PlainBadge } from "../components/ui";

const POLL_MS = 5000;
const STATUS_FILTERS = ["", "unresolved", "open", "acknowledged", "resolved"];
const SEVERS = ["", "critical", "high", "warning", "info"];

export default function AlertsPage() {
  const [data, setData] = useState({ cases: [], stats: null });
  const [statusFilter, setStatusFilter] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [expandedId, setExpandedId] = useState(null);
  const [assignees, setAssignees] = useState({});
  const [notes, setNotes] = useState({});
  const [busy, setBusy] = useState({});
  const [error, setError] = useState(null);

  useEffect(() => {
    let alive = true;
    const tick = () =>
      getCases({ limit: 200, status: statusFilter || undefined, severity: sevFilter || undefined })
        .then((d) => { if (alive) { setData(d); setError(null); } })
        .catch((e) => alive && setError(e.message));
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => { alive = false; clearInterval(id); };
  }, [statusFilter, sevFilter]);

  const { cases, stats } = data;
  const statsSev = stats?.unresolved_by_severity || {};

  const act = async (id, action, extra = {}) => {
    setBusy((b) => ({ ...b, [id]: action }));
    try {
      await caseAction(id, { action, ...extra });
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    } finally {
      setBusy((b) => { const n = { ...b }; delete n[id]; return n; });
    }
    const fresh = await getCases({ limit: 200, status: statusFilter || undefined, severity: sevFilter || undefined }).catch(() => null);
    if (fresh) setData(fresh);
  };

  const visible = (statusFilter ? cases : cases.filter((c) => c.status !== "resolved"));

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="soc · alert cases · triage lifecycle"
        title="Alert queue"
        sub="Every pipeline verdict and policy hit becomes a durable case — acknowledge, assign, resolve, and annotate. External delivery fans out at your configured severity floor."
        actions={<LiveBadge text={`Poll 5s · ${stats?.total ?? 0} cases`} />}
      />

      {/* case counters */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-5 anim-fadeup">
        <Tile label="total cases" value={stats?.total ?? 0} tone="tone-slate" />
        <Tile label="open" value={stats?.by_status?.open ?? 0} tone="tone-danger" />
        <Tile label="acknowledged" value={stats?.by_status?.acknowledged ?? 0} tone="tone-warn" />
        <Tile label="resolved" value={stats?.by_status?.resolved ?? 0} tone="tone-info" />
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
                  <button onClick={() => setExpandedId(open ? null : c.id)} className="flex w-full items-center gap-3 p-4 text-left">
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
                        {c.message || c.threat_class} · {c.source_value || "—"} {c.timestamp && `· ${c.timestamp}`}
                        {c.assignee && <span className="text-emerald-300"> · @{c.assignee}</span>}
                      </p>
                    </div>
                    <span className="text-slate-600 transition group-hover:text-emerald-300">{open ? "−" : "+"}</span>
                  </button>

                  {open && (
                    <div className="border-t border-white/5 bg-black/30 p-4">
                      <div className="mb-3 flex flex-wrap items-center gap-2">
                        {c.status === "open" && <ActionBtn onClick={() => act(c.id, "ack")} busy={busy[c.id]} label="Acknowledge" />}
                        {c.status === "acknowledged" && (
                          <>
                            <ActionBtn onClick={() => act(c.id, "resolve")} busy={busy[c.id]} label="Resolve" variant="danger" />
                            <ActionBtn onClick={() => act(c.id, "unack")} busy={busy[c.id]} label="Reopen" variant="ghost" />
                          </>
                        )}
                        {c.status === "resolved" && <ActionBtn onClick={() => act(c.id, "reopen")} busy={busy[c.id]} label="Reopen" variant="ghost" />}
                        {c.status !== "resolved" && <ActionBtn onClick={() => act(c.id, "resolve")} busy={busy[c.id]} label="Resolve" variant="danger" />}
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
                      </div>

                      <p className="eyebrow mb-2">Supporting evidence</p>
                      <CodeBlock maxH="max-h-48">{JSON.stringify(c.evidence || {}, null, 2)}</CodeBlock>

                      {(c.timeline?.length || 0) > 0 && (
                        <>
                          <p className="eyebrow mb-2 mt-4">Timeline</p>
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
    acknowledged: "text-amber-300 border-amber-500/30 bg-amber-500/10",
    resolved: "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
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