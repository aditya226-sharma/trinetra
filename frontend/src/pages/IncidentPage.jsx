import React, { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { getIncidentDetail, caseAction, enrichEntity } from "../lib/api";
import { SeverityBadge, SectionTitle, Empty } from "../components/ui";

const entityDot = (kind) => {
  const m = { ip: "bg-indigo-500", user: "bg-emerald-500", domain: "bg-cyan-500", client: "bg-violet-500", proc: "bg-amber-500" };
  return m[kind] || "bg-slate-500";
};

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

export default function IncidentPage({ role }) {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [enrich, setEnrich] = useState({});
  const enrichFetched = useRef(new Set());
  const canAct = role === "admin" || role === "analyst";

  useEffect(() => {
    let alive = true;
    getIncidentDetail(id)
      .then((d) => { if (alive) { setData(d); setError(""); } })
      .catch((e) => { if (alive) setError(e?.message || "failed to load incident"); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [id]);

  useEffect(() => {
    if (!data) return;
    const involved = data.involved || [];
    involved.filter((e) => e.kind === "ip" && e.value).forEach((e) => {
      const key = String(e.value);
      if (enrichFetched.current.has(key)) return;
      enrichFetched.current.add(key);
      enrichEntity("ip", key)
        .then((r) => setEnrich((m) => (m[key] ? m : { ...m, [key]: r })))
        .catch(() => {});
    });
  }, [data]);

  const act = (action, payload = {}) => {
    setBusy(true);
    caseAction(id, { action, note, ...payload })
      .then((r) => { setNote(""); setData({ ...data, case: r.case }); })
      .catch((e) => setError(e?.message || `action ${action} failed`))
      .finally(() => setBusy(false));
  };

  if (loading) return <div className="page-wide anim-fadeup"><div className="mono text-[12px] text-slate-500">Loading incident context…</div></div>;

  const incident = data || {};
  const c = incident.case || {};
  const involved = incident.involved || [];
  const timeline = incident.timeline || [];
  const graph = incident.graph || { nodes: [], edges: [] };

  return (
    <div className="page-wide space-y-5 anim-fadeup">
      <button onClick={() => navigate(-1)} className="mono text-[11px] text-slate-500 hover:text-slate-300">← back</button>

      <section className="glass p-5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="mono text-[18px] font-semibold text-slate-100">{c.threat_class || "Incident"}</span>
          <SeverityBadge severity={c.severity} />
          <StatusBadge status={c.status} />
          {c.client_id && <span className="mono rounded border border-violet-500/30 bg-violet-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-violet-300">{c.client_id}</span>}
          {c.assignee && <span className="mono text-[11px] text-emerald-300">investigator @{c.assignee}</span>}
        </div>
        <p className="mono mt-2 text-[11px] uppercase tracking-widest text-slate-500">{c.message || "—"}</p>
        <div className="mt-2 flex flex-wrap gap-3 text-[10.5px] text-slate-500">
          {c.id && <span className="mono">case {c.id}</span>}
          {c.source_kind && <span className="mono">source {c.source_kind}</span>}
          {c.first_seen && <span className="mono">first_seen {c.first_seen}</span>}
        </div>
        {canAct && (
          <div className="mt-4 flex flex-wrap items-center gap-2">
            {c.status !== "investigation" && c.status !== "closed" && (
              <button onClick={() => act("investigate")} disabled={busy} className="btn-primary mono !py-1.5 text-[10.5px]">investigate</button>
            )}
            {c.status !== "open" && c.status !== "investigation" && (
              <button onClick={() => act("reopen")} disabled={busy} className="btn-ghost mono !py-1.5 text-[10.5px]">reopen</button>
            )}
            {c.status === "open" || c.status === "investigation" ? (
              <button onClick={() => act("close")} disabled={busy} className="btn-ghost mono !py-1.5 text-[10.5px]">close</button>
            ) : null}
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="note for your action…"
              className="w-56 rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-[11px] text-slate-200 outline-none placeholder:text-slate-600 focus:border-emerald-500/50"
            />
            {c.status === "open" || c.status === "investigation" ? (
              <button onClick={() => act("assign", { assignee: "soc" })} disabled={busy} className="btn-ghost mono !py-1.5 text-[10.5px]">assign to soc</button>
            ) : null}
          </div>
        )}
      </section>

      <div className="grid gap-5 lg:grid-cols-2">
        <section className="glass p-5">
          <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">entity attribution</span>}>
            Involved parties
          </SectionTitle>
          {involved.length === 0 ? (
            <Empty title="No entity attribution" hint="The analyzer attributed no entities to this incident." />
          ) : (
            <div className="mt-3 space-y-2">
              {involved.map((e, i) => {
                const key = String(e.value);
                const meta = enrich[key] || {};
                const geo = meta.geo || {};
                const intel = meta.intel || {};
                return (
                  <div key={`${e.kind}-${e.value}-${i}`} className="glass-row p-3">
                    <div className="flex items-center gap-2">
                      <span className={`h-2 w-2 shrink-0 rounded-full ${entityDot(e.kind)}`} />
                      <span className="mono text-[10px] uppercase tracking-widest text-slate-500">{e.kind}</span>
                      <span className="mono truncate text-[13px] text-slate-100">{e.label || e.value}</span>
                      {typeof e.events === "number" && <span className="ml-auto mono text-[10.5px] text-slate-500">{e.events} events</span>}
                    </div>
                    {(geo.country || geo.city || geo.asn || intel.verdict) && (
                      <div className="mt-2 flex flex-wrap gap-1.5 text-[10px]">
                        {geo.country && <span className="mono rounded border border-white/10 px-1.5 py-0.5 text-slate-400">📍 {geo.country}{geo.city ? ` · ${geo.city}` : ""}</span>}
                        {geo.asn && <span className="mono rounded border border-white/10 px-1.5 py-0.5 text-slate-400">AS{geo.asn}</span>}
                        {geo.registered_country && <span className="mono rounded border border-white/10 px-1.5 py-0.5 text-slate-600">reg {geo.registered_country}</span>}
                        {intel.verdict && <span className={`mono rounded border px-1.5 py-0.5 ${intel.verdict === "malicious" ? "border-rose-500/40 text-rose-300" : intel.verdict === "suspicious" ? "border-amber-500/40 text-amber-300" : "border-emerald-500/40 text-emerald-300"}`}>{intel.verdict}</span>}
                        {intel.confidence && <span className="mono text-slate-600">conf {intel.confidence}</span>}
                        {intel.source && <span className="mono text-slate-600">via {intel.source}</span>}
                        {(geo.lat != null && geo.lon != null) && <span className="mono text-[9.5px] text-slate-600">{geo.lat.toFixed(2)},{geo.lon.toFixed(2)}</span>}
                      </div>
                    )}
                    {(e.activity || []).length > 0 && (
                      <div className="mt-2 space-y-0.5">
                        {e.activity.map((a, ai) => (
                          <p key={ai} className="mono truncate text-[9.5px] text-slate-600">
                            <span className="text-slate-500">{a.event_type}</span> — {String(a.summary || a.message || "").slice(0, 70)}
                          </p>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <section className="glass p-5">
          <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">investigation trail</span>}>
            Timeline
          </SectionTitle>
          {timeline.length === 0 ? (
            <Empty title="No activity yet" hint="Investigator actions will appear here." />
          ) : (
            <div className="mt-3 space-y-1.5">
              {timeline.map((t, ti) => (
                <p key={ti} className="mono text-[10.5px] text-slate-400">
                  <span className="text-slate-600">{t.ts}</span>{" "}
                  <span className={t.action === "created" ? "text-slate-500" : "text-emerald-300"}>{t.action}</span>
                  {" by "}<span className="text-slate-400">{t.actor}</span>
                  {t.detail && <span className="text-slate-500"> — {t.detail}</span>}
                  {t.note && <span className="text-amber-300/80"> (“{t.note}”)</span>}
                </p>
              ))}
            </div>
          )}
        </section>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <section className="glass p-5">
          <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">who connects to whom</span>}>
            Incident graph
          </SectionTitle>
          <div className="mt-3">
            <IncidentGraph graph={graph} />
          </div>
        </section>

        <section className="glass p-5">
          <SectionTitle right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">correlated evidence</span>}>
            Evidence
          </SectionTitle>
          {Object.keys(incident.evidence || c.evidence || {}).length === 0 ? (
            <Empty title="No evidence captured" hint="Supporting events will be listed here." />
          ) : (
            <div className="mt-3 space-y-1.5">
              {Object.values(incident.evidence || c.evidence || {}).slice(0, 8).map((ev, i) => {
                if (typeof ev !== "object") return <p key={i} className="mono text-[10.5px] text-slate-500">{String(ev)}</p>;
                return (
                  <div key={i} className="glass-row p-2.5">
                    <p className="mono text-[10px] uppercase tracking-widest text-cyan-300">{ev.event_type || ev.threat_class || ev.kind || `evidence ${i + 1}`}</p>
                    <p className="mono mt-0.5 text-[10.5px] text-slate-400">
                      {String(ev.summary || ev.message || ev.src_ip || ev.dst_ip || JSON.stringify(ev)).slice(0, 110)}
                    </p>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>

      {!canAct && <p className="mono text-[10px] uppercase tracking-widest text-slate-600">read-only view · manage this incident in the alert queue</p>}
    </div>
  );
}

function IncidentGraph({ graph }) {
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  if (nodes.length === 0) return <div className="glass-row p-3 text-[11px] text-slate-500">No graph data for this incident yet.</div>;
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