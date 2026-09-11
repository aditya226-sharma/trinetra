import React, { useEffect, useState } from "react";
import { getDashboard, getClients } from "../lib/api";
import { SeverityBadge, LiveBadge, PulseDot, SectionTitle, Empty } from "../components/ui";
import { Donut, Sparkline, ScoreRing } from "../components/charts";

const DONUT_COLORS = ["#34d399", "#22d3ee", "#818cf8", "#fbbf24", "#f472b6", "#f87171", "#60a5fa"];

const PIPELINE = [
  { id: "normalize", label: "Normalize" },
  { id: "dedup", label: "Dedup" },
  { id: "modules", label: "Modules A·B·C" },
  { id: "analyze", label: "Analyzer" },
];

export default function DashboardPage() {
  const [data, setData] = useState(null);
  const [clients, setClients] = useState([]);
  const [error, setError] = useState(null);

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

  const s = data.stats || {};
  const threats = data.threat_detections || {};
  const findings = (data.findings || []).slice(-6).reverse();
  const vpn = data.vpn?.profiles || [];
  const g = data.graph_summary || {};
  const top = clients.slice().sort((a, b) => b.events - a.events);

  const eventsSpark = top.map((c) => c.events);
  const threatVals = Object.values(threats).map(Number);

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
        <KpiCard
          label="Events ingested"
          value={s.events ?? 0}
          sub={`${s.raw_lines ?? 0} raw lines · ${Math.round((data.dedup_rate || 0) * 100)}% dedup`}
          tone="emerald"
          icon={<ChartIcon />}
          spark={{ values: eventsSpark, color: "#34d399" }}
          delay={0}
        />
        <KpiCard
          label="Deduplication rate"
          value={`${Math.round((data.dedup_rate || 0) * 100)}%`}
          sub="fingerprint-based corpus"
          tone="cyan"
          icon={<DedupIcon />}
          spark={{ values: [70, 76, 74, 80, 79, 78, 82].map((v) => 0), color: "#22d3ee" }}
          delay={60}
        />
        <KpiCard
          label="Module findings"
          value={s.findings ?? 0}
          sub={`${s.alerts_sent ?? 0} alerts sent to analyst queue`}
          tone="danger"
          icon={<ThreatIcon />}
          spark={{ values: threatVals.length ? threatVals : [1], color: "#f43f5e" }}
          delay={120}
        />
        <KpiCard
          label="Entity graph"
          value={`${g.nodes ?? 0}N / ${g.edges ?? 0}E`}
          sub={`${g.threatened?.length || 0} assets impacted`}
          tone="violet"
          icon={<GraphIcon />}
          spark={{ values: top.map((c) => c.events), color: "#22d3ee" }}
          delay={180}
        />
      </div>

      {/* radar + clients */}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {/* threat detections */}
          <section className="glass p-5 anim-fadeup">
            <SectionTitle
              right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">Module A · flow heuristics</span>}
            >
              Threat radar
            </SectionTitle>
            {Object.keys(threats).length === 0 ? (
              <Empty title="No detections recorded" hint="Run the demo dataset to arm the radar." />
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
                        <div
                          className="bar-grow h-full rounded-full"
                          style={{
                            width: `${(count / max) * 100}%`,
                            background: "linear-gradient(90deg,#059669,#10b981,#f43f5e)",
                            boxShadow: "0 0 12px rgba(244,63,94,0.5)",
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          {/* latest findings */}
          <section className="glass p-5 anim-fadeup">
            <SectionTitle
              right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">analyzer verdict feed</span>}
            >
              Latest findings
            </SectionTitle>
            {findings.length === 0 ? (
              <Empty title="No findings yet" hint="Run the demo dataset to populate the analyzer feed." />
            ) : (
              <div className="space-y-2">
                {findings.map((f, i) => {
                  const alert = f.alert || f;
                  return (
                    <div key={i} className="glass-row flex items-center gap-3 p-3 feed-in" style={{ animationDelay: `${i * 60}ms` }}>
                      <span className={`sev-strip ${sevStrip(alert.severity)}`} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="mono text-[12.5px] text-slate-100">{alert.threat_class}</span>
                          <span className="mono text-[10px] text-slate-500">conf {alert.confidence}</span>
                        </div>
                        <p className="mono mt-0.5 text-[10px] uppercase tracking-widest text-slate-500">
                          {alert.verdict} · {alert.store_decision}
                        </p>
                      </div>
                      <SeverityBadge severity={alert.severity} />
                    </div>
                  );
                })}
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
                <Donut
                  size={172}
                  thickness={17}
                  centerValue={s.events ?? 0}
                  centerLabel="events"
                  segments={top.map((c, i) => ({
                    value: c.events,
                    color: DONUT_COLORS[i % DONUT_COLORS.length],
                  }))}
                />
              </div>
              <div className="mt-2 space-y-1.5">
                {top.map((c, i) => (
                  <div key={c.client_id} className="flex items-center gap-2 text-[12px]">
                    <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: DONUT_COLORS[i % DONUT_COLORS.length], boxShadow: `0 0 8px ${DONUT_COLORS[i % DONUT_COLORS.length]}` }} />
                    <span className="mono truncate text-slate-300">{c.client_id}</span>
                    <span className="text-[10px] text-slate-600">{(c.source_types || [c.source_type]).filter(Boolean).join(", ")}</span>
                    <span className="ml-auto mono tabular-nums text-slate-500">{c.events}</span>
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
          <Empty title="No PCAP captures assessed" hint="Feed ipsec_*.pcap captures through Module B." />
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {vpn.map((p, i) => {
              const tone = p.risk_level === "critical" ? "#f43f5e" : p.risk_level === "high" ? "#fb923c" : "#34d399";
              return (
                <div key={i} className="glass-row flex items-center gap-4 p-4 feed-in" style={{ animationDelay: `${i * 70}ms` }}>
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

/* ------------------------------------------------------------------ local pieces */
function KpiCard({ label, value, sub, tone, icon, spark, delay }) {
  const tones = {
    emerald: "glow-emerald",
    cyan: "glow-cyan",
    danger: "glow-red",
    violet: "glow-cyan",
  };
  return (
    <div className={`glass p-4 anim-fadeup ${tones[tone]}`} style={{ animationDelay: `${delay}ms` }}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="eyebrow truncate">{label}</p>
          <p className="mono mt-1.5 text-[24px] font-bold leading-none text-slate-50">{value}</p>
          <p className="mt-2 text-[11px] leading-snug text-slate-500">{sub}</p>
        </div>
        <span className={`grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-white/10 bg-white/5 text-emerald-300 ${tone === "danger" ? "!text-rose-300" : ""}`}>
          {icon}
        </span>
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