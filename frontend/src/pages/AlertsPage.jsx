import React, { useEffect, useMemo, useState } from "react";
import { getAlerts } from "../lib/api";
import { PageHeader, LiveBadge, SeverityBadge, CodeBlock, Empty, PlainBadge } from "../components/ui";

const POLL_MS = 5000;
const SEVERS = ["", "critical", "high", "warning", "info"];

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [sent, setSent] = useState(0);
  const [sevFilter, setSevFilter] = useState("");
  const [expandedId, setExpandedId] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let alive = true;
    const tick = () =>
      getAlerts()
        .then((d) => {
          if (!alive) return;
          setAlerts(d.alerts);
          setSent(d.sent);
          setError(null);
        })
        .catch((e) => alive && setError(e.message));
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const stats = useMemo(() => {
    const out = { critical: 0, high: 0, warning: 0, info: 0, other: 0, malicious: 0, suspicious: 0 };
    alerts.forEach((a) => {
      if (["critical", "high", "warning", "info"].includes(a.severity)) out[a.severity] += 1;
      else out.other += 1;
      if (a.verdict === "malicious") out.malicious += 1;
      if (a.verdict === "suspicious") out.suspicious += 1;
    });
    return out;
  }, [alerts]);

  const visible = sevFilter ? alerts.filter((a) => a.severity === sevFilter) : alerts;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Analyzer · notifier fan-out"
        title="Alert stream"
        sub="Live export of verdicts pushed by the pipeline every batch — expand a verdict to inspect the raw evidence that fired it."
        actions={<LiveBadge text={`Poll 5s · ${sent} sent`} />}
      />

      {/* verdict tiles */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4 anim-fadeup">
        <Tile label="Alert events" value={sent} tone="tone-info" />
        <Tile label="Open verdicts" value={alerts.length} tone="tone-slate" />
        <Tile label="malicious · quarantine" value={stats.malicious} tone="tone-danger" />
        <Tile label="suspicious · review" value={stats.suspicious} tone="tone-warn" />
      </div>
      {stats.other > 0 && (
        <p className="text-[11px] text-slate-500">
          +{stats.other} with other severities ({["medium", "error", "low"].join("/")})
        </p>
      )}

      {error && <div className="text-sm text-rose-400">{error}</div>}

      {/* severity pills */}
      <div className="flex flex-wrap items-center gap-2 anim-fadeup">
        <span className="eyebrow mr-1">FILTER</span>
        {SEVERS.map((s) => (
          <button key={s || "all"} onClick={() => setSevFilter(s)} className={`chip ${sevFilter === s ? "chip-on" : ""}`}>
            {s === "" ? "all verdicts" : s}
          </button>
        ))}
        {stats.critical > 0 && (
          <span className="ml-auto flex items-center gap-1.5 text-[11px] text-rose-300">
            <span className="h-1.5 w-1.5 rounded-full bg-rose-500 pulse-dot-red" />
            {stats.critical} critical inbound
          </span>
        )}
      </div>

      {/* timeline feed */}
      {visible.length === 0 ? (
        <Empty title="No verdicts in flight" hint="Run the demo dataset to fan out alerts." />
      ) : (
        <div className="relative space-y-3 pl-6 anim-fadeup">
          {/* spine */}
          <span className="absolute bottom-2 left-[7px] top-2 w-px bg-gradient-to-b from-emerald-500/40 via-white/10 to-transparent" aria-hidden />
          {visible.map((a, i) => {
            const key = `${a.flows ?? a.timestamp}_${a.threat_class}_${a.confidence}`;
            const open = expandedId === key;
            return (
              <div key={key} className="relative feed-in" style={{ animationDelay: `${i * 55}ms` }}>
                <span className={`absolute -left-6 top-4 h-3 w-3 rounded-full border-2 border-[#05080f] ${dotCls(a.severity)} ${a.severity === "critical" ? "pulse-dot-red" : ""}`} />
                <div className={`glass-row overflow-hidden ${open ? "border-emerald-500/30" : ""}`}>
                  <button onClick={() => setExpandedId(open ? null : key)} className="flex w-full items-center gap-3 p-4 text-left">
                    <span className={`sev-strip ${stripCls(a.severity)}`} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="mono text-[13.5px] font-semibold text-slate-100">{a.threat_class}</span>
                        <SeverityBadge severity={a.severity} />
                        <PlainBadge>verdict <b className={a.verdict === "malicious" ? "text-rose-300" : "text-amber-300"}>{a.verdict}</b></PlainBadge>
                      </div>
                      <p className="mono mt-1 text-[11px] uppercase tracking-widest text-slate-500">
                        conf {a.confidence} · store → {a.store_decision} · {a.timestamp}
                      </p>
                    </div>
                    <span className="text-slate-600 transition group-hover:text-emerald-300">{open ? "−" : "+"}</span>
                  </button>
                  {open && (
                    <div className="border-t border-white/5 bg-black/30 p-4">
                      <p className="eyebrow mb-2">Supporting evidence · raw flows</p>
                      <CodeBlock maxH="max-h-64">{JSON.stringify(a.evidence || {}, null, 2)}</CodeBlock>
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

function Tile({ label, value, tone }) {
  const tones = {
    "tone-danger": "text-grad-danger glow-red",
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