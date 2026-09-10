import React, { useEffect, useMemo, useState } from "react";
import { getAlerts } from "../lib/api";
import { Card, SeverityBadge } from "../components/ui";

const POLL_MS = 5000;

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [sent, setSent] = useState(0);
  const [sevFilter, setSevFilter] = useState("");
  const [expanded, setExpanded] = useState(null);
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

  const verdicts = useMemo(() => {
    const counts = {};
    alerts.forEach((a) => {
      counts[a.verdict] = (counts[a.verdict] || 0) + 1;
    });
    return counts;
  }, [alerts]);

  const visible = sevFilter ? alerts.filter((a) => a.severity === sevFilter) : alerts;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Alerts</h1>
        <p className="text-sm text-slate-400">
          Live export of the analyzer + notifier fan-out (polls every {POLL_MS / 1000}s).
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4 border-b border-slate-800 pb-4 lg:grid-cols-4">
        <Stat label="Alert events" value={sent} />
        <Stat label="Open alerts" value={alerts.length} />
        <Stat label="malicious" value={verdicts.malicious || 0} tone="text-red-400" />
        <Stat label="suspicious" value={verdicts.suspicious || 0} tone="text-amber-400" />
      </div>

      {error && <div className="text-sm text-red-400">{error}</div>}

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-slate-500">Filter severity:</span>
        {["", "critical", "high", "warning", "info"].map((s) => (
          <button
            key={s || "all"}
            onClick={() => setSevFilter(s)}
            className={`rounded-full border px-3 py-1 text-xs ${
              sevFilter === s
                ? "border-emerald-500 bg-emerald-500/15 text-emerald-300"
                : "border-slate-700 text-slate-400 hover:border-slate-500"
            }`}
          >
            {s || "all"}
          </button>
        ))}
      </div>

      {visible.length === 0 ? (
        <Card title="No alerts yet">Run the demo dataset to fan out alerts.</Card>
      ) : (
        <div className="space-y-2">
          {visible.map((a, i) => (
            <button
              key={a.timestamp + a.threat_class + i}
              onClick={() => setExpanded(expanded === a.timestamp + a.threat_class + i ? null : a.timestamp + a.threat_class + i)}
              className="block w-full rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-left hover:border-emerald-500/50"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={a.severity} />
                  <span className="font-mono text-sm text-slate-200">{a.threat_class}</span>
                  <span className="text-xs text-slate-500">
                    conf {a.confidence} · verdict <b className={a.verdict === "malicious" ? "text-red-400" : "text-amber-400"}>{a.verdict}</b> ({a.store_decision})
                  </span>
                </div>
                <span className="text-xs text-slate-500">{a.timestamp}</span>
              </div>
              {expanded === a.timestamp + a.threat_class + i && (
                <pre className="mt-2 overflow-x-auto rounded-lg bg-slate-950 p-3 text-[11px] text-slate-300">
                  {JSON.stringify(a.evidence || {}, null, 2)}
                </pre>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, tone = "text-slate-100" }) {
  return (
    <div>
      <p className={`text-2xl font-bold ${tone}`}>{value}</p>
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
    </div>
  );
}