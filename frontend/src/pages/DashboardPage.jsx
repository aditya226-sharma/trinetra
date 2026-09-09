import React, { useEffect, useState } from "react";
import { getDashboard } from "../lib/api";
import { StatCard, Card, SeverityBadge } from "../components/ui";

export default function DashboardPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    getDashboard()
      .then(setData)
      .catch((e) => setError(e.message));
  }, []);

  if (error) {
    return <div className="text-red-400">Failed to load dashboard: {error}</div>;
  }
  if (!data) return <div className="text-slate-400">Loading…</div>;

  const s = data.stats || {};
  const threats = data.threat_detections || {};
  const findings = data.findings || [];
  const vpn = data.vpn?.profiles || [];
  const g = data.graph_summary || {};

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Security overview</h1>
        <p className="text-sm text-slate-400">
          Multi-domain AI threat intelligence across {s.events ?? 0} normalized
          events with {s.findings ?? 0} module findings.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Events ingested" value={s.events} sub={`${s.raw_lines} raw lines`} />
        <StatCard label="Dedup rate" value={`${Math.round((data.dedup_rate || 0) * 100)}%`} sub="fingerprint-based" />
        <StatCard label="Module findings" value={s.findings} accent="text-amber-400" sub={`${s.alerts_sent} alerts sent`} />
        <StatCard label="Graph" value={`${g.nodes} / ${g.edges}`} sub={`${g.threatened?.length || 0} assets impacted`} accent="text-emerald-400" />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Threat detections by class">
          {Object.keys(threats).length === 0 ? (
            <p className="text-sm text-slate-500">No detections recorded.</p>
          ) : (
            <div className="space-y-2">
              {Object.entries(threats).map(([threat, count]) => (
                <div key={threat} className="flex items-center justify-between text-sm">
                  <span className="font-mono text-slate-300">{threat}</span>
                  <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-xs text-red-400">
                    {count}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title="Latest findings">
          {findings.length === 0 ? (
            <p className="text-sm text-slate-500">No findings yet — run the demo dataset.</p>
          ) : (
            <div className="space-y-2">
              {findings.slice(-6).reverse().map((f, i) => {
                const alert = f.alert || f;
                return (
                  <div key={i} className="flex items-center justify-between text-sm">
                    <div>
                      <span className="font-mono text-slate-200">{alert.threat_class}</span>
                      <span className="ml-2 text-xs text-slate-500">
                        conf {alert.confidence}
                      </span>
                    </div>
                    <SeverityBadge severity={alert.severity} />
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>

      <Card title="VPN / IPsec gateway assessment (Module B)">
        {vpn.length === 0 ? (
          <p className="text-sm text-slate-500">No PCAP captures assessed.</p>
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {vpn.map((p, i) => (
              <div
                key={i}
                className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-sm"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono">{p.file}</span>
                  <SeverityBadge severity={p.risk_level} />
                </div>
                <div className="mt-2 grid grid-cols-2 gap-1 text-xs text-slate-400">
                  <span>IKEv{p.ike_version}</span>
                  <span>{p.encryption} / {p.key_length}bit</span>
                  <span>PRF {p.prf || "n/a"}</span>
                  <span>DH {p.dh_group}</span>
                  <span>PFS {p.pfs}</span>
                  <span>lifetime {p.sa_lifetime}s</span>
                </div>
                <div className="mt-2 text-xs text-slate-300">
                  Score <b className="text-slate-100">{p.security_score}/100</b> ·{" "}
                  {p.recommendations?.join(" · ") || ""}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}