import React, { useEffect, useState } from "react";
import { getAssets, getCompliance } from "../lib/api";
import { Card, SeverityBadge } from "../components/ui";

export default function CompliancePage() {
  const [assets, setAssets] = useState([]);
  const [selected, setSelected] = useState(null);
  const [compliance, setCompliance] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    getAssets()
      .then((d) => setAssets(d.assets.filter((a) => a.threatened)))
      .catch((e) => setError(e.message));
  }, []);

  const pick = async (ip) => {
    setSelected(ip);
    const d = await getCompliance(ip);
    setCompliance(d);
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Compliance mapping</h1>
      {error && <div className="text-red-400">{error}</div>}

      <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
        <Card title="Impacted assets">
          {assets.length === 0 ? (
            <p className="text-sm text-slate-500">No impacted assets.</p>
          ) : (
            <div className="space-y-1">
              {assets.map((a) => (
                <button
                  key={a.id}
                  onClick={() => pick(a.id)}
                  className={`block w-full rounded-lg px-3 py-2 text-left font-mono text-sm ${
                    selected === a.id
                      ? "bg-emerald-500/15 text-emerald-300"
                      : "text-slate-300 hover:bg-slate-800"
                  }`}
                >
                  {a.id}
                </button>
              ))}
            </div>
          )}
        </Card>

        <Card title={compliance ? `Controls — ${compliance.asset_id}` : "Control mapping"}>
          {!compliance ? (
            <p className="text-sm text-slate-500">
              Select an impacted asset to see the CIS Controls v8 / NIST CSF /
              MITRE ATT&amp;CK mapping for its threat findings.
            </p>
          ) : (
            <div className="space-y-4">
              <div className="space-y-3">
                {compliance.controls.length === 0 && (
                  <p className="text-sm text-slate-500">No mapped controls for this asset.</p>
                )}
                {compliance.controls.map((c, i) => (
                  <div
                    key={i}
                    className="rounded-lg border border-slate-800 bg-slate-950 p-3"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-sm">{c.threat_class}</span>
                      <SeverityBadge severity={c.severity} />
                    </div>
                    <dl className="mt-2 space-y-1 text-xs">
                      <Row k="NIST CSF" v={c.nist_csf} />
                      <Row k="CIS Controls" v={c.cis_controls.join(", ")} />
                      <Row k="MITRE ATT&CK" v={c.mitre_attack.join(", ") || "—"} />
                      <Row k="Status" v={c.status} />
                    </dl>
                  </div>
                ))}
              </div>

              {compliance.summary_markdown && (
                <details className="rounded-lg bg-slate-950 p-3">
                  <summary className="cursor-pointer text-xs text-slate-400">
                    Analyst-ready summary (markdown)
                  </summary>
                  <pre className="mt-2 whitespace-pre-wrap text-[11px] text-slate-300">
                    {compliance.summary_markdown}
                  </pre>
                </details>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

function Row({ k, v }) {
  return (
    <div className="grid grid-cols-[110px_1fr] gap-2">
      <dt className="text-slate-500">{k}</dt>
      <dd className="text-slate-300">{v || "—"}</dd>
    </div>
  );
}