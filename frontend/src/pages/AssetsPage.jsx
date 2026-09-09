import React, { useEffect, useState } from "react";
import { getAssets, getAssetRelations } from "../lib/api";
import { Card, SeverityBadge } from "../components/ui";

export default function AssetsPage() {
  const [assets, setAssets] = useState([]);
  const [relation, setRelation] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    getAssets()
      .then((d) => setAssets(d.assets))
      .catch((e) => setError(e.message));
  }, []);

  const open = async (ip) => {
    setRelation(null);
    const data = await getAssetRelations(ip);
    setRelation({ ip, ...data });
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Assets & lateral movement</h1>
      {error && <div className="text-red-400">{error}</div>}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Internal assets (risk-ranked)">
          {assets.length === 0 ? (
            <p className="text-sm text-slate-500">No assets in graph.</p>
          ) : (
            <div className="space-y-2">
              {assets.map((a) => (
                <button
                  key={a.id}
                  onClick={() => open(a.id)}
                  className="flex w-full items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-3 text-left hover:border-emerald-500/50"
                >
                  <div>
                    <span className="font-mono text-sm">{a.id}</span>
                    <span className="ml-2 text-xs text-slate-500">
                      degree {a.degree}
                    </span>
                  </div>
                  {a.threatened ? (
                    <SeverityBadge severity="critical" />
                  ) : (
                    <SeverityBadge severity="info" />
                  )}
                </button>
              ))}
            </div>
          )}
        </Card>

        <Card title={relation ? `Relations — ${relation.ip}` : "Asset drill down"}>
          {!relation ? (
            <p className="text-sm text-slate-500">
              Click an asset to see its communication edges, linked findings
              and compliance mapping.
            </p>
          ) : (
            <div className="space-y-4">
              <div>
                <h3 className="mb-1 text-xs uppercase text-slate-500">Edges</h3>
                <div className="max-h-40 space-y-1 overflow-y-auto">
                  {relation.edges.slice(0, 24).map((e, i) => (
                    <div key={i} className="text-xs">
                      <span className="font-mono text-slate-300">
                        {e.source} → {e.target}
                      </span>
                      <span className="ml-2 text-slate-500">
                        [{e.kind}] flows {e.flows}
                        {e.threat ? " · THREAT" : ""}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="mb-1 text-xs uppercase text-slate-500">Findings</h3>
                <div className="space-y-1">
                  {relation.findings.length === 0 && (
                    <p className="text-xs text-slate-500">No findings on this asset.</p>
                  )}
                  {relation.findings.map((f, i) => (
                    <div key={i} className="flex items-center justify-between text-sm">
                      <span className="font-mono">{f.threat_class}</span>
                      <SeverityBadge severity={f.severity} />
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="mb-1 text-xs uppercase text-slate-500">
                  Compliance controls
                </h3>
                <div className="space-y-1">
                  {relation.compliance?.controls?.map((c, i) => (
                    <div key={i} className="text-xs text-slate-300">
                      <b className="text-slate-100">{c.threat_class}</b> —{" "}
                      {c.cis_controls.join(", ") || "n/a"} · {c.nist_csf}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}