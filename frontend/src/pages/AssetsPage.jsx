import React, { useEffect, useRef, useState } from "react";
import { getAssets, getAssetRelations } from "../lib/api";
import { usePagedList, ShowMoreBar } from "../components/ShowMore";
import { PageHeader, LiveBadge, GlassCard, SeverityBadge, PlainBadge, Empty, SectionTitle, ProgressBar, CodeBlock } from "../components/ui";

export default function AssetsPage() {
  const [assets, setAssets] = useState([]);
  const [relation, setRelation] = useState(null);
  const [error, setError] = useState(null);
  const reqSeq = useRef(0);

  useEffect(() => {
    getAssets()
      .then((d) => setAssets(d.assets))
      .catch((e) => setError(e.message));
  }, []);

  const open = async (ip) => {
    const my = ++reqSeq.current;
    setRelation(null);
    try {
      const data = await getAssetRelations(ip);
      if (my === reqSeq.current) setRelation({ ip, ...data });
    } catch (e) {
      if (my === reqSeq.current) setError(e.response?.data?.detail || e.message);
    }
  };

  const paged = usePagedList(assets, 100);
  const maxDegree = Math.max(...assets.map((a) => a.degree), 1);
  const threatenedCount = assets.filter((a) => a.threatened).length;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Inventory · graph entities"
        title="Asset registry"
        sub="Every internal host seen by the sensors, risk-ranked by graph degree. Threatened assets are escalated and mapped to controls."
        actions={<LiveBadge text={`${assets.length} assets · ${threatenedCount} threatened`} />}
      />

      {error && <div className="text-sm text-pink-500">{error}</div>}

      <div className="grid gap-6 lg:grid-cols-2">
        <GlassCard title="Internal assets — risk ranked">
          {assets.length === 0 ? (
            <Empty title="No assets in graph" hint="Ingest flows so Module C can map entities." />
          ) : (
            <div className="space-y-2">
              {paged.shown.map((a, i) => (
                <button
                  key={a.id}
                  onClick={() => open(a.id)}
                  className="glass-row group flex w-full items-center gap-3 p-3 text-left feed-in"
                  style={{ animationDelay: `${Math.min(i, 15) * 40}ms` }}
                >
                  <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${a.threatened ? "bg-pink-500 pulse-dot-red" : "bg-violet-500/70"}`} />
                  <div className="min-w-0 flex-1">
                    <p className="mono text-[13px] text-slate-100">{a.id}</p>
                    <div className="mt-1.5 flex items-center gap-2">
                      <ProgressBar value={a.degree} max={maxDegree} color={a.threatened ? "from-[#ec4899] to-[#c084fc]" : "from-violet-600 to-violet-500"} className="w-40" />
                      <span className="mono text-[10px] text-violet-300">degree {a.degree}</span>
                    </div>
                  </div>
                  {a.threatened ? (
                    <SeverityBadge severity="critical" />
                  ) : (
                    <PlainBadge>clean</PlainBadge>
                  )}
                </button>
              ))}
              <ShowMoreBar
                remaining={paged.remaining}
                total={paged.total}
                shownCount={paged.shown.length}
                onMore={paged.showMore}
                onAll={paged.showAll}
                noun="assets"
              />
            </div>
          )}
        </GlassCard>

        <GlassCard
          title={relation ? `Relations — ${relation.ip}` : "Asset drill-down"}
          right={relation && <button onClick={() => setRelation(null)} className="text-[11px] text-violet-300 hover:text-slate-200">close ×</button>}
        >
          {!relation ? (
            <Empty
              title="Select an asset to pivot"
              hint="A summary of communication edges, linked findings and mapped controls appears here."
            />
          ) : (
            <div className="space-y-5">
              <div>
                <SectionTitle right={<span className="mono text-[10px] text-violet-300">{relation.edges.length} edges</span>}>
                  Communication edges
                </SectionTitle>
                <div className="max-h-48 space-y-1.5 overflow-y-auto pr-1">
                  {relation.edges.slice(0, 30).map((e, i) => (
                    <div key={i} className="glass-row flex items-center justify-between px-3 py-1.5 text-[12px]">
                      <span className="mono truncate text-slate-300">{e.source} → {e.target}</span>
                      <span className="flex items-center gap-2">
                        <PlainBadge>{e.kind}</PlainBadge>
                        <span className="mono text-[10px] text-violet-300">{e.flows}f</span>
                        {e.threat ? <span className="h-1.5 w-1.5 rounded-full bg-pink-500 pulse-dot-red" /> : null}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <SectionTitle>Linked findings</SectionTitle>
                {relation.findings.length === 0 ? (
                  <p className="text-[12px] text-violet-300">No findings on this asset.</p>
                ) : (
                  <div className="space-y-1.5">
                    {relation.findings.map((f, i) => (
                      <div key={i} className="glass-row flex items-center justify-between px-3 py-2 text-[12.5px]">
                        <span className="mono text-slate-200">{f.threat_class}</span>
                        <SeverityBadge severity={f.severity} />
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <SectionTitle>Mapped controls</SectionTitle>
                {!relation.compliance?.controls?.length ? (
                  <p className="text-[12px] text-violet-300">No controls mapped for this asset.</p>
                ) : (
                  <div className="space-y-1.5">
                    {relation.compliance.controls.map((c, i) => (
                      <div key={i} className="glass-row px-3 py-2 text-[12px]">
                        <p className="mono text-slate-100">{c.threat_class}</p>
                        <p className="mt-0.5 text-[11px] text-violet-200">
                          CIS {c.cis_controls?.join(", ") || "—"} · NIST {c.nist_csf}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
                {relation.compliance?.summary_markdown && (
                  <details className="mt-3">
                    <summary className="cursor-pointer text-[11px] text-violet-300 hover:text-slate-300">analyst brief (markdown)</summary>
                    <CodeBlock maxH="max-h-40" >{relation.compliance.summary_markdown}</CodeBlock>
                  </details>
                )}
              </div>
            </div>
          )}
        </GlassCard>
      </div>
    </div>
  );
}