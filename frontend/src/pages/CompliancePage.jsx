import React, { useEffect, useRef, useState } from "react";
import { getAssets, getCompliance, complianceReportUrl } from "../lib/api";
import { usePagedList, ShowMoreBar } from "../components/ShowMore";
import { PageHeader, LiveBadge, GlassCard, SeverityBadge, PlainBadge, Empty, SectionTitle, CodeBlock } from "../components/ui";

export default function CompliancePage() {
  const [assets, setAssets] = useState([]);
  const [selected, setSelected] = useState(null);
  const [compliance, setCompliance] = useState(null);
  const [error, setError] = useState(null);
  const reqSeq = useRef(0);
  const assetPage = usePagedList(assets, 100);

  useEffect(() => {
    getAssets()
      .then((d) => setAssets(d.assets.filter((a) => a.threatened)))
      .catch((e) => setError(e.message));
  }, []);

  const pick = async (ip) => {
    const my = ++reqSeq.current;
    setSelected(ip);
    setCompliance(null);
    try {
      const d = await getCompliance(ip);
      if (my === reqSeq.current) setCompliance(d);
    } catch (e) {
      if (my === reqSeq.current) setError(e.response?.data?.detail || e.message);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Governance · actionable controls"
        title="Compliance briefs"
        sub="Every impacted asset gets a CIS Controls v8 / NIST CSF / MITRE ATT&CK mapping with a generated analyst-ready brief."
        actions={<LiveBadge text={`${assets.length} assets require action`} />}
      />

      {error && <div className="text-sm text-rose-400">{error}</div>}

      <div className="grid gap-6 lg:grid-cols-[300px_1fr]">
        {/* asset rail */}
        <GlassCard title="Impacted assets">
          {assets.length === 0 ? (
            <Empty title="No impacted assets" hint="Threatened assets will appear here." />
          ) : (
            <div className="space-y-1.5">
              {assetPage.shown.map((a, i) => (
                <button
                  key={a.id}
                  onClick={() => pick(a.id)}
                  className={`w-full rounded-xl border px-3.5 py-2.5 text-left transition feed-in ${selected === a.id
                      ? "border-emerald-500/60 bg-emerald-500/10 shadow-[0_0_20px_-4px_rgba(52,211,153,0.4)]"
                      : "border-white/5 bg-white/[0.03] hover:border-emerald-500/30"
                    }`}
                  style={{ animationDelay: `${i * 60}ms` }}
                >
                  <p className="mono text-[12.5px] text-slate-100">{a.id}</p>
                  <p className="mt-0.5 flex items-center gap-1.5 text-[10px] text-rose-300">
                    <span className="h-1.5 w-1.5 rounded-full bg-rose-500 pulse-dot-red" />
                    {a.degree} edges · escalated
                  </p>
                </button>
              ))}
              <ShowMoreBar
                remaining={assetPage.remaining}
                total={assetPage.total}
                shownCount={assetPage.shown.length}
                onMore={assetPage.showMore}
                onAll={assetPage.showAll}
                noun="impacted assets"
              />
            </div>
          )}
        </GlassCard>

        {/* mapping panel */}
        <GlassCard
          title={compliance ? `Controls — ${compliance.asset_id}` : "Control mapping"}
          right={selected && !compliance && <span className="mono text-[10px] text-slate-500">loading…</span>}
        >
          {!compliance ? (
            <Empty
              title="Select an impacted asset"
              hint="The CIS / NIST / MITRE mapping for its threat findings renders here with action status."
            />
          ) : (
            <div className="space-y-5">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity="critical" />
                <PlainBadge cls="uppercase">action required</PlainBadge>
                <span className="mono ml-auto text-[11px] text-slate-500">
                  {compliance.controls.length} threat → control chains
                </span>
              </div>

              {selected && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => window.open(complianceReportUrl(compliance.asset_id), "_blank")}
                    className="rounded-xl border border-emerald-500/40 bg-emerald-500/15 px-3.5 py-1.5 text-[10.5px] font-semibold uppercase tracking-wider text-emerald-300 hover:bg-emerald-500/25"
                  >
                    PDF report
                  </button>
                  <span className="text-[10px] text-slate-500">print-friendly brief · Save as PDF</span>
                </div>
              )}

              <div className="grid gap-4 lg:grid-cols-2">
                {compliance.controls.length === 0 && (
                  <p className="text-[12px] text-slate-500">No mapped controls for this asset.</p>
                )}
                {compliance.controls.map((c, i) => (
                  <div key={i} className="glass-row feed-in p-4" style={{ animationDelay: `${i * 70}ms` }}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="mono text-[13px] font-semibold text-slate-100">{c.threat_class}</span>
                      <SeverityBadge severity={c.severity} />
                    </div>
                    <div className="mt-3 space-y-2 text-[11.5px]">
                      <Frameworks label="NIST CSF" value={c.nist_csf} />
                      <Frameworks label="CIS CONTROLS" value={c.cis_controls?.join(" · ") || "—"} />
                      <Frameworks label="MITRE ATT&CK" value={c.mitre_attack?.join(", ") || "—"} />
                      <div className="flex items-center gap-2 pt-1">
                        <span className="eyebrow">STATUS</span>
                        <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-300">
                          {c.status || "pending"}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {compliance.summary_markdown && (
                <div>
                  <SectionTitle right={<span className="mono text-[10px] text-slate-500">analyst-ready</span>}>
                    Generated brief
                  </SectionTitle>
                  <CodeBlock maxH="max-h-64">{compliance.summary_markdown}</CodeBlock>
                </div>
              )}
            </div>
          )}
        </GlassCard>
      </div>
    </div>
  );
}

function Frameworks({ label, value }) {
  return (
    <div className="flex items-start justify-between gap-3">
      <span className="eyebrow mt-0.5 shrink-0">{label}</span>
      <span className="mono text-right text-slate-300">{value}</span>
    </div>
  );
}