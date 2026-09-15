import React, { useEffect, useState } from "react";
import { getAnalytics, downloadAnalyticsCsv } from "../lib/api";
import { PageHeader, GlassCard, Empty, PlainBadge } from "../components/ui";

function useAnalytics() {
  const [data, setData] = useState(null);
  const [hours, setHours] = useState(48);
  const [error, setError] = useState(null);
  const load = () =>
    getAnalytics(hours)
      .then(setData)
      .catch((e) => setError(e.message));
  useEffect(() => { load(); }, [hours]);
  return { data, hours, setHours, error, refresh: load };
}

function Dim({ title, obj = {} }) {
  const entries = Object.entries(obj).sort(([, a], [, b]) => b - a).slice(0, 10);
  const max = entries[0]?.[1] || 1;
  return (
    <div className="space-y-2">
      <p className="eyebrow">{title}</p>
      {entries.length === 0 && <p className="text-[11px] text-slate-500">None</p>}
      {entries.map(([k, v]) => (
        <div key={k} className="flex items-center gap-3 text-[11.5px]">
          <span className="mono w-24 truncate text-slate-300">{k || "—"}</span>
          <div className="relative h-2 flex-1 overflow-hidden rounded-full bg-white/5">
            <div
              className="absolute inset-y-0 left-0 rounded-full bg-emerald-500/70"
              style={{ width: `${Math.max(4, (v / max) * 100)}%` }}
            />
          </div>
          <span className="mono w-14 text-right text-slate-400">{v.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

function MiniChart({ series = [] }) {
  const max = Math.max(...series.map((b) => b.events), 1);
  return (
    <div className="flex items-end gap-px h-32">
      {series.map((b, i) => (
        <div
          key={i}
          title={`${b.bucket}\n${b.events} events`}
          className="flex-1 bg-emerald-500/80 rounded-t"
          style={{ height: `${Math.max(2, (b.events / max) * 100)}%` }}
        />
      ))}
      {series.length === 0 && (
        <span className="text-[11px] text-slate-500">No series data</span>
      )}
    </div>
  );
}

export default function AnalyticsPage() {
  const { data, hours, setHours, error, refresh } = useAnalytics();
  const [exporting, setExporting] = useState(false);

  const download = async () => {
    setExporting(true);
    try {
      const blob = await downloadAnalyticsCsv(hours);
      if (blob) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `analytics_${hours}h.csv`;
        document.body.appendChild(a);
        a.click();
        URL.revokeObjectURL(url);
        a.remove();
      }
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Intelligence · time-series + dimensions"
        title="Analytics"
        sub="Roll-up statistics with hourly event time-series and dimension breakdowns for source / severity / category / client."
        actions={
          <div className="flex items-center gap-2">
            {[
              [24, "24 h"],
              [48, "48 h"],
              [72, "3 d"],
              [168, "7 d"],
            ].map(([h, lbl]) => (
              <button
                key={h}
                onClick={() => setHours(h)}
                className={`rounded-full border px-3 py-1 text-[10px] font-semibold uppercase tracking-wider transition ${
                  hours === h
                    ? "border-emerald-500/60 bg-emerald-500/20 text-emerald-300"
                    : "border-white/10 bg-white/[0.03] text-slate-400 hover:border-white/20"
                }`}
              >
                {lbl}
              </button>
            ))}
            <button
              onClick={download}
              disabled={exporting}
              className="ml-2 rounded-xl border border-white/10 bg-white/[0.04] px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-300 hover:border-emerald-500/30 hover:text-emerald-300 disabled:opacity-50"
            >
              {exporting ? "exporting…" : "CSV"}
            </button>
          </div>
        }
      />

      {error && <div className="text-sm text-rose-400">{error}</div>}
      {!data && !error && (
        <GlassCard title="Loading analytics…">
          <p className="mono text-[11px] text-slate-500">Fetching roll-ups…</p>
        </GlassCard>
      )}
      {data && (
        (() => {
          const series = data.time_series || [];
          return (
            <>
              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <Stat k="Events total" v={data.totals?.events_total ?? 0} />
                <Stat k="Events window" v={data.totals?.events_in_window ?? 0} />
                <Stat k="Findings" v={data.totals?.findings_total ?? 0} accent="rose" />
                <Stat k="Dedup rate" v={`${((data.totals?.dedup_rate ?? 0) * 100).toFixed(2)}%`} accent="amber" />
              </div>

              <GlassCard title={`Hourly event volume (last ${hours}h)`} right={<PlainBadge>{series.length} buckets</PlainBadge>}>
                <MiniChart series={series} />
                <p className="mt-2 text-[10.5px] text-slate-500">Hover bars for exact counts; chart auto-scales to peak.</p>
              </GlassCard>

              <div className="grid gap-6 lg:grid-cols-2">
                <GlassCard title="By source type">
                  <Dim obj={data.by_source_type} title="source_type" />
                </GlassCard>
                <GlassCard title="By severity">
                  <Dim obj={data.by_severity} title="severity" />
                </GlassCard>
                <GlassCard title="By category">
                  <Dim obj={data.by_category} title="category" />
                </GlassCard>
                <GlassCard title="By client">
                  <Dim obj={data.by_client} title="client_id" />
                </GlassCard>
              </div>

              <GlassCard title="Detection classes">
                <Dim obj={data.detections} title="threat_class" />
              </GlassCard>

              <p className="text-right text-[10px] text-slate-500">Generated {data.generated_at?.replace("T", " ").replace("Z", " UTC")}</p>
            </>
          );
        })()
      )}
    </div>
  );
}

function Stat({ k, v, accent = "emerald" }) {
  const color =
    accent === "rose"
      ? "text-rose-400"
      : accent === "amber"
      ? "text-amber-400"
      : "text-emerald-400";
  return (
    <div className="glass-row p-4">
      <p className="eyebrow">{k}</p>
      <p className={`mt-1 mono text-xl font-semibold ${color}`}>{typeof v === "number" ? v.toLocaleString() : v}</p>
    </div>
  );
}