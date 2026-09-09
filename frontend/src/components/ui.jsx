import React from "react";

export function StatCard({ label, value, sub, accent = "text-slate-100" }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${accent}`}>{value}</p>
      {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
    </div>
  );
}

const sevColors = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  warning: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  info: "bg-sky-500/15 text-sky-400 border-sky-500/30",
  low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
};

export function SeverityBadge({ severity }) {
  const cls = sevColors[severity] || sevColors.info;
  return (
    <span className={`inline-block rounded-full border px-2 py-0.5 text-xs ${cls}`}>
      {severity}
    </span>
  );
}

export function Card({ title, children, actions }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">{title}</h2>
        {actions}
      </div>
      {children}
    </div>
  );
}