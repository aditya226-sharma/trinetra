import React from "react";
import { Sparkline } from "./charts";

/* Shared UI primitives for the TriNetra command center */

// Seven severity keys preserved so existing data and call sites keep working,
// mapped onto the three command-center hues: critical #F87171, warning
// #FBBF24, info #38BDF8. `error` keeps violet to stay distinct from warning.
const SEV = {
  critical: { strip: "sev-critical", text: "sev-text-critical", label: "bg-[#f87171]" },
  high: { strip: "sev-high", text: "sev-text-high", label: "bg-[#fca5a5]" },
  medium: { strip: "sev-medium", text: "sev-text-warning", label: "bg-[#fbbf24]" },
  warning: { strip: "sev-warning", text: "sev-text-warning", label: "bg-[#fbbf24]" },
  error: { strip: "sev-error", text: "sev-text-error", label: "bg-[#a78bfa]" },
  info: { strip: "sev-info", text: "sev-text-info", label: "bg-[#38bdf8]" },
  low: { strip: "sev-low", text: "sev-text-low", label: "bg-[#38bdf8]" },
};

// Coarse buckets used for ranking and for picking one of the three spec hues
// when a caller needs a single severity colour.
const SEV_RANK = { critical: 0, high: 1, error: 2, warning: 3, medium: 4, info: 5, low: 6 };
const SEV_HUE = {
  critical: "#f87171",
  high: "#f87171",
  error: "#a78bfa",
  warning: "#fbbf24",
  medium: "#fbbf24",
  info: "#38bdf8",
  low: "#38bdf8",
};

export const severityRank = (severity) =>
  SEV_RANK[String(severity || "").toLowerCase()] ?? SEV_RANK.info;

export const severityHex = (severity) =>
  SEV_HUE[String(severity || "").toLowerCase()] ?? SEV_HUE.info;

export function SeverityDot({ severity }) {
  const s = SEV[severity] || SEV.info;
  const hex = severityHex(severity);
  return <span className={`inline-block h-2 w-2 rounded-full ${s.label}`} style={{ boxShadow: `0 0 8px ${hex}cc` }} />;
}

export function SeverityBadge({ severity }) {
  const s = SEV[severity] || SEV.info;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border border-white/10 px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${s.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.label}`} />
      {severity}
    </span>
  );
}

export function PlainBadge({ children, cls = "" }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-[10px] font-medium text-slate-300 ${cls}`}>
      {children}
    </span>
  );
}

export function PulseDot({ color = "bg-emerald-400", cls = "pulse-dot" }) {
  return <span className={`inline-block h-2 w-2 rounded-full ${color} ${cls}`} />;
}

export function LiveBadge({ text = "LIVE" }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-widest text-emerald-300">
      <PulseDot />
      {text}
    </span>
  );
}

export function PageHeader({ eyebrow, title, sub, actions }) {
  return (
    <div className="mb-6 anim-fadeup">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          {eyebrow && <p className="eyebrow mb-1.5">{eyebrow}</p>}
          <h1 className="text-2xl font-bold tracking-tight text-slate-50">{title}</h1>
          {sub && <p className="mt-1 max-w-2xl text-[13px] leading-relaxed text-slate-400">{sub}</p>}
        </div>
        {actions && <div className="flex items-center gap-3">{actions}</div>}
      </div>
    </div>
  );
}

export function Kpi({
  label,
  value,
  sub,
  icon,
  tone = "emerald",
  spark,
  delay = 0,
}) {
  const tones = {
    emerald: { text: "text-grad-emerald", glow: "glow-emerald", bar: "from-emerald-500 to-cyan-500" },
    cyan: { text: "text-grad-emerald", glow: "glow-cyan", bar: "from-cyan-400 to-sky-500" },
    danger: { text: "text-grad-danger", glow: "glow-red", bar: "from-rose-500 to-orange-500" },
    violet: { text: "text-grad-emerald", glow: "glow-cyan", bar: "from-indigo-400 to-fuchsia-400" },
  };
  const t = tones[tone] || tones.emerald;
  return (
    <div className={`glass p-4 anim-fadeup ${t.glow}`} style={{ animationDelay: `${delay}ms` }}>
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <p className="eyebrow truncate">{label}</p>
          <p className={`mt-1.5 text-[26px] font-bold leading-none mono ${t.text}`}>{value}</p>
          {sub && <p className="mt-2 text-[11px] text-slate-500">{sub}</p>}
        </div>
        {icon && (
          <span className={`grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-gradient-to-br ${t.bar} bg-opacity-20 text-slate-950`}>
            {icon}
          </span>
        )}
      </div>
      {spark && spark.values.length > 0 && (
        <div className="mt-3">
          <Sparkline data={spark.values} color={spark.color || "#22d3ee"} />
        </div>
      )}
    </div>
  );
}

export function SectionTitle({ children, right }) {
  return (
    <div className="mb-3 flex items-center justify-between">
      <h2 className="flex items-center gap-2 text-[13px] font-semibold text-slate-200">
        <span className="inline-block h-3.5 w-1 rounded-full bg-gradient-to-b from-emerald-400 to-cyan-500" />
        {children}
      </h2>
      {right}
    </div>
  );
}

export function GlassCard({ title, right, children, pad = "p-4", className = "" }) {
  return (
    <section className={`glass ${pad} anim-fadeup ${className}`}>
      {(title || right) && (
        <div className="mb-4 flex items-center justify-between gap-3">
          {title && (
            <h2 className="flex items-center gap-2 text-[13px] font-semibold text-slate-200">
              <span className="inline-block h-3.5 w-1 rounded-full bg-gradient-to-b from-emerald-400 to-cyan-500" />
              {title}
            </h2>
          )}
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

export function ProgressBar({ value = 0, max = 100, color = "from-emerald-500 to-cyan-500", className = "" }) {
  const pct = max ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
  return (
    <div className={`h-1.5 w-full overflow-hidden rounded-full bg-white/5 ${className}`}>
      <div
        className={`bar-grow h-full rounded-full bg-gradient-to-r ${color}`}
        style={{ width: `${pct}%`, boxShadow: "0 0 10px rgba(52,211,153,0.45)" }}
      />
    </div>
  );
}

export function CodeBlock({ children, maxH = "max-h-56" }) {
  return (
    <pre className={`${maxH} overflow-y-auto overflow-x-auto rounded-lg border border-white/5 bg-black/50 p-3 text-[11px] leading-relaxed text-slate-300 mono`}>
      {children}
    </pre>
  );
}

export function Empty({ title = "Nothing here yet", hint = "The store is waiting for data." }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-white/10 py-10 text-center">
      <div className="grid h-10 w-10 place-items-center rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <circle cx="12" cy="12" r="9" />
          <path d="M12 8v4l2.5 2.5" strokeLinecap="round" />
        </svg>
      </div>
      <p className="mt-3 text-sm font-medium text-slate-300">{title}</p>
      <p className="mt-1 text-xs text-slate-500">{hint}</p>
    </div>
  );
}

export function LegendDot({ color, label }) {
  return (
    <span className="flex items-center gap-1.5 text-[11px] text-slate-400">
      <span className="h-2 w-2 rounded-full" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
      {label}
    </span>
  );
}