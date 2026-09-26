import React from "react";
import { Sparkline } from "./charts";

/* Shared UI primitives for the TriNetra command center */

// Seven severity keys preserved so existing data and call sites keep working.
// The palette has no green, so severity cannot lean on hue to separate "fine"
// from "act now". It is encoded by BRIGHTNESS and SATURATION instead:
// critical #EC4899 is the most vivid colour in the system, and low #6B5B8A is
// deliberately dim so a healthy state never competes with an urgent one.
const SEV = {
  critical: { strip: "sev-critical", text: "sev-text-critical", label: "bg-[#ec4899]" },
  high: { strip: "sev-high", text: "sev-text-high", label: "bg-[#f472b6]" },
  medium: { strip: "sev-medium", text: "sev-text-warning", label: "bg-[#c084fc]" },
  warning: { strip: "sev-warning", text: "sev-text-warning", label: "bg-[#c084fc]" },
  error: { strip: "sev-error", text: "sev-text-error", label: "bg-[#7c3aed]" },
  info: { strip: "sev-info", text: "sev-text-info", label: "bg-[#d8b4fe]" },
  low: { strip: "sev-low", text: "sev-text-low", label: "bg-[#6b5b8a]" },
};

// Coarse buckets used for ranking and for picking one severity colour when a
// caller needs a single hue.
const SEV_RANK = { critical: 0, high: 1, error: 2, warning: 3, medium: 4, info: 5, low: 6 };
const SEV_HUE = {
  critical: "#ec4899",
  high: "#f472b6",
  error: "#7c3aed",
  warning: "#c084fc",
  medium: "#c084fc",
  info: "#d8b4fe",
  low: "#6b5b8a",
};

// Normalise once so a severity of "Critical"/"HIGH"/" Info" resolves the same as
// its lowercase form. Without this the SEV lookup silently fell back to info,
// painting a critical finding blue while severityHex() reported it red.
export const normaliseSeverity = (severity) => String(severity ?? "").trim().toLowerCase();

const SEV_TONE = (severity) => SEV[normaliseSeverity(severity)] || SEV.info;

export const severityRank = (severity) =>
  SEV_RANK[normaliseSeverity(severity)] ?? SEV_RANK.info;

export const severityHex = (severity) =>
  SEV_HUE[normaliseSeverity(severity)] ?? SEV_HUE.info;

export function SeverityDot({ severity }) {
  const s = SEV_TONE(severity);
  const hex = severityHex(severity);
  return <span className={`inline-block h-2 w-2 rounded-full ${s.label}`} style={{ boxShadow: `0 0 8px ${hex}cc` }} />;
}

export function SeverityBadge({ severity }) {
  const s = SEV_TONE(severity);
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

export function PulseDot({ color = "bg-violet-500", cls = "pulse-dot" }) {
  return <span className={`inline-block h-2 w-2 rounded-full ${color} ${cls}`} />;
}

export function LiveBadge({ text = "LIVE" }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-violet-600/30 bg-violet-600/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-widest text-violet-300">
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
          {sub && <p className="mt-1 max-w-2xl text-[13px] leading-relaxed text-violet-200">{sub}</p>}
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
    emerald: { text: "text-grad-emerald", glow: "glow-emerald", bar: "from-violet-600 to-violet-600" },
    cyan: { text: "text-grad-emerald", glow: "glow-cyan", bar: "from-violet-500 to-purple-500" },
    danger: { text: "text-grad-danger", glow: "glow-red", bar: "from-[#ec4899] to-[#c084fc]" },
    violet: { text: "text-grad-emerald", glow: "glow-cyan", bar: "from-violet-400 to-pink-400" },
  };
  const t = tones[tone] || tones.emerald;
  return (
    <div className={`glass p-4 anim-fadeup ${t.glow}`} style={{ animationDelay: `${delay}ms` }}>
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <p className="eyebrow truncate">{label}</p>
          <p className={`mt-1.5 text-[26px] font-bold leading-none mono ${t.text}`}>{value}</p>
          {sub && <p className="mt-2 text-[11px] text-violet-300">{sub}</p>}
        </div>
        {icon && (
          <span className={`grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-gradient-to-br ${t.bar} bg-opacity-20 text-violet-950`}>
            {icon}
          </span>
        )}
      </div>
      {spark && spark.values.length > 0 && (
        <div className="mt-3">
          <Sparkline data={spark.values} color={spark.color || "#a855f7"} />
        </div>
      )}
    </div>
  );
}

export function SectionTitle({ children, right }) {
  return (
    <div className="mb-3 flex items-center justify-between">
      <h2 className="flex items-center gap-2 text-[13px] font-semibold text-slate-200">
        <span className="inline-block h-3.5 w-1 rounded-full bg-gradient-to-b from-violet-500 to-violet-600" />
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
              <span className="inline-block h-3.5 w-1 rounded-full bg-gradient-to-b from-violet-500 to-violet-600" />
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

export function ProgressBar({ value = 0, max = 100, color = "from-violet-600 to-violet-600", className = "" }) {
  const pct = max ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
  return (
    <div className={`h-1.5 w-full overflow-hidden rounded-full bg-white/5 ${className}`}>
      <div
        className={`bar-grow h-full rounded-full bg-gradient-to-r ${color}`}
        style={{ width: `${pct}%`, boxShadow: "0 0 10px rgba(167, 139, 196,0.45)" }}
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
      <div className="grid h-10 w-10 place-items-center rounded-full border border-violet-600/30 bg-violet-600/10 text-violet-500">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <circle cx="12" cy="12" r="9" />
          <path d="M12 8v4l2.5 2.5" strokeLinecap="round" />
        </svg>
      </div>
      <p className="mt-3 text-sm font-medium text-slate-300">{title}</p>
      <p className="mt-1 text-xs text-violet-300">{hint}</p>
    </div>
  );
}

export function LegendDot({ color, label }) {
  return (
    <span className="flex items-center gap-1.5 text-[11px] text-violet-200">
      <span className="h-2 w-2 rounded-full" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
      {label}
    </span>
  );
}