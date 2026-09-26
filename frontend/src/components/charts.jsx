import React from "react";

/* Pure-SVG micro-charts — no external deps. */

export function Sparkline({ data = [], color = "#22d3ee", width = 120, height = 36, fill = true }) {
  if (data.length < 2) {
    return <svg width={width} height={height} className="opacity-30" />;
  }
  const min = Math.min(...data);
  const max = Math.max(...data);
  const span = max - min || 1;
  const step = width / (data.length - 1);
  const pts = data.map((v, i) => [i * step, height - 3 - ((v - min) / span) * (height - 6)]);
  const line = pts.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const area = `0,${height} ${line} ${width},${height}`;
  const gid = `spark-${color.replace(/[^a-z0-9]/gi, "")}-${height}-${data.length}`;
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="block">
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {fill && <polygon points={area} fill={`url(#${gid})`} />}
      <polyline points={line} fill="none" stroke={color} strokeWidth="1.6" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={pts[pts.length - 1][0]} cy={pts[pts.length - 1][1]} r="2.4" fill={color} />
    </svg>
  );
}

export function Donut({ segments = [], size = 160, thickness = 16, centerValue, centerLabel }) {
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  let acc = 0;
  const gid = `donut-${segments.map((s) => s.color.replace(/[^a-z0-9]/gi, "")).join("")}`;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="block">
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="1" y2="1">
          {segments.map((s, i) => (
            <stop key={i} offset={`${(i / segments.length) * 100}%`} stopColor={s.color} />
          ))}
        </linearGradient>
      </defs>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(148,163,184,0.1)" strokeWidth={thickness} />
      {segments.map((s, i) => {
        const raw = (s.value / total) * c;
        // 2px inset between neighbouring arcs. A zero (or sub-inset) share
        // yields a non-positive dash, and a negative strokeDasharray is
        // invalid: the browser discards it and paints the circle as an
        // unbroken full ring, which buried every real arc in this chart.
        const dash = raw - 2;
        if (!(dash > 0)) return null;
        const off = c - acc;
        acc += raw;
        return (
          <circle
            key={i}
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={s.color}
            strokeWidth={thickness}
            strokeLinecap="butt"
            strokeDasharray={`${dash} ${c - dash}`}
            strokeDashoffset={off}
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
            style={{ filter: `drop-shadow(0 0 6px ${s.color}66)` }}
          />
        );
      })}
      {centerValue !== undefined && (
        <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" className="fill-slate-100 mono" fontSize="26" fontWeight="700">
          {centerValue}
        </text>
      )}
      {centerLabel && (
        <text x="50%" y="62%" textAnchor="middle" textRendering="geometricPrecision" className="fill-slate-500" fontSize="9" letterSpacing="2">
          {centerLabel.toUpperCase()}
        </text>
      )}
    </svg>
  );
}

export function ScoreRing({ score = 0, size = 96, tone = "#22d3ee", label }) {
  const thickness = 8;
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score));
  const gid = `ring-${tone.replace(/[^a-z0-9]/gi, "")}`;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="block">
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor={tone} />
          <stop offset="100%" stopColor="#22d3ee" />
        </linearGradient>
      </defs>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(148,163,184,0.12)" strokeWidth={thickness} />
      <circle
        cx={size / 2}
        cy={size / 2}
        r={r}
        fill="none"
        stroke={`url(#${gid})`}
        strokeWidth={thickness}
        strokeLinecap="round"
        strokeDasharray={`${(pct / 100) * c} ${c}`}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
        style={{ filter: `drop-shadow(0 0 8px ${tone}77)`, transition: "stroke-dasharray 0.6s ease" }}
      />
      <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" className="fill-slate-100 mono" fontSize="20" fontWeight="700">
        {Math.round(score)}
      </text>
      {label && (
        <text x="50%" y="66%" textAnchor="middle" className="fill-slate-500" fontSize="7.5" letterSpacing="1.6">
          {label.toUpperCase()}
        </text>
      )}
    </svg>
  );
}

export function MiniBars({ data = [], color = "#22d3ee", height = 44, barWidth = 8 }) {
  const max = Math.max(...data, 1);
  return (
    <div className="flex items-end gap-1" style={{ height }}>
      {data.map((v, i) => (
        <div
          key={i}
          className="bar-grow rounded-sm"
          style={{
            width: barWidth,
            height: `${Math.max(8, (v / max) * height)}px`,
            background: `linear-gradient(180deg, ${color}cc, ${color}33)`,
          }}
        />
      ))}
    </div>
  );
}