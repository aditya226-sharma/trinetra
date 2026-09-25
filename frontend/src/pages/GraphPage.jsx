import React, { useEffect, useMemo, useRef, useState } from "react";
import { getGraph } from "../lib/api";
import { computeLayout, pickRenderable } from "../lib/forceLayout";
import { PageHeader, LiveBadge, GlassCard, LegendDot, SeverityBadge, PlainBadge, CodeBlock } from "../components/ui";

function useForceLayout(nodes, edges, width = 900, height = 540) {
  return useMemo(() => computeLayout(nodes, edges, width, height), [nodes, edges, width, height]);
}

const KIND_COLOR = {
  ip: "#22d3ee",
  user: "#34d399",
  proc: "#fbbf24",
  domain: "#818cf8",
  threat: "#f43f5e",
};

export default function GraphPage() {
  const [graph, setGraph] = useState(null);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const svgRef = useRef(null);
  const [size, setSize] = useState({ w: 960, h: 540 });

  useEffect(() => {
    getGraph()
      .then(setGraph)
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    const el = svgRef.current;
    const observer = new ResizeObserver(() => {
      if (el) setSize({ w: el.clientWidth || 960, h: 540 });
    });
    if (el) observer.observe(el);
    return () => observer.disconnect();
  }, [graph]);

  const allNodes = graph?.nodes || [];
  const allEdges = ((graph?.edges) || []).filter((e) => e.kind === "comm" || e.threat);
  // Cap the laid-out/rendered set so a large graph cannot lock the UI thread.
  const { nodes, edges, hidden } = useMemo(
    () => pickRenderable(allNodes, allEdges),
    [allNodes, allEdges]
  );
  const pos = useForceLayout(nodes, edges, size.w, size.h);
  const byId = {};
  allNodes.forEach((n) => (byId[n.id] = n));
  const selNode = selected ? byId[selected] : null;

  if (error) return <div className="text-sm text-rose-400">Failed to load graph: {error}</div>;
  if (!graph) return <div className="text-slate-500">Rendering entity graph…</div>;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Module C · entity correlations"
        title="Relationship graph"
        sub="Force-layout over IPs, users, processes, domains and threat classes. Click a node to pivot into its edges and evidence."
        actions={<LiveBadge text={`${allNodes.length} nodes · ${allEdges.length} edges`} />}
      />

      {hidden > 0 && (
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-[12px] text-amber-300">
          Showing the {nodes.length} most connected of {allNodes.length} nodes
          ({hidden} lower-degree nodes hidden) to keep the layout responsive.
        </div>
      )}

      <GlassCard
        title="Entity graph — click any node"
        right={
          <div className="flex flex-wrap gap-3">
            {Object.entries(KIND_COLOR).map(([k, c]) => (
              <LegendDot key={k} color={c} label={k} />
            ))}
          </div>
        }
      >
        <div className="terminal overflow-hidden rounded-xl border border-white/5 bg-black/50 p-3" ref={svgRef}>
          <svg width={size.w} height={size.h} className="block">
            <defs>
              {Object.entries(KIND_COLOR).map(([k, c]) => (
                <radialGradient key={k} id={`nodeg-${k}`} cx="35%" cy="30%" r="75%">
                  <stop offset="0%" stopColor="#ffffff" stopOpacity="0.9" />
                  <stop offset="25%" stopColor={c} stopOpacity="0.95" />
                  <stop offset="100%" stopColor={c} stopOpacity="0.4" />
                </radialGradient>
              ))}
              <filter id="edgeGlow" x="-40%" y="-40%" width="180%" height="180%">
                <feGaussianBlur stdDeviation="2.2" result="blur" />
                <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
            </defs>

            {edges.map((e, i) => {
              const a = pos[e.source];
              const b = pos[e.target];
              if (!a || !b) return null;
              const threatened = e.threat === 1;
              const ax = a.x, ay = a.y, bx = b.x, by = b.y;
              const mx = (ax + bx) / 2, my = (ay + by) / 2;
              const dx = bx - ax, dy = by - ay;
              const len = Math.sqrt(dx * dx + dy * dy) || 1;
              const px = -dy / len, py = dx / len;
              const qx = mx + px * 18, qy = my + py * 18;
              const path = threatened
                ? `M ${ax} ${ay} Q ${qx} ${qy} ${bx} ${by}`
                : `M ${ax} ${ay} L ${bx} ${by}`;
              return (
                <g key={i}>
                  <path
                    d={path}
                    fill="none"
                    stroke={threatened ? "#f43f5e" : "#2a3a55"}
                    strokeWidth={threatened ? 1.8 : 1}
                    opacity={threatened ? 0.95 : 0.6}
                    filter={threatened ? "url(#edgeGlow)" : undefined}
                    strokeLinecap="round"
                  />
                  {threatened && e.flows && (
                    <text x={mx} y={my - 4} textAnchor="middle" fontSize="8.5" className="fill-slate-400 mono">
                      {e.flows}f
                    </text>
                  )}
                </g>
              );
            })}

            {nodes.map((n) => {
              const p = pos[n.id] || { x: 10, y: 10 };
              const isSel = selected === n.id;
              const r = n.kind === "threat" ? 11 : n.kind === "domain" ? 9 : 7;
              return (
                <g key={n.id} onClick={() => setSelected(isSel ? null : n.id)} style={{ cursor: "pointer" }}>
                  {isSel && (
                    <circle cx={p.x} cy={p.y} r={19} fill="none" stroke={KIND_COLOR[n.kind] || "#34d399"} strokeWidth="1.4" opacity="0.65">
                      <animate attributeName="r" values="16;24;16" dur="2s" repeatCount="indefinite" />
                      <animate attributeName="opacity" values="0.6;0.1;0.6" dur="2s" repeatCount="indefinite" />
                    </circle>
                  )}
                  <circle
                    cx={p.x}
                    cy={p.y}
                    r={r}
                    fill={KIND_COLOR[n.kind] ? `url(#nodeg-${n.kind})` : "#34d399"}
                    stroke={isSel ? "#f8fafc" : "rgba(255,255,255,0.25)"}
                    strokeWidth={isSel ? 1.6 : 0.6}
                    style={{ filter: `drop-shadow(0 0 ${isSel ? 10 : 5}px ${KIND_COLOR[n.kind] || "#34d399"})` }}
                  />
                  <text
                    x={p.x}
                    y={p.y + (n.kind === "threat" ? -16 : -13)}
                    textAnchor="middle"
                    fontSize={isSel ? 12.5 : n.kind === "threat" ? 11 : 9.5}
                    fontWeight={isSel ? 700 : 400}
                    fill={isSel ? "#f8fafc" : "#a7b6c9"}
                    className="mono"
                    style={{ paintOrder: "stroke", stroke: "#05080f", strokeWidth: 3 }}
                  >
                    {n.label && String(n.label).length > 18 ? String(n.label).slice(0, 17) + "…" : n.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
        <p className="mt-2 text-[11px] text-slate-500">
          Amber curves carry module-threat flags · hover nothing, click everything.
        </p>
      </GlassCard>

      {selNode && (
        <GlassCard
          title={`Node — ${selNode.label || selNode.id}`}
          right={
            <div className="flex items-center gap-3">
              <LegendDot color={KIND_COLOR[selNode.kind] || "#34d399"} label={selNode.kind} />
              <button onClick={() => setSelected(null)} className="text-[12px] text-slate-500 hover:text-slate-200">
                close ×
              </button>
            </div>
          }
        >
          <div className="grid gap-5 md:grid-cols-[1.2fr_1fr]">
            <div>
              {(() => {
                // Detail view always uses the full edge set: the count and the
                // list must agree, and a trimmed node may still have more
                // relationships than the layout shows.
                const linked = allEdges.filter(
                  (e) => e.source === selected || e.target === selected
                );
                return (
                  <>
                    <p className="eyebrow mb-2">Connected edges ({linked.length})</p>
                    <div className="max-h-64 space-y-1.5 overflow-y-auto pr-1">
                      {linked.slice(0, 40).map((e, i) => (
                        <div key={i} className="glass-row flex items-center justify-between gap-2 px-3 py-1.5 text-[12px]">
                          <span className="mono truncate text-slate-300">{e.source} → {e.target}</span>
                          <span className="flex shrink-0 items-center gap-2">
                            <PlainBadge>{e.kind}</PlainBadge>
                            {e.flows ? <span className="mono text-[10px] text-slate-500">{e.flows}f</span> : null}
                            {e.threat ? <span className="h-1.5 w-1.5 rounded-full bg-rose-500 pulse-dot-red" /> : null}
                          </span>
                        </div>
                      ))}
                      {linked.length === 0 && (
                        <p className="px-3 py-2 text-[12px] text-slate-500">
                          No relationships recorded for this node yet.
                        </p>
                      )}
                    </div>
                  </>
                );
              })()}
            </div>
            <div>
              <p className="eyebrow mb-2">Node payload</p>
              <CodeBlock maxH="max-h-64">{JSON.stringify(selNode, null, 2)}</CodeBlock>
            </div>
          </div>
        </GlassCard>
      )}
    </div>
  );
}