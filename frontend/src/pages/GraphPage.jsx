import React, { useEffect, useMemo, useRef, useState } from "react";
import { getGraph } from "../lib/api";
import { computeLayout, pickRenderable, MAX_LAYOUT_NODES } from "../lib/forceLayout";
import { PageHeader, LiveBadge, GlassCard, LegendDot, SeverityBadge, PlainBadge, CodeBlock } from "../components/ui";

function useForceLayout(nodes, edges, width = 900, height = 540) {
  return useMemo(() => computeLayout(nodes, edges, width, height), [nodes, edges, width, height]);
}

const KIND_COLOR = {
  ip: "#22d3ee",
  user: "#34d399",
  proc: "#fbbf24",
  domain: "#818cf8",
  threat: "#f87171",
};

// Module C records six relationship kinds. The page used to keep only `comm`
// and threatened edges, which silently discarded every dns/auth/exec/runs edge
// and left all domain, user and process nodes unconnected. Each kind now gets
// its own stroke so the picture says which relationship it is showing.
const EDGE_STYLE = {
  comm: { stroke: "#2a3a55", width: 1, dash: null, label: "comm" },
  dns: { stroke: "#6366f1", width: 1, dash: "3 3", label: "dns" },
  auth: { stroke: "#34d399", width: 1.5, dash: null, label: "auth" },
  exec: { stroke: "#fbbf24", width: 1.5, dash: "5 3", label: "exec" },
  runs: { stroke: "#a78bfa", width: 1.2, dash: null, label: "runs" },
  flagged: { stroke: "#f87171", width: 1.8, dash: null, label: "flagged" },
};

const NODE_KIND_UNIVERSE = Object.keys(KIND_COLOR);
const REL_KIND_UNIVERSE = Object.keys(EDGE_STYLE);

export default function GraphPage() {
  const [graph, setGraph] = useState(null);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  // null = no filter on that axis.
  const [nodeKinds, setNodeKinds] = useState(null);
  const [relKinds, setRelKinds] = useState(null);
  const [query, setQuery] = useState("");
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
  // Every relationship kind is eligible: filtering to comm+threat orphaned
  // 4,249 of 5,000 nodes and made the node detail claim "no relationships"
  // for users and processes that demonstrably had them.
  const allEdges = graph?.edges || [];

  // Filters run *before* the layout cap, so narrowing to one kind actually
  // gives that kind the whole node budget instead of losing to degree.
  const kindEdges = useMemo(
    () => (relKinds ? allEdges.filter((e) => relKinds.has(e.kind)) : allEdges),
    [allEdges, relKinds]
  );
  // Narrowing to one entity kind would otherwise strand it: a domain's only
  // edge points at an IP that the filter removed, leaving isolated dots. Pull
  // one-hop neighbours back in as dimmed context so the relationships survive.
  const kindNodes = useMemo(() => {
    if (!nodeKinds) return allNodes;
    const focus = allNodes.filter((n) => nodeKinds.has(n.kind));
    const ids = new Set(focus.map((n) => n.id));
    const out = [...focus];
    const seen = new Set(ids);
    const byIdLocal = new Map(allNodes.map((n) => [n.id, n]));
    const addCtx = (id) => {
      if (seen.has(id)) return;
      const n = byIdLocal.get(id);
      if (!n) return;
      seen.add(id);
      out.push({ ...n, ctx: true });
    };
    for (const e of kindEdges) {
      // Only the far end of an edge that leaves the focus set is context.
      const sFocus = ids.has(e.source);
      const tFocus = ids.has(e.target);
      if (sFocus && !tFocus) addCtx(e.target);
      if (tFocus && !sFocus) addCtx(e.source);
    }
    return out;
  }, [allNodes, nodeKinds, kindEdges]);
  // Search is over the whole payload, not just what survived trimming, so the
  // 4,820 omitted nodes are still reachable.
  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    const hits = [];
    for (const n of allNodes) {
      if (String(n.label || "").toLowerCase().includes(q) || String(n.id).toLowerCase().includes(q)) {
        hits.push(n);
        if (hits.length >= 8) break;
      }
    }
    return hits;
  }, [allNodes, query]);
  const pins = useMemo(() => (selected ? [selected] : []), [selected]);

  // Cap the laid-out/rendered set so a large graph cannot lock the UI thread.
  const { nodes, edges, hidden } = useMemo(
    () => pickRenderable(kindNodes, kindEdges, MAX_LAYOUT_NODES, pins),
    [kindNodes, kindEdges, pins]
  );
  const pos = useForceLayout(nodes, edges, size.w, size.h);
  const byId = {};
  allNodes.forEach((n) => (byId[n.id] = n));
  const selNode = selected ? byId[selected] : null;
  const kindCounts = useMemo(() => {
    const c = {};
    for (const e of kindEdges) c[e.kind] = (c[e.kind] || 0) + 1;
    return c;
  }, [kindEdges]);
  // Count what is actually on screen, so the legend cannot advertise a kind
  // that trimming removed. Context nodes are excluded: the entity chips
  // deliberately filtered those kinds out.
  const drawnNodeKinds = useMemo(() => {
    const c = {};
    for (const n of nodes) {
      if (n.ctx) continue;
      c[n.kind] = (c[n.kind] || 0) + 1;
    }
    return c;
  }, [nodes]);
  const ctxCount = useMemo(() => nodes.filter((n) => n.ctx).length, [nodes]);
  const drawnEdgeKinds = useMemo(() => {
    const c = {};
    for (const e of edges) c[e.kind] = (c[e.kind] || 0) + 1;
    return c;
  }, [edges]);

  // Chips behave like checkboxes over the full set of kinds: clicking an
  // active chip turns that kind off, and turning the last one back on clears
  // the filter entirely.
  const toggle = (setter, kind, universe) =>
    setter((prev) => {
      const next = new Set(prev || universe);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next.size === universe.length || next.size === 0 ? null : next;
    });

  const anyFilter = !!nodeKinds || !!relKinds || !!query.trim();
  // Search pins a node rather than removing any, so only the kind chips
  // change what "matching" means.
  const kindFilterActive = !!nodeKinds || !!relKinds;
  const clearFilters = () => {
    setNodeKinds(null);
    setRelKinds(null);
    setQuery("");
  };
  const allNodeKindCounts = useMemo(() => {
    const c = {};
    for (const n of allNodes) c[n.kind] = (c[n.kind] || 0) + 1;
    return c;
  }, [allNodes]);
  const allRelKindCounts = useMemo(() => {
    const c = {};
    for (const e of allEdges) c[e.kind] = (c[e.kind] || 0) + 1;
    return c;
  }, [allEdges]);

  if (error) return <div className="text-sm text-red-400">Failed to load graph: {error}</div>;
  if (!graph) return <div className="text-slate-500">Rendering entity graph…</div>;

  const chip = (label, active, onClick, color) => (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`rounded-full border px-2.5 py-1 text-[11px] transition ${
        active
          ? "border-transparent bg-slate-100/90 font-medium text-slate-900"
          : "border-white/10 bg-white/5 text-slate-400 hover:border-white/25 hover:text-slate-200"
      }`}
    >
      {color ? (
        <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full align-middle" style={{ background: color }} />
      ) : null}
      {label}
    </button>
  );

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Module C · entity correlations"
        title="Relationship graph"
        sub="Force-layout over IPs, users, processes, domains and threat classes. Click a node to pivot into its edges and evidence."
        actions={<LiveBadge text={`${allNodes.length} nodes · ${allEdges.length} edges`} />}
      />

      <GlassCard title="Filters" right={anyFilter ? (
        <button type="button" onClick={clearFilters} className="text-[12px] text-slate-500 hover:text-slate-200">
          clear all
        </button>
      ) : null}>
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="eyebrow w-24 shrink-0">Entity</span>
            {Object.entries(KIND_COLOR)
              .filter(([k]) => allNodeKindCounts[k])
              .map(([k, c]) =>
                chip(
                  `${k} ${allNodeKindCounts[k].toLocaleString()}`,
                  !nodeKinds || nodeKinds.has(k),
                  () => toggle(setNodeKinds, k, NODE_KIND_UNIVERSE),
                  c
                )
              )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="eyebrow w-24 shrink-0">Relationship</span>
            {Object.keys(EDGE_STYLE)
              .filter((k) => allRelKindCounts[k])
              .map((k) =>
                chip(
                  `${k} ${allRelKindCounts[k].toLocaleString()}`,
                  !relKinds || relKinds.has(k),
                  () => toggle(setRelKinds, k, REL_KIND_UNIVERSE),
                  EDGE_STYLE[k].stroke
                )
              )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="eyebrow w-24 shrink-0">Find</span>
            <div className="relative min-w-[16rem] flex-1">
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="search any node by id or label, e.g. deploy or 10.10.1.10"
                className="field mono w-full px-3 py-1.5 text-[12px]"
              />
              {query.trim() ? (
                <div className="absolute z-20 mt-1 max-h-64 w-full overflow-y-auto rounded-lg border border-white/10 bg-slate-900/95 shadow-xl">
                  {matches.length === 0 && (
                    <p className="px-3 py-2 text-[12px] text-slate-500">No node matches “{query.trim()}”.</p>
                  )}
                  {matches.map((n) => (
                    <button
                      key={n.id}
                      type="button"
                      onClick={() => {
                        setSelected(n.id);
                        setQuery(n.label || n.id);
                      }}
                      className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-[12px] hover:bg-white/10 ${
                        selected === n.id ? "bg-white/10" : ""
                      }`}
                    >
                      <span
                        className="h-1.5 w-1.5 shrink-0 rounded-full"
                        style={{ background: KIND_COLOR[n.kind] || "#34d399" }}
                      />
                      <span className="mono truncate text-slate-200">{n.label || n.id}</span>
                      <span className="ml-auto shrink-0 text-[10px] text-slate-500">{n.kind}</span>
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
            {kindFilterActive && (
              <span className="mono text-[11px] text-slate-500">
                matching {kindNodes.length.toLocaleString()} nodes · {kindEdges.length.toLocaleString()} edges
              </span>
            )}
          </div>
        </div>
      </GlassCard>

      {hidden > 0 && (
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-[12px] text-amber-300">
          Laying out {nodes.length} of {kindNodes.length.toLocaleString()} nodes (
          {hidden.toLocaleString()} omitted) to keep the layout responsive. User, process and threat
          nodes are always included, so their relationships stay visible.
        </div>
      )}

      {nodes.length === 0 && (
        <div className="rounded-lg border border-white/10 bg-white/5 px-3 py-6 text-center text-[12px] text-slate-500">
          {allNodes.length === 0
            ? "No entities recorded yet. The store is waiting for traffic."
            : "No nodes match these filters. Re-enable an entity or relationship kind."}
        </div>
      )}

      <GlassCard
        title="Entity graph — click any node"
        right={
          <div className="flex flex-wrap gap-3">
            {Object.entries(KIND_COLOR)
              .filter(([k]) => drawnNodeKinds[k])
              .map(([k, c]) => (
                <LegendDot key={k} color={c} label={`${k} ${drawnNodeKinds[k]}`} />
              ))}
          </div>
        }
      >
        <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-[11px] text-slate-500">
          <span className="eyebrow">Relationships</span>
          {Object.keys(EDGE_STYLE)
            .filter((k) => kindCounts[k])
            .map((k) => {
              const s = EDGE_STYLE[k];
              const drawn = drawnEdgeKinds[k] || 0;
              const total = kindCounts[k];
              const partial = drawn < total;
              return (
                <span
                  key={k}
                  className={`flex items-center gap-1.5 ${partial ? "opacity-60" : ""}`}
                  title={partial ? `${total.toLocaleString()} recorded, ${drawn.toLocaleString()} laid out` : undefined}
                >
                  <svg width="26" height="8" aria-hidden="true">
                    <line
                      x1="1"
                      y1="4"
                      x2="25"
                      y2="4"
                      stroke={s.stroke}
                      strokeWidth={s.width}
                      strokeDasharray={s.dash || undefined}
                      strokeLinecap="round"
                    />
                  </svg>
                  <span className="mono text-slate-400">
                    {k} {drawn.toLocaleString()}
                    {partial ? ` of ${total.toLocaleString()}` : ""}
                  </span>
                </span>
              );
            })}
        </div>
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
              const threatened = e.threat === 1 || e.kind === "flagged";
              const style = threatened ? EDGE_STYLE.flagged : EDGE_STYLE[e.kind] || EDGE_STYLE.comm;
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
                    stroke={style.stroke}
                    strokeWidth={style.width}
                    strokeDasharray={style.dash || undefined}
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
              // Context nodes exist only to anchor a filtered node's edges.
              return (
                <g
                  key={n.id}
                  onClick={() => setSelected(isSel ? null : n.id)}
                  style={{ cursor: "pointer", opacity: n.ctx && !isSel ? 0.45 : 1 }}
                >
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
                    fontSize={isSel ? 12.5 : n.kind === "threat" ? 11 : n.ctx ? 8.5 : 9.5}
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
          Rose curves carry module-threat flags · dashed lines are dns lookups · hover nothing,
          click everything.
          {ctxCount > 0 && ` · ${ctxCount} dimmed node${ctxCount === 1 ? "" : "s"} shown as context for the filtered entity`}
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
                    <p className="eyebrow mb-2">
                      Connected edges ({linked.length.toLocaleString()}
                      {linked.length > 40 ? ` · showing first 40` : ""})
                    </p>
                    <div className="max-h-64 space-y-1.5 overflow-y-auto pr-1">
                      {linked.slice(0, 40).map((e, i) => (
                        <div key={i} className="glass-row flex items-center justify-between gap-2 px-3 py-1.5 text-[12px]">
                          <span className="mono truncate text-slate-300">{e.source} → {e.target}</span>
                          <span className="flex shrink-0 items-center gap-2">
                            <PlainBadge>{e.kind}</PlainBadge>
                            {e.flows ? <span className="mono text-[10px] text-slate-500">{e.flows}f</span> : null}
                            {e.threat ? <span className="h-1.5 w-1.5 rounded-full bg-red-400 pulse-dot-red" /> : null}
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