import React, { useEffect, useMemo, useRef, useState } from "react";
import { getGraph } from "../lib/api";
import { Card } from "../components/ui";

// Minimal force-directed layout in pure SVG — no heavy deps.
function useForceLayout(nodes, edges, width = 900, height = 560) {
  const positions = useMemo(() => {
    const pos = {};
    nodes.forEach((n, i) => {
      const angle = (i / Math.max(nodes.length, 1)) * 2 * Math.PI;
      pos[n.id] = { x: width / 2 + Math.cos(angle) * 180, y: height / 2 + Math.sin(angle) * 140 };
    });
    const k = 0.55;
    for (let iter = 0; iter < 220; iter++) {
      const forces = {};
      nodes.forEach((n) => (forces[n.id] = { x: 0, y: 0 }));
      // repulsion
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = pos[nodes[i].id];
          const b = pos[nodes[j].id];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist2 = Math.max(dx * dx + dy * dy, 20);
          const f = (k * 9000) / dist2;
          const d = Math.sqrt(dist2);
          forces[nodes[i].id].x += (f * dx) / d;
          forces[nodes[i].id].y += (f * dy) / d;
          forces[nodes[j].id].x -= (f * dx) / d;
          forces[nodes[j].id].y -= (f * dy) / d;
        }
      }
      // attraction
      const adj = {};
      edges.forEach((e) => {
        if (!adj[e.source]) adj[e.source] = [];
        adj[e.source].push(e.target);
        if (!adj[e.target]) adj[e.target] = [];
        adj[e.target].push(e.source);
      });
      nodes.forEach((n) => {
        (adj[n.id] || []).forEach((t) => {
          if (!pos[t]) return;
          const dx = pos[t].x - pos[n.id].x;
          const dy = pos[t].y - pos[n.id].y;
          const d = Math.max(Math.sqrt(dx * dx + dy * dy), 1e-6);
          const f = 0.12 * d;
          forces[n.id].x += (f * dx) / d;
          forces[n.id].y += (f * dy) / d;
        });
      });
      nodes.forEach((n) => {
        pos[n.id].x += forces[n.id].x;
        pos[n.id].y += forces[n.id].y;
        pos[n.id].x = Math.max(20, Math.min(width - 20, pos[n.id].x));
        pos[n.id].y = Math.max(20, Math.min(height - 20, pos[n.id].y));
      });
    }
    return pos;
  }, [nodes, edges, width, height]);
  return positions;
}

export default function GraphPage() {
  const [graph, setGraph] = useState(null);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const svgRef = useRef(null);
  const [size, setSize] = useState({ w: 900, h: 560 });

  useEffect(() => {
    getGraph()
      .then(setGraph)
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    const el = svgRef.current;
    const observer = new ResizeObserver(() => {
      if (el) setSize({ w: el.clientWidth || 900, h: 560 });
    });
    if (el) observer.observe(el);
    return () => observer.disconnect();
  }, [graph]);

  const nodes = (graph?.nodes) || [];
  const edges = ((graph?.edges) || []).filter((e) => e.kind === "comm" || e.threat);
  // Hooks must be unconditional — feed empty arrays until data arrives.
  const pos = useForceLayout(nodes, edges, size.w, size.h);
  const byId = {};
  nodes.forEach((n) => (byId[n.id] = n));

  if (error) return <div className="text-red-400">Failed: {error}</div>;
  if (!graph) return <div className="text-slate-400">Loading graph…</div>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Relationship graph</h1>
      <Card
        title="Module C — entity relationship graph"
        actions={
          <div className="flex gap-3 text-xs text-slate-400">
            <Legend color="#4f46e5" label="ip" />
            <Legend color="#059669" label="user" />
            <Legend color="#d97706" label="proc" />
            <Legend color="#0891b2" label="domain" />
            <Legend color="#dc2626" label="threat" />
          </div>
        }
      >
        <div className="rounded-lg bg-slate-950 p-3" ref={svgRef}>
          <svg width={size.w} height={size.h} className="block">
            {edges.map((e, i) => {
              const a = pos[e.source];
              const b = pos[e.target];
              if (!a || !b) return null;
              const threatened = e.threat === 1;
              return (
                <line
                  key={i}
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke={threatened ? "#dc2626" : "#334155"}
                  strokeWidth={threatened ? 2 : 1}
                  opacity={threatened ? 0.9 : 0.5}
                />
              );
            })}
            {nodes.map((n) => {
              const p = pos[n.id] || { x: 10, y: 10 };
              const isSel = selected === n.id;
              return (
                <g
                  key={n.id}
                  onClick={() => setSelected(n.id)}
                  style={{ cursor: "pointer" }}
                >
                  <circle
                    cx={p.x}
                    cy={p.y}
                    r={n.kind === "threat" ? 11 : 7}
                    fill={n.color}
                    stroke={isSel ? "#f8fafc" : "none"}
                    strokeWidth={isSel ? 2 : 0}
                  />
                  <text
                    x={p.x}
                    y={p.y + (n.kind === "threat" ? -14 : -12)}
                    textAnchor="middle"
                    fontSize={isSel ? 12 : n.kind === "threat" ? 11 : 9}
                    fill={isSel ? "#f8fafc" : "#cbd5e1"}
                  >
                    {n.label && String(n.label).length > 16
                      ? String(n.label).slice(0, 15) + "…"
                      : n.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
        <p className="mt-2 text-xs text-slate-500">
          Click any node to inspect it. Red edges carry module-threat flags;
          node labels are IPs, users, processes, domains and threat classes.
        </p>
      </Card>

      {selectedNode() && (
        <Card
          title={`Node — ${selectedNode().label || selectedNode().id}`}
          actions={
            <div className="flex items-center gap-3">
              <Legend color={selectedNode().color} label={selectedNode().kind} />
              <button
                onClick={() => setSelected(null)}
                className="text-xs text-slate-500 hover:text-slate-300"
              >
                close ×
              </button>
            </div>
          }
        >
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <h3 className="mb-2 text-xs uppercase text-slate-500">Connected edges</h3>
              <div className="max-h-56 space-y-1 overflow-y-auto">
                {(graph.edges || [])
                  .filter((e) => e.source === selected || e.target === selected)
                  .slice(0, 40)
                  .map((e, i) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <span className="font-mono text-slate-300">
                        {e.source} → {e.target}
                      </span>
                      <span className={e.threat ? "text-red-400" : "text-slate-500"}>
                        [{e.kind}]{e.flows ? ` ${e.flows} flows` : ""}
                        {e.threat ? " · THREAT" : ""}
                      </span>
                    </div>
                  ))}
              </div>
            </div>
            <div>
              <h3 className="mb-2 text-xs uppercase text-slate-500">Node</h3>
              <pre className="max-h-56 overflow-y-auto rounded-lg bg-slate-950 p-3 text-[11px] text-slate-300">
                {JSON.stringify(selectedNode(), null, 2)}
              </pre>
            </div>
          </div>
        </Card>
      )}
    </div>
  );

  function selectedNode() {
    if (!selected) return null;
    return nodes.find((n) => n.id === selected) || null;
  }
}

function Legend({ color, label }) {
  return (
    <span className="flex items-center gap-1">
      <span className="h-2.5 w-2.5 rounded-full" style={{ background: color }} />
      {label}
    </span>
  );
}