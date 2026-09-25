// Force-directed layout helpers for the entity graph.
//
// Kept out of the page component so the cost is unit-testable: the previous
// inline implementation ran 220 iterations of O(n^2) repulsion on the main
// thread, which froze the UI for seconds once the graph had real volume
// (3.5s at 856 nodes, 11s at 1500, and the API permits 5000).

// An SVG force graph cannot usefully render thousands of nodes, so we lay out
// only the most significant ones and tell the user how many were hidden.
export const MAX_LAYOUT_NODES = 180;

// Ranking purely by degree buried the interesting half of the graph: there are
// ~1000 IPs but only a handful of users, processes and threat classes, so the
// cap filled with high-degree IPs and every auth/exec/runs/flagged edge lost
// an endpoint. Those nodes then rendered as unconnected dots even though the
// legend advertised their colour. Reserve part of the budget for them.
export const RESERVED_KINDS = ["threat", "user", "proc"];
export const RESERVED_FRACTION = 0.25;

const SEVERITY_RANK = { critical: 5, high: 4, warning: 3, medium: 3, low: 2, none: 1 };

/**
 * Keep the most significant nodes: degree first (hubs carry the structure),
 * then severity, so trimming never hides the interesting part of the graph.
 * A reserved slice of the budget is held for RESERVED_KINDS so their
 * relationships survive. Edges are kept only when both endpoints survive, so
 * the render is consistent.
 */
export function pickRenderable(nodes, edges, cap = MAX_LAYOUT_NODES) {
  if (nodes.length <= cap) return { nodes, edges, hidden: 0 };

  const degree = new Map();
  for (const e of edges) {
    degree.set(e.source, (degree.get(e.source) || 0) + 1);
    degree.set(e.target, (degree.get(e.target) || 0) + 1);
  }
  const ranked = [...nodes].sort((a, b) => {
    const d = (degree.get(b.id) || 0) - (degree.get(a.id) || 0);
    if (d) return d;
    const s = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
    if (s) return s;
    return String(a.id).localeCompare(String(b.id));
  });

  const keep = new Set();
  const reserve = Math.max(1, Math.floor(cap * RESERVED_FRACTION));
  for (const kind of RESERVED_KINDS) {
    let taken = 0;
    for (const n of ranked) {
      if (taken >= reserve) break;
      if (n.kind === kind) {
        keep.add(n.id);
        taken += 1;
      }
    }
  }
  for (const n of ranked) {
    if (keep.size >= cap) break;
    keep.add(n.id);
  }

  const kept = ranked.filter((n) => keep.has(n.id));
  return {
    nodes: kept,
    edges: edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
    hidden: nodes.length - kept.length,
  };
}

/**
 * Index-based force layout. Positions/forces live in typed arrays and the
 * adjacency list is derived from the edges once, rather than rebuilt per
 * iteration, so cost stays proportional to the capped node count.
 */
export function computeLayout(nodes, edges, width = 900, height = 540) {
  const n = nodes.length;
  const pos = {};
  if (!n) return pos;

  const idx = new Map();
  nodes.forEach((node, i) => idx.set(node.id, i));
  const px = new Float64Array(n);
  const py = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const angle = (i / n) * 2 * Math.PI;
    px[i] = width / 2 + Math.cos(angle) * 190;
    py[i] = height / 2 + Math.sin(angle) * 150;
  }

  // Build adjacency (CSR) once.
  const adjStart = new Int32Array(n + 1);
  const pairs = [];
  for (const e of edges) {
    const a = idx.get(e.source);
    const b = idx.get(e.target);
    if (a === undefined || b === undefined || a === b) continue;
    pairs.push(a, b);
  }
  for (let i = 0; i < pairs.length; i += 2) {
    adjStart[pairs[i] + 1]++;
    adjStart[pairs[i + 1] + 1]++;
  }
  for (let i = 0; i < n; i++) adjStart[i + 1] += adjStart[i];
  const adj = new Int32Array(pairs.length);
  const cursor = adjStart.slice(0, n);
  for (let i = 0; i < pairs.length; i += 2) {
    adj[cursor[pairs[i]]++] = pairs[i + 1];
    adj[cursor[pairs[i + 1]]++] = pairs[i];
  }

  const fx = new Float64Array(n);
  const fy = new Float64Array(n);
  const k = 0.55;
  const iters = n > 140 ? 90 : 160;

  for (let iter = 0; iter < iters; iter++) {
    fx.fill(0);
    fy.fill(0);
    for (let i = 0; i < n; i++) {
      const axi = px[i];
      const ayi = py[i];
      for (let j = i + 1; j < n; j++) {
        const dx = axi - px[j];
        const dy = ayi - py[j];
        const dist2 = dx * dx + dy * dy || 20;
        const d = Math.sqrt(dist2);
        const f = ((k * 9000) / (dist2 < 20 ? 20 : dist2)) / d;
        const ux = f * dx;
        const uy = f * dy;
        fx[i] += ux;
        fy[i] += uy;
        fx[j] -= ux;
        fy[j] -= uy;
      }
    }
    for (let i = 0; i < n; i++) {
      for (let a = adjStart[i]; a < adjStart[i + 1]; a++) {
        const t = adj[a];
        const dx = px[t] - px[i];
        const dy = py[t] - py[i];
        const d = Math.sqrt(dx * dx + dy * dy) || 1e-6;
        const f = (0.12 * d) / d;
        fx[i] += f * dx;
        fy[i] += f * dy;
      }
    }
    for (let i = 0; i < n; i++) {
      px[i] = Math.max(20, Math.min(width - 20, px[i] + fx[i]));
      py[i] = Math.max(20, Math.min(height - 20, py[i] + fy[i]));
    }
  }

  for (let i = 0; i < n; i++) pos[nodes[i].id] = { x: px[i], y: py[i] };
  return pos;
}
