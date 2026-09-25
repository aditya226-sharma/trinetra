import { describe, it, expect } from "vitest";
import { computeLayout, pickRenderable, MAX_LAYOUT_NODES } from "./forceLayout";

const mk = (n, edgesPer = 1.2) => {
  const nodes = Array.from({ length: n }, (_, i) => ({
    id: `n${i}`,
    severity: ["none", "low", "warning", "high", "critical"][i % 5],
  }));
  const edges = Array.from({ length: Math.floor(n * edgesPer) }, (_, i) => ({
    source: `n${i % n}`,
    target: `n${(i * 7 + 3) % n}`,
  }));
  return { nodes, edges };
};

describe("pickRenderable", () => {
  it("passes small graphs through untouched", () => {
    const { nodes, edges } = mk(50);
    const r = pickRenderable(nodes, edges);
    expect(r.nodes).toHaveLength(50);
    expect(r.edges).toHaveLength(edges.length);
    expect(r.hidden).toBe(0);
  });

  it("caps the laid-out node count and reports what it hid", () => {
    const { nodes, edges } = mk(2000);
    const r = pickRenderable(nodes, edges);
    expect(r.nodes.length).toBeLessThanOrEqual(MAX_LAYOUT_NODES);
    expect(r.hidden).toBe(2000 - r.nodes.length);
  });

  it("keeps the highest-degree nodes so structure survives trimming", () => {
    const nodes = [
      { id: "hub", severity: "none" },
      { id: "leaf", severity: "critical" },
    ];
    const edges = [];
    for (let i = 0; i < 40; i++) edges.push({ source: "hub", target: `x${i}` });
    // pad to exceed the cap with degree-0 nodes
    for (let i = 0; i < MAX_LAYOUT_NODES + 10; i++) nodes.push({ id: `n${i}` });
    const r = pickRenderable(nodes, edges, 5);
    expect(r.nodes.map((n) => n.id)).toContain("hub");
  });

  it("drops edges whose endpoints were trimmed, so render stays consistent", () => {
    const { nodes, edges } = mk(400);
    const r = pickRenderable(nodes, edges, 20);
    const ids = new Set(r.nodes.map((n) => n.id));
    for (const e of r.edges) {
      expect(ids.has(e.source)).toBe(true);
      expect(ids.has(e.target)).toBe(true);
    }
  });
});

describe("computeLayout", () => {
  it("positions every node inside the viewport", () => {
    const { nodes, edges } = pickRenderable(...Object.values(mk(300)));
    const pos = computeLayout(nodes, edges, 900, 540);
    expect(Object.keys(pos)).toHaveLength(nodes.length);
    for (const p of Object.values(pos)) {
      expect(p.x).toBeGreaterThanOrEqual(20);
      expect(p.x).toBeLessThanOrEqual(880);
      expect(p.y).toBeGreaterThanOrEqual(20);
      expect(p.y).toBeLessThanOrEqual(520);
    }
  });

  it("handles an empty graph", () => {
    expect(computeLayout([], [])).toEqual({});
  });

  it("ignores edges referencing unknown nodes", () => {
    const nodes = [{ id: "a" }, { id: "b" }];
    const pos = computeLayout(nodes, [
      { source: "a", target: "ghost" },
      { source: "a", target: "b" },
    ]);
    expect(Object.keys(pos).sort()).toEqual(["a", "b"]);
  });

  // Regression: the inline version froze the main thread for 3.5s at 856
  // nodes (and ~11s at 1500) because it ran 220 O(n^2) passes and rebuilt the
  // adjacency map every iteration.
  it("stays fast on an API-sized graph", () => {
    const big = mk(5000);
    const { nodes, edges } = pickRenderable(big.nodes, big.edges);
    const t0 = performance.now();
    computeLayout(nodes, edges, 900, 540);
    const ms = performance.now() - t0;
    expect(ms).toBeLessThan(400);
  });
});
