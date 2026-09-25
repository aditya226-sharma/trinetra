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

  it("drops dangling edges on the untrimmed fast path too", () => {
    // A kind filter can leave edges pointing at nodes that are gone. Counting
    // those made the legend claim relationships the canvas cannot draw.
    const nodes = [{ id: "a", kind: "domain" }, { id: "b", kind: "ip" }];
    const edges = [
      { source: "a", target: "b", kind: "dns" },
      { source: "a", target: "gone", kind: "comm" },
      { source: "gone", target: "b", kind: "comm" },
    ];
    const r = pickRenderable(nodes, edges);
    expect(r.edges).toHaveLength(1);
    expect(r.edges[0].kind).toBe("dns");
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

  it("reserves budget for user/proc/threat so their relationships survive", () => {
    // Mirrors the live shape: a flood of high-degree IPs plus a handful of
    // users, processes and threat classes whose edges all point at IPs.
    const nodes = [];
    const edges = [];
    for (let i = 0; i < 1000; i++) nodes.push({ id: `ip${i}`, kind: "ip", severity: "none" });
    for (let i = 0; i < 4; i++) nodes.push({ id: `user:${i}`, kind: "user", severity: "none" });
    for (let i = 0; i < 1; i++) nodes.push({ id: `proc:${i}`, kind: "proc", severity: "none" });
    for (let i = 0; i < 3; i++) nodes.push({ id: `threat:${i}`, kind: "threat", severity: "high" });
    for (let i = 0; i < 15546; i++) {
      edges.push({ source: `ip${i % 1000}`, target: `ip${(i * 7 + 3) % 1000}`, kind: "comm" });
    }
    for (let i = 0; i < 25; i++) edges.push({ source: `user:${i % 4}`, target: `ip${i}`, kind: "auth" });
    for (let i = 0; i < 4; i++) edges.push({ source: `user:${i}`, target: "proc:0", kind: "exec" });
    for (let i = 0; i < 424; i++) {
      edges.push({ source: `ip${i % 1000}`, target: `threat:${i % 3}`, kind: "flagged", threat: 1 });
    }

    const r = pickRenderable(nodes, edges);
    const ids = new Set(r.nodes.map((n) => n.id));
    for (const n of nodes) {
      if (n.kind === "ip") continue;
      expect(ids).toContain(n.id);
    }
    const kinds = new Set(r.edges.map((e) => e.kind));
    expect(kinds).toContain("auth");
    expect(kinds).toContain("exec");
    expect(kinds).toContain("flagged");
  });

  it("still honours the cap when reserved kinds are numerous", () => {
    const nodes = Array.from({ length: 900 }, (_, i) => ({
      id: `user:${i}`,
      kind: "user",
      severity: "none",
    }));
    for (let i = 0; i < 100; i++) nodes.push({ id: `ip${i}`, kind: "ip", severity: "none" });
    const edges = [];
    for (let i = 0; i < 200; i++) edges.push({ source: `user:${i}`, target: `ip${i % 100}` });
    const r = pickRenderable(nodes, edges, 20);
    expect(r.nodes.length).toBeLessThanOrEqual(20);
    expect(r.hidden).toBe(nodes.length - r.nodes.length);
  });

  it("keeps a pinned search hit even when it is low-degree", () => {
    // A degree-0 node would never survive degree ranking, but the user
    // searched for it by name, so it has to be on screen.
    const nodes = [{ id: "needle", kind: "domain", severity: "none" }];
    for (let i = 0; i < 400; i++) {
      nodes.push({ id: `ip${i}`, kind: "ip", severity: "none" });
      if (i) nodes.push({ id: `d${i}`, kind: "domain", severity: "none" });
    }
    const edges = [];
    for (let i = 1; i < 400; i++) edges.push({ source: `ip${i}`, target: `ip${(i * 3) % 400}` });

    const without = pickRenderable(nodes, edges, 20);
    expect(without.nodes.map((n) => n.id)).not.toContain("needle");

    const withPin = pickRenderable(nodes, edges, 20, ["needle"]);
    expect(withPin.nodes.map((n) => n.id)).toContain("needle");
    expect(withPin.nodes.length).toBeLessThanOrEqual(20);
  });

  it("ignores a pin that is not in the node set", () => {
    const { nodes, edges } = mk(400);
    const r = pickRenderable(nodes, edges, 20, ["nope", "n5"]);
    expect(r.nodes.map((n) => n.id)).toContain("n5");
    expect(r.nodes.map((n) => n.id)).not.toContain("nope");
    expect(r.nodes.length).toBeLessThanOrEqual(20);
  });

  it("ranks focus nodes above ctx context nodes", () => {
    // Context exists so a filtered node keeps its edges; it must never
    // displace the node the user filtered for.
    const nodes = [];
    const edges = [];
    for (let i = 0; i < 50; i++) {
      nodes.push({ id: `ctx${i}`, kind: "ip", severity: "none", ctx: true });
      edges.push({ source: `ctx${i}`, target: `focus${i}`, kind: "dns" });
      nodes.push({ id: `focus${i}`, kind: "domain", severity: "none" });
    }
    const r = pickRenderable(nodes, edges, 20);
    const keptCtx = r.nodes.filter((n) => n.ctx).length;
    expect(keptCtx).toBe(0);
    expect(r.nodes).toHaveLength(20);
    expect(r.nodes.every((n) => n.kind === "domain")).toBe(true);
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
