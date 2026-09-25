import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import GraphPage from "./GraphPage";
import * as api from "../lib/api";

vi.mock("../lib/api", () => ({
  getGraph: vi.fn(),
}));

// The live graph shape that exposed the defect: a flood of comm edges plus
// dns/auth/exec/runs relationships the page used to discard.
const graph = () => {
  const nodes = [
    { id: "10.10.1.10", label: "10.10.1.10", kind: "ip", severity: "none" },
    { id: "10.10.1.22", label: "10.10.1.22", kind: "ip", severity: "none" },
    { id: "user:deploy", label: "deploy", kind: "user", severity: "none" },
    { id: "proc:sshd", label: "sshd", kind: "proc", severity: "none" },
    { id: "domain:evil.top", label: "evil.top", kind: "domain", severity: "none" },
    { id: "threat:port_scan", label: "port_scan", kind: "threat", severity: "high" },
  ];
  const edges = [
    { source: "10.10.1.10", target: "10.10.1.22", kind: "comm", flows: 12, threat: 0 },
    { source: "user:deploy", target: "10.10.1.10", kind: "auth", flows: 30, threat: 0 },
    { source: "user:deploy", target: "proc:sshd", kind: "exec", flows: 20, threat: 0 },
    { source: "10.10.1.10", target: "proc:sshd", kind: "runs", flows: 30, threat: 0 },
    { source: "domain:evil.top", target: "10.10.1.22", kind: "dns", flows: 1, threat: 0 },
    {
      source: "10.10.1.22",
      target: "threat:port_scan",
      kind: "flagged",
      flows: 1,
      threat: 1,
    },
  ];
  return { nodes, edges, findings: {}, client_id: "edge-fw-01" };
};

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={["/graph"]}>
      <GraphPage />
    </MemoryRouter>
  );

describe("GraphPage", () => {
  beforeEach(() => {
    api.getGraph.mockReset();
    api.getGraph.mockResolvedValue(graph());
    // jsdom has no ResizeObserver; the page uses it to size the viewport.
    globalThis.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  });

  it("draws every relationship kind, not just comm and threatened edges", async () => {
    const { container } = renderPage();
    await screen.findByText(/Relationship graph/i);

    const paths = container.querySelectorAll("svg path");
    const dashes = Array.from(paths).map((p) => p.getAttribute("stroke-dasharray"));
    const strokes = Array.from(paths).map((p) => p.getAttribute("stroke"));

    // dns is dashed, auth/exec/runs use their own colours, flagged is red.
    expect(dashes).toContain("3 3");
    expect(strokes).toContain("#34d399"); // auth
    expect(strokes).toContain("#fbbf24"); // exec
    expect(strokes).toContain("#a78bfa"); // runs
    expect(strokes).toContain("#f43f5e"); // flagged
  });

  it("counts and labels each relationship kind in the legend", async () => {
    const { container } = renderPage();
    await screen.findByText(/Relationship graph/i);
    for (const kind of ["comm", "dns", "auth", "exec", "runs", "flagged"]) {
      expect(screen.getByText(new RegExp(`^${kind} `))).toBeTruthy();
    }
    // The small fixture lays out every node, so drawn counts are the totals.
    expect(container.textContent).toContain("auth 1");
    expect(container.textContent).toContain("exec 1");
  });
  it("never advertises a relationship kind that was not drawn", async () => {
    // 250 mutually-connected ips, so degree ranking fills the whole cap with
    // them. The domain has degree 1 and loses, which strands its dns edge:
    // the legend must report "0 of 1" rather than implying dns is on screen.
    const nodes = Array.from({ length: 250 }, (_, i) => ({
      id: `ip${i}`,
      label: `ip${i}`,
      kind: "ip",
      severity: "none",
    }));
    const edges = [];
    for (let i = 0; i < 250; i++) {
      edges.push({ source: `ip${i}`, target: `ip${(i + 1) % 250}`, kind: "comm", flows: 2, threat: 0 });
      edges.push({ source: `ip${i}`, target: `ip${(i + 2) % 250}`, kind: "comm", flows: 2, threat: 0 });
    }
    nodes.push(
      { id: "user:deploy", label: "deploy", kind: "user", severity: "none" },
      { id: "proc:sshd", label: "sshd", kind: "proc", severity: "none" },
      { id: "domain:evil.top", label: "evil.top", kind: "domain", severity: "none" }
    );
    edges.push(
      { source: "user:deploy", target: "ip0", kind: "auth", flows: 3, threat: 0 },
      { source: "user:deploy", target: "proc:sshd", kind: "exec", flows: 3, threat: 0 },
      { source: "domain:evil.top", target: "ip0", kind: "dns", flows: 1, threat: 0 }
    );
    api.getGraph.mockResolvedValue({
      nodes,
      edges,
      findings: {},
      client_id: "edge-fw-01",
    });

    const { container } = renderPage();
    await screen.findByText(/Relationship graph/i);

    // auth/exec survive via the reserved slice; dns is recorded but not laid out.
    expect(container.textContent).toContain("auth 1");
    expect(container.textContent).toContain("exec 1");
    expect(container.textContent).toContain("dns 0 of 1");
    // a kind that is drawn but only partly laid out says so too
    expect(container.textContent).toMatch(/comm [\d,]+ of 500/);
    // the domain node was trimmed, so its legend colour is not advertised
    expect(container.textContent).not.toContain("domain 1");
  });

  it("shows a user's real relationships instead of claiming there are none", async () => {
    const { container } = renderPage();
    await screen.findByText(/Relationship graph/i);

    fireEvent.click(screen.getByText("deploy"));
    await waitFor(() => expect(screen.getByText(/Node — deploy/)).toBeTruthy());

    // auth + exec edges exist for this user in the payload.
    expect(screen.queryByText(/No relationships recorded/)).toBeNull();
    expect(container.textContent).toContain("Connected edges (2)");
    expect(container.textContent).toContain("user:deploy → 10.10.1.10");
  });
});
