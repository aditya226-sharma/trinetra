import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
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

// The graph card, scoped so legend assertions cannot be satisfied by the
// filter chips, which show the same kind names with payload-wide counts.
const graphCard = () =>
  screen.getByText("Entity graph — click any node").closest("section");

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

    // dns is dashed, auth/exec/runs use their own colours, flagged is critical red.
    expect(dashes).toContain("3 3");
    expect(strokes).toContain("#34d399"); // auth
    expect(strokes).toContain("#fbbf24"); // exec
    expect(strokes).toContain("#a78bfa"); // runs
    expect(strokes).toContain("#f87171"); // flagged
  });

  it("counts and labels each relationship kind in the legend", async () => {
    renderPage();
    await screen.findByText(/Relationship graph/i);
    const card = within(graphCard());
    for (const kind of ["comm", "dns", "auth", "exec", "runs", "flagged"]) {
      expect(card.getByText(new RegExp(`^${kind} `))).toBeTruthy();
    }
    // The small fixture lays out every node, so drawn counts are the totals.
    expect(card.getByText(/^auth 1$/)).toBeTruthy();
    expect(card.getByText(/^exec 1$/)).toBeTruthy();
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
    const card = within(graphCard());

    // auth/exec survive via the reserved slice; dns is recorded but not laid out.
    expect(card.getByText(/^auth 1$/)).toBeTruthy();
    expect(card.getByText(/^exec 1$/)).toBeTruthy();
    expect(card.getByText(/^dns 0 of 1$/)).toBeTruthy();
    // a kind that is drawn but only partly laid out says so too
    expect(card.getByText(/^comm [\d,]+ of 500$/)).toBeTruthy();
    // the domain node was trimmed, so its legend colour is not advertised
    expect(card.queryByText(/^domain /)).toBeNull();
    // ...but the filter chip still offers it
    expect(container.textContent).toContain("domain 1");
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

describe("GraphPage filters", () => {
  beforeEach(() => {
    api.getGraph.mockReset();
    api.getGraph.mockResolvedValue(graph());
    globalThis.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  });

  it("filters to a single relationship kind", async () => {
    const { container } = renderPage();
    await screen.findByText(/Relationship graph/i);
    const card = within(graphCard());

    // turn off everything except auth
    for (const kind of ["comm", "dns", "exec", "runs", "flagged"]) {
      fireEvent.click(screen.getByRole("button", { name: new RegExp(`^${kind} `) }));
    }

    const paths = Array.from(container.querySelectorAll("svg path")).filter((p) =>
      p.getAttribute("d")?.startsWith("M ")
    );
    expect(paths.length).toBe(1);
    expect(paths[0].getAttribute("stroke")).toBe("#34d399"); // auth
    expect(card.getByText(/^auth 1$/)).toBeTruthy();
  });

  it("keeps a filtered entity's relationships by adding dimmed context", async () => {
    const { container } = renderPage();
    await screen.findByText(/Relationship graph/i);
    const card = within(graphCard());

    // isolate the domain: its only edge points at an IP the filter removed
    for (const kind of ["ip", "user", "proc", "threat"]) {
      fireEvent.click(screen.getByRole("button", { name: new RegExp(`^${kind} `) }));
    }

    // the domain and the IP it resolved to are both on screen
    expect(card.getByText(/^domain 1$/)).toBeTruthy();
    expect(container.textContent).toContain("10.10.1.22");
    const dashed = Array.from(container.querySelectorAll("svg path")).filter(
      (p) => p.getAttribute("stroke-dasharray") === "3 3"
    );
    expect(dashed.length).toBe(1);
    // edges whose far endpoint the filter removed are not counted as drawn
    expect(card.getByText(/^comm 0 of 1$/)).toBeTruthy();
    // and the page says why the extra node is there
    expect(container.textContent).toMatch(/dimmed node.*context/i);
  });

  it("searches every node, including ones the layout trimmed", async () => {
    api.getGraph.mockResolvedValue({
      nodes: [
        ...Array.from({ length: 400 }, (_, i) => ({
          id: `10.0.0.${i}`,
          label: `10.0.0.${i}`,
          kind: "ip",
          severity: "none",
        })),
        { id: "user:deploy", label: "deploy", kind: "user", severity: "none" },
        { id: "proc:sshd", label: "sshd", kind: "proc", severity: "none" },
        { id: "10.0.0.7", label: "10.0.0.7", kind: "ip", severity: "none" },
        { id: "domain:evil.top", label: "evil.top", kind: "domain", severity: "none" },
      ],
      edges: [
        { source: "user:deploy", target: "10.0.0.7", kind: "auth", flows: 3, threat: 0 },
        { source: "user:deploy", target: "proc:sshd", kind: "exec", flows: 3, threat: 0 },
        { source: "domain:evil.top", target: "10.0.0.7", kind: "dns", flows: 1, threat: 0 },
      ],
      findings: {},
      client_id: "edge-fw-01",
    });

    const { container } = renderPage();
    await screen.findByText(/Relationship graph/i);

    fireEvent.change(screen.getByPlaceholderText(/search any node/i), {
      target: { value: "evil" },
    });
    // the hit appears in the dropdown, which is distinct from the node label
    // already painted in the svg
    const hit = await screen.findByRole("button", { name: /evil\.top/ });
    expect(hit).toBeTruthy();

    // picking the hit pins it into the layout and opens its detail
    fireEvent.click(hit);
    await waitFor(() => expect(screen.getByText(/Node — evil.top/)).toBeTruthy());
    expect(container.textContent).toContain("domain:evil.top");
    expect(screen.queryByText(/No node matches/)).toBeNull();
  });

  it("treats chips as checkboxes and restores the full set", async () => {
    const { container } = renderPage();
    await screen.findByText(/Relationship graph/i);
    const paths = () =>
      Array.from(container.querySelectorAll("svg path")).filter((p) =>
        p.getAttribute("d")?.startsWith("M ")
      ).length;

    const before = paths();
    expect(before).toBe(6);

    // one click turns exactly that kind off
    fireEvent.click(screen.getByRole("button", { name: /^comm / }));
    expect(paths()).toBe(5);
    // clicking it again brings it back and clears the filter
    fireEvent.click(screen.getByRole("button", { name: /^comm / }));
    expect(paths()).toBe(6);
  });

  it("adds only one-hop context, not the whole graph", async () => {
    // 300 mutually-connected ips; only ip0 is adjacent to a user. A sloppy
    // context expansion pulls every endpoint of every edge in and the filter
    // stops filtering anything.
    const nodes = Array.from({ length: 300 }, (_, i) => ({
      id: `ip${i}`,
      label: `ip${i}`,
      kind: "ip",
      severity: "none",
    }));
    const edges = [];
    for (let i = 1; i < 300; i++) edges.push({ source: `ip${i}`, target: `ip${i - 1}`, kind: "comm" });
    nodes.push({ id: "user:deploy", label: "deploy", kind: "user", severity: "none" });
    edges.push({ source: "user:deploy", target: "ip0", kind: "auth", flows: 3, threat: 0 });
    api.getGraph.mockResolvedValue({ nodes, edges, findings: {}, client_id: "edge-fw-01" });

    const { container } = renderPage();
    await screen.findByText(/Relationship graph/i);

    // this fixture has no proc/domain/threat nodes, so no such chips render
    fireEvent.click(screen.getByRole("button", { name: /^ip / }));

    expect(container.textContent).toMatch(/matching 2 nodes/);
    expect(container.textContent).toMatch(/1 dimmed node/);
    // and only that one auth edge is drawn
    const paths = Array.from(container.querySelectorAll("svg path")).filter((p) =>
      p.getAttribute("d")?.startsWith("M ")
    );
    expect(paths.length).toBe(1);
    expect(paths[0].getAttribute("stroke")).toBe("#34d399");
  });

  it("shows an empty state instead of a blank canvas when nothing is recorded", async () => {
    api.getGraph.mockResolvedValue({ nodes: [], edges: [], findings: {}, client_id: "x" });
    renderPage();
    expect(await screen.findByText(/No entities recorded yet/)).toBeTruthy();
  });

  it("clears every filter at once", async () => {
    renderPage();
    await screen.findByText(/Relationship graph/i);
    fireEvent.click(screen.getByRole("button", { name: /^comm / }));
    fireEvent.change(screen.getByPlaceholderText(/search any node/i), {
      target: { value: "deploy" },
    });
    const clear = screen.getByRole("button", { name: /clear all/i });
    fireEvent.click(clear);
    expect((screen.getByPlaceholderText(/search any node/i)).value).toBe("");
    expect(screen.queryByRole("button", { name: /clear all/i })).toBeNull();
  });
});
