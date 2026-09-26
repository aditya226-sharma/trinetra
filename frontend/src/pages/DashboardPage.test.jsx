import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { TaskRow, TaskPriority, ClientTasks, AdminTaskManage, NeedsReview, buildReviewQueue } from "./DashboardPage";
import * as api from "../lib/api";

vi.mock("../lib/api", () => ({
  getTasks: vi.fn(),
  createTask: vi.fn(),
  patchTask: vi.fn(),
  getDashboard: vi.fn(),
  getClients: vi.fn(),
  streamEvents: vi.fn(() => () => {}),
}));

const wrap = (node) => <MemoryRouter>{node}</MemoryRouter>;

describe("TaskPriority", () => {
  it("renders the priority label", () => {
    render(wrap(<TaskPriority priority="P1" />));
    expect(screen.getByText("P1")).toBeInTheDocument();
  });

  it("falls back to P3 tone for unknown priorities", () => {
    const { container } = render(wrap(<TaskPriority priority="P9" />));
    expect(container.querySelector("span").className).toContain("text-violet-300");
  });
});

describe("TaskRow", () => {
  const base = {
    id: "t1", title: "Patch the VPN cert", description: "rotate the gateway cert",
    priority: "P1", status: "todo", due_at: "2020-01-01T00:00:00Z", created_by: "admin",
  };

  it("shows the overdue badge for a past due_at task that is not done", () => {
    render(wrap(<TaskRow task={base} onPatch={() => {}} canPatch />));
    expect(screen.getByText("overdue")).toBeInTheDocument();
    expect(screen.getByText("2020-01-01 due")).toBeInTheDocument();
  });

  it("does not mark done tasks overdue even when due_at is past", () => {
    render(wrap(<TaskRow task={{ ...base, status: "done" }} onPatch={() => {}} canPatch />));
    expect(screen.queryByText("overdue")).not.toBeInTheDocument();
  });

  it("cycles status todo → in_progress on checkbox click", () => {
    const patch = vi.fn();
    render(wrap(<TaskRow task={base} onPatch={patch} canPatch />));
    fireEvent.click(screen.getByTitle("Mark in_progress"));
    expect(patch).toHaveBeenCalledWith("t1", { status: "in_progress" });
  });

  it("posts a note on Enter and clears the input", () => {
    const patch = vi.fn();
    render(wrap(<TaskRow task={base} onPatch={patch} canPatch />));
    const input = screen.getByPlaceholderText("add a note (enter to post)");
    fireEvent.change(input, { target: { value: "done under NDA window" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(patch).toHaveBeenCalledWith("t1", { note: "done under NDA window" });
    expect(input.value).toBe("");
  });

  it("hides patch controls when canPatch is false", () => {
    render(wrap(<TaskRow task={base} onPatch={() => {}} canPatch={false} />));
    expect(screen.queryByTitle("Mark in_progress")).not.toBeInTheDocument();
    expect(screen.queryByPlaceholderText("add a note (enter to post)")).not.toBeInTheDocument();
  });
});

describe("ClientTasks", () => {
  beforeEach(() => {
    vi.mocked(api.getTasks).mockResolvedValue({
      list: [
        { id: "a", title: "Active task", priority: "P2", status: "todo" },
        { id: "b", title: "Finished task", priority: "P3", status: "done" },
      ],
    });
    vi.mocked(api.patchTask).mockResolvedValue({ task: {} });
  });

  it("splits active and completed tasks, hiding completed under a <details>", async () => {
    render(wrap(<ClientTasks clientId="edge-fw-01" initial={{ total: 2 }} />));
    expect(await screen.findByText("Active task")).toBeInTheDocument();
    const summary = screen.getByText(/completed · 1/i);
    expect(summary).toBeInTheDocument();
  });

  it("re-fetches after a status patch", async () => {
    render(wrap(<ClientTasks clientId="edge-fw-01" initial={{ total: 2 }} />));
    await screen.findByText("Active task");
    fireEvent.click(screen.getByTitle("Mark in_progress"));
    await waitFor(() => expect(api.patchTask).toHaveBeenCalledWith("a", { status: "in_progress" }));
    await waitFor(() => expect(api.getTasks).toHaveBeenCalledTimes(2));
  });
});

describe("AdminTaskManage", () => {
  beforeEach(() => {
    vi.mocked(api.getTasks).mockResolvedValue({ list: [] });
    vi.mocked(api.createTask).mockResolvedValue({ task: {} });
    vi.mocked(api.patchTask).mockResolvedValue({ task: {} });
  });

  it("renders an empty state when no open tasks", async () => {
    render(wrap(<AdminTaskManage clients={[]} initial={{}} />));
    expect(await screen.findByText(/No open tasks/i)).toBeInTheDocument();
  });

  it("assigns a trimmed task payload on submit", async () => {
    render(wrap(<AdminTaskManage clients={[{ client_id: "edge-fw-01" }]} initial={{}} />));
    await screen.findByText(/No open tasks/i);
    fireEvent.change(screen.getByPlaceholderText(/Task title/i), {
      target: { value: "  Rotate root CAs  " },
    });
    fireEvent.change(screen.getByText("assign to…").closest("select"), {
      target: { value: "edge-fw-01" },
    });
    fireEvent.change(screen.getByText("P3").closest("select"), {
      target: { value: "P2" },
    });
    fireEvent.click(screen.getByText(/assign task/i));
    await waitFor(() =>
      expect(api.createTask).toHaveBeenCalledWith({
        title: "Rotate root CAs",
        description: "",
        priority: "P2",
        due_at: "",
        client_id: "edge-fw-01",
      })
    );
    expect(await screen.findByText(/✓ task assigned to edge-fw-01/i)).toBeInTheDocument();
  });
});
describe("buildReviewQueue", () => {
  it("ranks by severity before recency", () => {
    const rows = buildReviewQueue({
      findings: [
        { id: "f1", title: "info one", severity: "info", ts: "2026-02-01T00:00:00Z" },
        { id: "f2", title: "critical one", severity: "critical", ts: "2026-01-01T00:00:00Z" },
      ],
      incidents: [
        { id: "i1", title: "warning one", severity: "warning", ts: "2026-03-01T00:00:00Z" },
      ],
    });
    // The older critical outranks both newer, lower-severity rows.
    expect(rows.map((r) => r.title)).toEqual(["critical one", "warning one", "info one"]);
  });

  it("falls back to info for a missing severity so a row is never dropped", () => {
    const rows = buildReviewQueue({ findings: [{ id: "f1", title: "no severity" }], incidents: [] });
    expect(rows).toHaveLength(1);
    expect(rows[0].severity).toBe("info");
    expect(rows[0].title).toBe("no severity");
  });

  it("uses the source label when a row has no title", () => {
    const rows = buildReviewQueue({ findings: [], incidents: [{ id: "i9", severity: "high" }] });
    expect(rows[0].title).toBe("Incident I9");
    expect(rows[0].source).toBe("incident");
  });

  it("titles rows from threat_class, the field the dashboard actually returns", () => {
    // /api/dashboard findings carry threat_class and no title, so without this
    // fallback every real row rendered as "Untitled finding".
    const rows = buildReviewQueue({
      findings: [
        { threat_class: "port_scan", severity: "warning", client_id: "db-primary", timestamp: "2026-09-26T07:36:44Z" },
        { threat_class: "dga_dns", severity: "high", client_id: "app-srv-01", timestamp: "2026-09-26T07:37:11Z" },
      ],
      incidents: [],
    });
    expect(rows.map((r) => r.title)).toEqual(["Dga dns", "Port scan"]);
  });

  it("never renders an empty title", () => {
    const rows = buildReviewQueue({ findings: [{ severity: "info" }], incidents: [{ severity: "info" }] });
    rows.forEach((r) => expect(r.title.trim().length).toBeGreaterThan(0));
  });

  it("orders by recency within the same severity", () => {
    const rows = buildReviewQueue({
      findings: [
        { threat_class: "old_one", severity: "high", timestamp: "2026-01-01T00:00:00Z" },
        { threat_class: "new_one", severity: "high", timestamp: "2026-06-01T00:00:00Z" },
      ],
      incidents: [],
    });
    expect(rows.map((r) => r.title)).toEqual(["New one", "Old one"]);
  });

  it("caps the queue so the panel cannot grow without bound", () => {
    const findings = Array.from({ length: 40 }, (_, i) => ({
      id: `f${i}`,
      title: `finding ${i}`,
      severity: "info",
    }));
    expect(buildReviewQueue({ findings, incidents: [] })).toHaveLength(6);
  });

  it("returns an empty queue when there is nothing to review", () => {
    expect(buildReviewQueue({ findings: [], incidents: [] })).toEqual([]);
  });

  it("caps repeats of one threat class so the queue shows spread", () => {
    // A live estate is dominated by its noisiest detector; a plain top-6 was
    // six identical "dga_dns" rows.
    const findings = Array.from({ length: 9 }, (_, i) => ({
      id: `f${i}`,
      threat_class: "dga_dns",
      severity: "high",
      client_id: `c${i}`,
      timestamp: `2026-06-0${i + 1}T00:00:00Z`,
    }));
    const rows = buildReviewQueue({ findings, incidents: [] });
    expect(rows.filter((r) => r.title === "Dga dns")).toHaveLength(3);
  });

  it("still fills the panel from other classes when one class dominates", () => {
    const incidents = [
      ...Array.from({ length: 20 }, (_, i) => ({
        id: `i${i}`,
        threat_class: "port_scan",
        severity: "high",
        client_id: `c${i}`,
        timestamp: `2026-06-01T00:00:${String(i).padStart(2, "0")}Z`,
      })),
      ...["dns_tunnel", "c2_beacon", "brute_force", "exfil", "lateral"].map((t, i) => ({
        id: `x${i}`,
        threat_class: t,
        severity: "high",
        client_id: `c${i}`,
        timestamp: "2026-05-01T00:00:00Z",
      })),
    ];
    const rows = buildReviewQueue({ findings: [], incidents });
    expect(rows).toHaveLength(6);
    expect(rows.filter((r) => r.title === "Port scan")).toHaveLength(3);
  });

  it("returns fewer rows than the cap when the whole queue is one class", () => {
    // Honest outcome: three real rows beat six copies of the same finding.
    const incidents = Array.from({ length: 20 }, (_, i) => ({
      id: `i${i}`,
      threat_class: "port_scan",
      severity: "high",
      client_id: `c${i}`,
      timestamp: `2026-06-01T00:00:${String(i).padStart(2, "0")}Z`,
    }));
    expect(buildReviewQueue({ findings: [], incidents })).toHaveLength(3);
  });

  it("still puts criticals first when the cap defers a row", () => {
    const findings = [
      ...Array.from({ length: 3 }, (_, i) => ({
        id: `n${i}`,
        threat_class: "dga_dns",
        severity: "high",
        timestamp: "2026-06-01T00:00:00Z",
      })),
      { id: "c1", threat_class: "c2p_exfil", severity: "critical", timestamp: "2026-01-01T00:00:00Z" },
    ];
    const rows = buildReviewQueue({ findings, incidents: [] });
    // The older critical must stay first despite the newer high-severity rows.
    expect(rows[0].title).toBe("C2p exfil");
    expect(rows[0].severity).toBe("critical");
  });

  it("keeps the panel full when classes are already varied", () => {
    const findings = ["a", "b", "c", "d", "e", "f", "g"].map((t, i) => ({
      id: `f${i}`,
      threat_class: `class_${t}`,
      severity: "high",
      timestamp: "2026-06-01T00:00:00Z",
    }));
    expect(buildReviewQueue({ findings, incidents: [] })).toHaveLength(6);
  });
});

describe("NeedsReview", () => {
  it("shows the clear state when the queue is empty", () => {
    render(wrap(<NeedsReview rows={[]} />));
    expect(screen.getByText("Queue is clear")).toBeInTheDocument();
  });

  it("lists rows with a severity pill and links into triage", () => {
    render(
      wrap(
        <NeedsReview
          rows={buildReviewQueue({
            findings: [{ id: "f1", title: "beacon to C2", severity: "critical", client_id: "acme" }],
            incidents: [],
          })}
        />
      )
    );
    expect(screen.getByText("Needs Review")).toBeInTheDocument();
    expect(screen.getByText("beacon to C2")).toBeInTheDocument();
    expect(screen.getByText("acme")).toBeInTheDocument();
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.getByText("1 high priority")).toBeInTheDocument();
    // Findings route to the graph, incidents to the alert queue.
    expect(screen.getByRole("link").getAttribute("href")).toBe("/graph");
  });
});
