import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { TaskRow, TaskPriority, ClientTasks, AdminTaskManage } from "./DashboardPage";
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
    expect(container.querySelector("span").className).toContain("text-cyan-300");
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