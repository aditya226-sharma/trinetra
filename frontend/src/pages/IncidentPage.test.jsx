import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import IncidentPage from "./IncidentPage";
import * as api from "../lib/api";

vi.mock("../lib/api", () => ({
  getIncidentDetail: vi.fn(),
  caseAction: vi.fn(),
  enrichEntity: vi.fn(),
}));

const renderPage = (role) =>
  render(
    <MemoryRouter initialEntries={["/incidents/case-123"]}>
      <Routes>
        <Route path="/incidents/:id" element={<IncidentPage role={role} />} />
      </Routes>
    </MemoryRouter>
  );

const detail = () => ({
  case: {
    id: "case-123",
    threat_class: "Malware beacon",
    severity: "high",
    status: "open",
    client_id: "edge-fw-01",
  },
  involved: [
    { kind: "ip", value: "185.220.101.4", label: "185.220.101.4", events: 3 },
  ],
  timeline: [],
  graph: { nodes: [], edges: [] },
  evidence: {},
});

describe("IncidentPage enrichment contract", () => {
  beforeEach(() => {
    vi.mocked(api.getIncidentDetail).mockResolvedValue(detail());
    vi.mocked(api.caseAction).mockResolvedValue({ case: { ...detail().case, status: "investigation" } });
  });

  it("renders the normalized intel verdict, confidence and source from the enricher", async () => {
    vi.mocked(api.enrichEntity).mockResolvedValue({
      geo: { country: "DE", city: "Frankfurt", asn: 51167 },
      intel: { source: "virustotal", verdict: "malicious", confidence: 72, malicious: 9 },
    });
    renderPage("analyst");
    expect(await screen.findByText("Malware beacon")).toBeInTheDocument();

    await waitFor(() => expect(api.enrichEntity).toHaveBeenCalledWith("ip", "185.220.101.4"));
    expect(await screen.findByText("malicious")).toBeInTheDocument();
    expect(screen.getByText(/conf 72/)).toBeInTheDocument();
    expect(screen.getByText(/via virustotal/)).toBeInTheDocument();
    expect(screen.getByText(/📍 DE · Frankfurt/)).toBeInTheDocument();
    expect(screen.getByText(/AS51167/)).toBeInTheDocument();
  });

  it("calls enrichEntity exactly once per involved IP (dedup via ref)", async () => {
    vi.mocked(api.enrichEntity).mockResolvedValue({ geo: {}, intel: {} });
    renderPage("analyst");
    await screen.findByText("Malware beacon");
    // Re-running the effect (e.g. data refresh) must not re-query the provider.
    await waitFor(() => expect(api.enrichEntity).toHaveBeenCalledTimes(1));
    vi.mocked(api.getIncidentDetail).mockResolvedValue(detail());
    render(<MemoryRouter initialEntries={["/incidents/case-999"]}>
      <Routes><Route path="/incidents/:id" element={<IncidentPage role="analyst" />} /></Routes>
    </MemoryRouter>);
    await screen.findByText("Malware beacon");
    await waitFor(() => expect(api.enrichEntity).toHaveBeenCalledTimes(2));
  });

  it("analysts can act on incidents (investigate / close / assign)", async () => {
    vi.mocked(api.enrichEntity).mockResolvedValue({ geo: {}, intel: {} });
    renderPage("analyst");
    await screen.findByText("Malware beacon");
    expect(screen.getByText("investigate")).toBeInTheDocument();
    expect(screen.getByText("close")).toBeInTheDocument();
    expect(screen.getByText("assign to soc")).toBeInTheDocument();
    fireEvent.click(screen.getByText("investigate"));
    await waitFor(() =>
      expect(api.caseAction).toHaveBeenCalledWith("case-123", { action: "investigate", note: "" })
    );
  });

  it("viewers get a read-only view with no action buttons", async () => {
    vi.mocked(api.enrichEntity).mockResolvedValue({ geo: {}, intel: {} });
    renderPage("viewer");
    await screen.findByText("Malware beacon");
    expect(screen.queryByText("investigate")).not.toBeInTheDocument();
    expect(screen.queryByText("close")).not.toBeInTheDocument();
    expect(screen.getByText(/read-only view/i)).toBeInTheDocument();
  });
});