import { describe, it, expect } from "vitest";
import { navGroups, navItemVisible } from "./App";

const ITEMS = navGroups.flatMap((g) => g.items);
const find = (to) => ITEMS.find((i) => i.to === to);
const admin = { role: "admin" };
const analyst = { role: "analyst" };
const scopedViewer = { role: "viewer", client_scope: "acme" };
const scopedAnalyst = { role: "analyst", client_scope: "acme" };

describe("sidebar grouping", () => {
  it("uses the three command-center sections in order", () => {
    expect(navGroups.map((g) => g.label)).toEqual(["Overview", "Investigate", "Govern"]);
  });

  it("keeps every route reachable in exactly one group", () => {
    const paths = ITEMS.map((i) => i.to);
    expect(new Set(paths).size).toBe(paths.length);
  });

  it("places the dashboard in Overview and triage views in Investigate", () => {
    expect(navGroups[0].items.map((i) => i.label)).toContain("Dashboard");
    expect(navGroups[1].items.map((i) => i.label)).toEqual(
      expect.arrayContaining(["Alerts", "Events", "Graph"]),
    );
  });

  it("puts admin-only routes in Govern", () => {
    expect(navGroups[2].items.map((i) => i.to)).toEqual(
      expect.arrayContaining(["/rules", "/compliance", "/ingest", "/settings"]),
    );
  });

  it("only marks the dashboard route as an exact match", () => {
    expect(ITEMS.filter((i) => i.end).map((i) => i.to)).toEqual(["/"]);
  });
});

describe("navItemVisible", () => {
  it("shows everything to an admin", () => {
    ITEMS.forEach((i) => expect(navItemVisible(i, admin)).toBe(true));
  });

  it("hides admin-only routes from analysts", () => {
    expect(navItemVisible(find("/settings"), analyst)).toBe(false);
    expect(navItemVisible(find("/ingest"), analyst)).toBe(false);
  });

  it("restricts a scoped client viewer to their dashboard and alerts", () => {
    expect(navItemVisible(find("/"), scopedViewer)).toBe(true);
    expect(navItemVisible(find("/alerts"), scopedViewer)).toBe(true);
    ITEMS.filter((i) => i.to !== "/" && i.to !== "/alerts").forEach((i) => {
      expect(navItemVisible(i, scopedViewer)).toBe(false);
    });
  });

  it("still lets a scoped analyst reach the full SOC estate", () => {
    expect(navItemVisible(find("/graph"), scopedAnalyst)).toBe(true);
    expect(navItemVisible(find("/clients"), scopedAnalyst)).toBe(true);
  });

  it("shows all routes when there is no user yet", () => {
    ITEMS.forEach((i) => expect(navItemVisible(i, null)).toBe(true));
  });

  it("never leaves a group with routes visible to a scoped viewer except Overview/Investigate", () => {
    // Guards the "dangling empty heading" regression: if Govern ever gains a
    // route a scoped viewer can see, this fails rather than rendering an
    // empty caption.
    const emptyGroups = navGroups
      .map((g) => ({ label: g.label, visible: g.items.filter((i) => navItemVisible(i, scopedViewer)) }))
      .filter((g) => g.visible.length === 0)
      .map((g) => g.label);
    expect(emptyGroups).toEqual(["Govern"]);
  });
});
