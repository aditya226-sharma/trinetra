import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import {
  SeverityBadge,
  SeverityDot,
  severityHex,
  severityRank,
  normaliseSeverity,
} from "./ui";

describe("severity normalisation", () => {
  it("resolves mixed case to the same hue and rank as lowercase", () => {
    for (const v of ["Critical", "CRITICAL", "critical", " Critical "]) {
      expect(severityHex(v)).toBe("#f87171");
      expect(severityRank(v)).toBe(0);
    }
  });

  it("trims and lowercases", () => {
    expect(normaliseSeverity("  HIGH ")).toBe("high");
  });

  it("falls back to info for unknown or missing severities", () => {
    expect(severityHex("nonsense")).toBe("#38bdf8");
    expect(severityHex(undefined)).toBe("#38bdf8");
    expect(severityRank(null)).toBe(severityRank("info"));
  });

  it("orders critical ahead of high, warning and info", () => {
    expect(severityRank("critical")).toBeLessThan(severityRank("high"));
    expect(severityRank("high")).toBeLessThan(severityRank("warning"));
    expect(severityRank("warning")).toBeLessThan(severityRank("info"));
  });
});

describe("SeverityBadge", () => {
  it("keeps the critical hue for a mixed-case severity", () => {
    // Regression: the SEV lookup was case-sensitive, so "Critical" silently
    // fell back to info and painted a critical finding blue.
    const { container } = render(<SeverityBadge severity="Critical" />);
    const dot = container.querySelector("span span");
    expect(dot.className).toContain("f87171");
    expect(dot.className).not.toContain("38bdf8");
  });

  it("renders each severity on its own hue", () => {
    const cases = [
      ["critical", "f87171"],
      ["warning", "fbbf24"],
      ["info", "38bdf8"],
    ];
    for (const [sev, hex] of cases) {
      const { container } = render(<SeverityBadge severity={sev} />);
      expect(container.querySelector("span span").className).toContain(hex);
    }
  });

  it("falls back to the info hue for an unknown severity", () => {
    const { container } = render(<SeverityBadge severity="bogus" />);
    expect(container.querySelector("span span").className).toContain("38bdf8");
  });
});

describe("SeverityDot", () => {
  it("glows with the severity hue, not a fixed grey", () => {
    const { container } = render(<SeverityDot severity="Critical" />);
    const style = container.querySelector("span").getAttribute("style");
    expect(style).toContain("#f87171");
  });
});

describe("locked-in palette severity hues", () => {
  it("maps each severity to the exact hue from the palette spec", () => {
    // High and Error deliberately share #FB923C, per spec.
    const spec = {
      critical: "#f87171",
      high: "#fb923c",
      error: "#fb923c",
      warning: "#fbbf24",
      medium: "#fbbf24",
      info: "#38bdf8",
      low: "#34d399",
      success: "#34d399",
      resolved: "#34d399",
    };
    for (const [sev, hex] of Object.entries(spec)) {
      expect(severityHex(sev)).toBe(hex);
    }
  });

  it("gives every severity a chip fill so it reads as a block, not only as text", () => {
    for (const sev of ["critical", "high", "error", "warning", "medium", "info", "low", "success"]) {
      const { container } = render(<SeverityBadge severity={sev} />);
      expect(container.querySelector("span").className).toMatch(/sev-chip-/);
    }
  });

  it("keeps the strip and the chip on the same hue for one severity", () => {
    // A row whose strip says critical but whose dot says something else
    // reads as two different severities; the two must not drift.
    const { container } = render(<SeverityBadge severity="critical" />);
    const chip = container.querySelector("span").className;
    const dot = container.querySelector("span span").className;
    expect(chip).toContain("sev-chip-critical");
    expect(dot).toContain("f87171");
  });
});
