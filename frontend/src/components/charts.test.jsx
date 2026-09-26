import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import React from "react";
import { Donut } from "./charts";

// The dashboard "Feed share" donut mixed reporting clients with registered but
// silent ones. A zero-value segment produced `strokeDasharray="-2 <c+2>"`, and a
// negative dasharray is invalid: the browser drops the property and paints the
// circle as an unbroken full ring. One silent sensor therefore covered every
// real arc and the chart read as a single flat colour.
describe("Donut", () => {
  const circ = 2 * Math.PI * ((160 - 16) / 2);

  it("never emits a negative or non-finite dasharray", () => {
    const { container } = render(
      <Donut
        segments={[
          { value: 100, color: "#a78bfa" },
          { value: 0, color: "#ec4899" },
          { value: 0, color: "#c4b5fd" },
          { value: 50, color: "#7c3aed" },
        ]}
      />
    );
    const dashes = [...container.querySelectorAll("circle[stroke-dasharray]")].map((c) =>
      parseFloat(c.getAttribute("stroke-dasharray").split(",")[0])
    );
    expect(dashes.length).toBe(2); // only the two segments with real share
    dashes.forEach((d) => {
      expect(Number.isFinite(d)).toBe(true);
      expect(d).toBeGreaterThan(0);
    });
  });

  it("drops zero-value segments instead of painting a full ring", () => {
    const { container } = render(
      <Donut segments={[{ value: 0, color: "#a78bfa" }, { value: 0, color: "#ec4899" }]} />
    );
    expect(container.querySelectorAll("circle[stroke-dasharray]").length).toBe(0);
  });

  it("keeps sub-inset segments from going negative", () => {
    // one dominant segment leaves the other far below the 2px inter-arc inset
    const { container } = render(
      <Donut
        segments={[
          { value: 10_000_000, color: "#a78bfa" },
          { value: 1, color: "#ec4899" },
        ]}
      />
    );
    const dashes = [...container.querySelectorAll("circle[stroke-dasharray]")].map((c) =>
      parseFloat(c.getAttribute("stroke-dasharray").split(",")[0])
    );
    expect(dashes.length).toBe(1);
    expect(dashes[0]).toBeGreaterThan(0);
  });

  it("segments still sum to the full circumference", () => {
    const segs = [
      { value: 40, color: "#a78bfa" },
      { value: 35, color: "#a855f7" },
      { value: 25, color: "#7c3aed" },
    ];
    const { container } = render(<Donut segments={segs} />);
    const circles = [...container.querySelectorAll("circle[stroke-dasharray]")];
    expect(circles.length).toBe(3);
    // first arc starts at 12 o'clock (offset == circumference)
    expect(parseFloat(circles[0].getAttribute("stroke-dashoffset"))).toBeCloseTo(circ, 3);
    // each arc is inset by 2px at its end, so the drawn total is the full
    // circumference minus one gap per segment (including the wrap-around)
    const drawn = circles.map((c) => {
      const [d] = c.getAttribute("stroke-dasharray").split(",");
      return parseFloat(d);
    });
    expect(drawn[0] + drawn[1] + drawn[2]).toBeCloseTo(circ - 2 * segs.length, 1);
  });

  it("renders the centre value it is given", () => {
    const { container } = render(
      <Donut segments={[{ value: 7, color: "#a78bfa" }]} centerValue={7} centerLabel="events" />
    );
    const texts = [...container.querySelectorAll("text")].map((t) => t.textContent);
    expect(texts).toContain("7");
    expect(texts.join(" ")).toContain("EVENTS");
  });
});
