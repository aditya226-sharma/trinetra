import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import React, { useState } from "react";
import { usePagedList, ShowMoreBar } from "./ShowMore";

function Probe({ items, step = 100 }) {
  const p = usePagedList(items, step);
  return (
    <div>
      <span data-testid="count">{p.shown.length}</span>
      <span data-testid="remaining">{p.remaining}</span>
      <ShowMoreBar
        remaining={p.remaining}
        total={p.total}
        shownCount={p.shown.length}
        onMore={p.showMore}
        onAll={p.showAll}
        noun="assets"
      />
    </div>
  );
}

const items = (n) => Array.from({ length: n }, (_, i) => ({ id: `n${i}` }));

describe("usePagedList", () => {
  // The asset/case lists grow with live traffic; rendering all of them cost
  // ~9,600 DOM nodes and blocked the main thread for seconds on load.
  it("caps the initial render", () => {
    render(<Probe items={items(1001)} />);
    expect(screen.getByTestId("count").textContent).toBe("100");
    expect(screen.getByTestId("remaining").textContent).toBe("901");
  });

  it("grows a page on demand and keeps every item reachable", () => {
    render(<Probe items={items(250)} />);
    expect(screen.getByTestId("count").textContent).toBe("100");
    fireEvent.click(screen.getByText("Show more"));
    expect(screen.getByTestId("count").textContent).toBe("200");
    fireEvent.click(screen.getByText("Show more"));
    expect(screen.getByTestId("count").textContent).toBe("250");
  });

  it("can show everything at once", () => {
    render(<Probe items={items(1001)} />);
    fireEvent.click(screen.getByText(/Show all 1001/));
    expect(screen.getByTestId("count").textContent).toBe("1001");
    expect(screen.getByTestId("remaining").textContent).toBe("0");
  });

  it("reports fully-rendered lists instead of offering a dead button", () => {
    render(<Probe items={items(12)} step={100} />);
    expect(screen.getByText(/Showing all 12 assets/)).toBeTruthy();
    expect(screen.queryByText("Show more")).toBeNull();
  });

  it("handles an empty list", () => {
    render(<Probe items={[]} />);
    expect(screen.getByTestId("count").textContent).toBe("0");
    expect(screen.getByText(/Showing all 0 assets/)).toBeTruthy();
  });
});
