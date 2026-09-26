import React, { useState } from "react";

/**
 * Renders long, unbounded server-side lists without dumping thousands of DOM
 * nodes on first paint. The asset/case/control lists grow with live traffic, so
 * an uncapped map blocked the main thread for seconds on load.
 *
 * Shows `step` items initially and grows on demand, keeping every item
 * reachable while bounding the initial render cost.
 */
export function usePagedList(items, step = 100) {
  const [limit, setLimit] = useState(step);
  const shown = items.slice(0, limit);
  const remaining = Math.max(0, items.length - shown.length);
  const showMore = () => setLimit((n) => n + step);
  const showAll = () => setLimit(items.length);
  return { shown, remaining, showMore, showAll, total: items.length };
}

export function ShowMoreBar({ remaining, total, shownCount, onMore, onAll, noun = "items" }) {
  if (remaining <= 0) {
    return (
      <p className="mono mt-3 text-[11px] text-violet-300">
        Showing all {total} {noun}
      </p>
    );
  }
  return (
    <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-white/5 pt-3">
      <p className="mono text-[11px] text-violet-300">
        Showing {shownCount} of {total} {noun} · {remaining} more not rendered
      </p>
      <button
        onClick={onMore}
        className="rounded-lg border border-violet-500/30 px-3 py-1.5 text-[12px] text-violet-300 hover:border-violet-500/60"
      >
        Show more
      </button>
      <button
        onClick={onAll}
        className="rounded-lg border border-white/10 px-3 py-1.5 text-[12px] text-violet-200 hover:border-white/25 hover:text-slate-200"
      >
        Show all {total}
      </button>
    </div>
  );
}
