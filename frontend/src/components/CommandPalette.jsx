import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

// Global command palette — ⌘K / Ctrl-K. Jumps between pages and runs a few
// headless actions. Zero dependencies; rendered inside the app shell so it
// inherits the existing dark/light theming.
export default function CommandPalette({ theme, setTheme }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef(null);
  const navigate = useNavigate();

  const ACTIONS = useMemo(() => ({
    pages: [
      { label: "Clients", hint: "/clients", run: () => navigate("/clients") },
      { label: "Dashboard", hint: "/", run: () => navigate("/") },
      { label: "Events", hint: "/events", run: () => navigate("/events") },
      { label: "Alerts", hint: "/alerts", run: () => navigate("/alerts") },
      { label: "Graph", hint: "/graph", run: () => navigate("/graph") },
      { label: "Assets", hint: "/assets", run: () => navigate("/assets") },
      { label: "Compliance", hint: "/compliance", run: () => navigate("/compliance") },
      { label: "Ingest", hint: "/ingest", run: () => navigate("/ingest") },
      { label: "Live console", hint: "/console", run: () => navigate("/console") },
    ],
    quick: [
      {
        label: theme === "dark" ? "Switch to light theme" : "Switch to dark theme",
        hint: "⌥T",
        run: () => setTheme(theme === "dark" ? "light" : "dark"),
      },
      { label: "Export events as CSV", hint: "→ /events", run: () => navigate("/events") },
    ],
  }), [navigate, theme, setTheme]);

  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
        setQ("");
        setActiveIndex(0);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 20);
    else setQ("");
  }, [open]);

  const results = useMemo(() => {
    const term = q.trim().toLowerCase();
    const score = (s) => (term ? (s.label.toLowerCase().includes(term) ? 0 : s.hint.toLowerCase().includes(term) ? 1 : 4) : 0);
    const all = [...ACTIONS.quick, ...ACTIONS.pages];
    return all
      .map((a) => ({ ...a, _s: score(a) }))
      .filter((a) => a._s < 4)
      .sort((a, b) => a._s - b._s)
      .slice(0, 8);
  }, [q, ACTIONS]);

  const run = (a) => { a.run(); setOpen(false); setQ(""); };
  const onKeyDown = (e) => {
    if (e.key === "Escape") { setOpen(false); setQ(""); }
    if (e.key === "ArrowDown") { e.preventDefault(); setActiveIndex((i) => Math.min(i + 1, results.length - 1)); }
    if (e.key === "ArrowUp") { e.preventDefault(); setActiveIndex((i) => Math.max(i - 1, 0)); }
    if (e.key === "Enter" && results[activeIndex]) run(results[activeIndex]);
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center px-4 pt-[12vh]" onMouseDown={() => setOpen(false)}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" aria-hidden />
      <div
        onMouseDown={(e) => e.stopPropagation()}
        className="glass relative w-full max-w-lg overflow-hidden anim-fadeup"
        role="dialog"
        aria-modal="true"
      >
        <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
          <code className="mono text-[11px] text-emerald-300">⌘K</code>
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => { setQ(e.target.value); setActiveIndex(0); }}
            onKeyDown={onKeyDown}
            placeholder="jump to a page or run an action…"
            className="field mono w-full border-none bg-transparent py-1 px-1 focus:shadow-none"
          />
        </div>
        <div className="max-h-[46vh] overflow-y-auto p-2">
          {results.length === 0 ? (
            <p className="px-3 py-6 text-center text-[12px] text-slate-500">no matches — try “events”, “alerts” or “theme”</p>
          ) : (
            results.map((a, i) => (
              <button
                key={`${a.label}-${i}`}
                onClick={() => run(a)}
                onMouseEnter={() => setActiveIndex(i)}
                className={`flex w-full items-center justify-between gap-3 rounded-lg px-3 py-2.5 text-left text-[13px] transition ${
                  i === activeIndex ? "bg-emerald-500/15 text-emerald-200" : "text-slate-300 hover:bg-white/[0.04]"
                }`}
              >
                <span>{a.label}</span>
                <span className="mono text-[10px] uppercase tracking-widest text-slate-600">{a.hint}</span>
              </button>
            ))
          )}
        </div>
        <div className="flex items-center gap-3 border-t border-white/10 px-4 py-2 text-[10px] uppercase tracking-widest text-slate-600">
          <span>↑↓ navigate</span><span>↵ run</span><span>esc close</span>
        </div>
      </div>
    </div>
  );
}