import React, { useEffect, useState } from "react";
import { Link, NavLink, Route, Routes, useNavigate, useLocation } from "react-router-dom";
import { bootstrapDemo, getHealth } from "./lib/api";
import DashboardPage from "./pages/DashboardPage";
import EventsPage from "./pages/EventsPage";
import AlertsPage from "./pages/AlertsPage";
import GraphPage from "./pages/GraphPage";
import AssetsPage from "./pages/AssetsPage";
import CompliancePage from "./pages/CompliancePage";
import IngestPage from "./pages/IngestPage";

const ICONS = {
  Dashboard: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
      <rect x="3" y="3" width="8" height="8" rx="2" />
      <rect x="13" y="3" width="8" height="5" rx="2" />
      <rect x="13" y="10" width="8" height="11" rx="2" />
      <rect x="3" y="13" width="8" height="8" rx="2" />
    </svg>
  ),
  Events: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
      <path d="M4 6h16M4 12h10M4 18h6" />
      <path d="M17 14l3 3-3 3M17 14v6" strokeWidth="1.6" />
    </svg>
  ),
  Alerts: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" />
      <path d="M12 9v4M12 17h.01" />
    </svg>
  ),
  Graph: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="6" cy="6" r="2.6" />
      <circle cx="18" cy="8" r="2.6" />
      <circle cx="10" cy="18" r="2.6" />
      <path d="M8.3 7.1l7.3.6M7 8.4l1.7 8M15.8 9.8l-4.6 6.4" strokeWidth="1.4" />
    </svg>
  ),
  Assets: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
      <path d="M4 17l6-6 4 4 6-7" />
      <path d="M14 8h6v6" />
    </svg>
  ),
  Compliance: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  ),
  Ingest: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
      <path d="M4 5h16M4 12h16M4 19h10" />
      <path d="M17 15v6M17 15l-2 2M17 15l2 2" strokeWidth="1.6" />
    </svg>
  ),
};

const navItems = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/events", label: "Events" },
  { to: "/alerts", label: "Alerts" },
  { to: "/graph", label: "Graph" },
  { to: "/assets", label: "Assets" },
  { to: "/compliance", label: "Compliance" },
  { to: "/ingest", label: "Ingest" },
];

const TITLES = {
  "/": "Security overview",
  "/events": "Event triage",
  "/alerts": "Alert fan-out",
  "/graph": "Entity graph",
  "/assets": "Asset registry",
  "/compliance": "Compliance briefs",
  "/ingest": "Live ingest",
};

export default function App() {
  const [ready, setReady] = useState(null);
  const [apiOffline, setApiOffline] = useState(false);
  const [loading, setLoading] = useState(false);
  const [clock, setClock] = useState(new Date());
  const [health, setHealth] = useState(null);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const int = setInterval(() => setClock(new Date()), 1000);
    getHealth()
      .then((h) => {
        setReady(h.demo_ready === true);
        setHealth(h);
      })
      .catch(() => {
        setReady(false);
        setApiOffline(true);
      });
    return () => clearInterval(int);
  }, []);

  const handleBootstrap = async () => {
    setLoading(true);
    try {
      await bootstrapDemo(true);
      setReady(true);
      navigate("/");
    } catch (err) {
      alert("Bootstrap failed: " + (err?.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  if (ready === null) {
    return (
      <div className="grid h-full place-items-center">
        <div className="text-center">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-2 border-emerald-500/30 border-t-emerald-400" />
          <p className="mono text-xs tracking-widest text-slate-500">LINKING TO ULPP CORE…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="relative flex min-h-screen">
      <div className="bg-grid" aria-hidden />
      {/* ambient core glow behind content */}
      <div
        className="pointer-events-none fixed left-1/2 top-28 z-0 h-96 w-[60rem] -translate-x-1/2 rounded-full opacity-25"
        style={{ background: "radial-gradient(closest-side, rgba(52,211,153,0.18), transparent)" }}
        aria-hidden
      />

      {/* ------------------------------------------------------- nav rail */}
      <aside className="sticky top-0 z-20 flex h-screen w-60 shrink-0 flex-col border-r border-white/5 bg-[#070b15]/80 backdrop-blur-xl">
        {/* glow seat */}
        <div className="pointer-events-none absolute inset-x-0 top-0 h-32 bg-gradient-to-b from-emerald-500/[0.07] to-transparent" aria-hidden />

        <div className="relative px-5 pb-5 pt-6">
          <Link to="/" className="group flex items-center gap-3">
            <div className="relative grid h-10 w-10 place-items-center rounded-xl border border-emerald-500/40 bg-gradient-to-br from-emerald-500/30 to-cyan-500/10 shadow-[0_0_24px_-4px_rgba(52,211,153,0.7)]">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" className="text-emerald-300">
                <path d="M12 3a9 9 0 019 9v1l-2-1.5L20 15l-2-1.5V12" strokeWidth="1.5" fill="none" />
                <path d="M12 21a9 9 0 01-9-9v-1l2 1.5L4 9l2 1.5V12" strokeWidth="1.5" fill="none" />
                <circle cx="12" cy="12" r="2.2" />
              </svg>
            </div>
            <div>
              <p className="text-[17px] font-bold leading-none tracking-tight">
                Tri<span className="text-grad-emerald">Netra</span>
              </p>
              <p className="eyebrow mt-1">ULP Framework</p>
            </div>
          </Link>
        </div>

        <div className="px-1.5 pb-2 pt-1">
          <p className="eyebrow px-4 pb-2">Command</p>
          <nav className="space-y-0.5">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) => `rail-link ${isActive ? "active" : ""}`}
              >
                <span className="grid h-6 w-6 place-items-center opacity-80">{ICONS[item.label]}</span>
                {item.label}
                {item.label === "Alerts" && (
                  <span className="ml-auto h-1.5 w-1.5 rounded-full bg-rose-500 pulse-dot-red" />
                )}
              </NavLink>
            ))}
          </nav>
        </div>

        <div className="mt-auto space-y-3 px-4 pb-5">
          <div className="rounded-xl border border-white/5 bg-white/[0.03] p-3">
            {apiOffline ? (
              <div className="flex items-center gap-2.5">
                <span className="h-2 w-2 rounded-full bg-amber-400" />
                <div>
                  <p className="text-[11px] font-medium text-amber-300">STATIC PREVIEW</p>
                  <p className="text-[10px] text-slate-500">API not reachable from Pages</p>
                </div>
              </div>
            ) : ready ? (
              <div className="flex items-center gap-2.5">
                <span className="h-2 w-2 rounded-full bg-emerald-400 pulse-dot" />
                <div>
                  <p className="text-[11px] font-medium text-emerald-300">DATA LINK ESTABLISHED</p>
                  <p className="text-[10px] text-slate-500">demo corpus on-line</p>
                </div>
              </div>
            ) : (
              <button
                onClick={handleBootstrap}
                disabled={loading}
                className="btn-primary w-full text-center"
              >
                {loading ? "BOOTING…" : "RUN DEMO DATASET"}
              </button>
            )}
          </div>
          <div className="mono text-[10px] leading-relaxed tracking-wide text-slate-600">
            PS26156 · PS26145<br />PS26160 · PS26189
          </div>
        </div>
      </aside>

      {/* ------------------------------------------------------- main column */}
      <div className="relative z-10 flex min-w-0 flex-1 flex-col">
        {/* top bar */}
        <header className="sticky top-0 z-30 border-b border-white/5 bg-[#05080f]/70 px-7 py-3 backdrop-blur-xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <p className="eyebrow">/{TITLES[location.pathname]?.toLowerCase().replace(/ /g, "-") || "console"}</p>
            </div>
            <div className="flex items-center gap-5">
              <div className="hidden items-center gap-2 rounded-full border border-white/5 bg-white/[0.03] px-3 py-1.5 lg:flex">
                <span className={`h-2 w-2 rounded-full ${health?.analyzer?.healthy ? "bg-emerald-400 pulse-dot" : "bg-amber-400 pulse-dot-red"}`} />
                <span className="mono text-[10px] uppercase tracking-widest text-slate-400">
                  {health ? `analyzer · ${health?.analyzer?.configured_backend || "…"}` : "api · offline"}
                </span>
              </div>
              <div className="mono text-right">
                <p className="text-sm font-semibold tabular-nums tracking-widest text-slate-200">
                  {clock.toLocaleTimeString("en-GB", { hour12: false })}
                </p>
                <p className="text-[10px] uppercase tracking-widest text-slate-600">
                  {clock.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })}
                </p>
              </div>
            </div>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1500px] flex-1 px-7 pb-14 pt-7">
          {apiOffline && (
            <div className="mb-5 rounded-xl border border-amber-500/25 bg-amber-500/[0.07] px-4 py-3 text-[11px] leading-relaxed text-amber-200/90">
              <span className="mono font-semibold tracking-widest text-amber-300">STATIC PREVIEW</span>
              {" — the Python API lives in the container, so this page shows the UI shell. Run it live: "}
              <code className="mono text-amber-100">docker run -p 8000:8000 ghcr.io/aditya226-sharma/trinetra:latest</code>
            </div>
          )}
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/events" element={<EventsPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/graph" element={<GraphPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/compliance" element={<CompliancePage />} />
            <Route path="/ingest" element={<IngestPage />} />
          </Routes>
        </main>

        <footer className="border-t border-white/5 px-7 py-3">
          <div className="flex items-center justify-between text-[10px] uppercase tracking-widest text-slate-600">
            <span>TriNetra · Universal Log Pre-processing</span>
            <span className="mono">normalize → dedup → modules → analyze</span>
          </div>
        </footer>
      </div>
    </div>
  );
}