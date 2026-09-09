import React, { useEffect, useState } from "react";
import { Link, NavLink, Route, Routes, useNavigate } from "react-router-dom";
import { bootstrapDemo, getHealth } from "./lib/api";
import DashboardPage from "./pages/DashboardPage";
import EventsPage from "./pages/EventsPage";
import GraphPage from "./pages/GraphPage";
import AssetsPage from "./pages/AssetsPage";
import CompliancePage from "./pages/CompliancePage";

const navItems = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/events", label: "Events" },
  { to: "/graph", label: "Graph" },
  { to: "/assets", label: "Assets" },
  { to: "/compliance", label: "Compliance" },
];

export default function App() {
  const [ready, setReady] = useState(null); // null = checking
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    getHealth()
      .then((h) => setReady(h.demo_ready === true))
      .catch(() => setReady(false));
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
      <div className="grid h-full place-items-center text-slate-400">
        Checking TriNetra API…
      </div>
    );
  }

  return (
    <div className="flex min-h-screen">
      <aside className="w-60 shrink-0 border-r border-slate-800 bg-slate-900/60 p-4">
        <div className="mb-6">
          <h1 className="text-lg font-bold tracking-tight text-slate-50">
            Tri<span className="text-emerald-400">Netra</span>
          </h1>
          <p className="text-xs text-slate-500">Universal Log Pre-processing</p>
        </div>
        <nav className="space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `block rounded-lg px-3 py-2 text-sm ${
                  isActive
                    ? "bg-emerald-500/15 text-emerald-300"
                    : "text-slate-300 hover:bg-slate-800"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-8 border-t border-slate-800 pt-4">
          {ready ? (
            <div className="flex items-center gap-2 text-xs text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400" /> demo loaded
            </div>
          ) : (
            <button
              onClick={handleBootstrap}
              disabled={loading}
              className="w-full rounded-lg bg-emerald-500 px-3 py-2 text-sm font-semibold text-slate-950 disabled:opacity-60"
            >
              {loading ? "Running demo…" : "Run demo dataset"}
            </button>
          )}
        </div>
        <Link
          to="/"
          className="mt-4 block rounded-lg bg-slate-800 px-3 py-2 text-xs text-slate-300"
        >
          PS26156 · PS26145 · PS26160 · PS26189
        </Link>
      </aside>

      <main className="flex-1 overflow-y-auto p-6">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/graph" element={<GraphPage />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="/compliance" element={<CompliancePage />} />
        </Routes>
      </main>
    </div>
  );
}