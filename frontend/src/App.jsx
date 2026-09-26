import React, { useEffect, useState, useRef } from "react";
import { Link, NavLink, Navigate, Route, Routes, useNavigate, useLocation } from "react-router-dom";
import { bootstrapDemo, getHealth, getAlerts, getCaseStats, isPreview, authMe, logoutUser } from "./lib/api";
import { getToken, setToken } from "./lib/auth";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import IncidentPage from "./pages/IncidentPage";
import EventsPage from "./pages/EventsPage";
import AlertsPage from "./pages/AlertsPage";
import GraphPage from "./pages/GraphPage";
import AssetsPage from "./pages/AssetsPage";
import CompliancePage from "./pages/CompliancePage";
import AnalyticsPage from "./pages/AnalyticsPage";
import FleetPage from "./pages/FleetPage";
import ReportPage from "./pages/ReportPage";
import RulesPage from "./pages/RulesPage";
import WatchlistPage from "./pages/WatchlistPage";
import IngestPage from "./pages/IngestPage";
import ClientsPage from "./pages/ClientsPage";
import LogConsolePage from "./pages/LogConsolePage";
import OnboardingPage from "./pages/OnboardingPage";
import ConsolePage from "./pages/ConsolePage";
import SettingsPage from "./pages/SettingsPage";
import CommandPalette from "./components/CommandPalette";
import { SeverityDot } from "./components/ui";

function useLiveUrl() {
  const [liveUrl, setLiveUrl] = useState(null);
  useEffect(() => {
    fetch(`${import.meta.env.BASE_URL}live-url.txt`, { cache: "no-store" })
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error("no live-url.txt"))))
      .then((t) => {
        const m = t.trim().match(/^https?:\/\/[^\s]+\/?$/);
        const url = m ? new URL(m[0]) : null;
        if (url && url.host !== window.location.host) setLiveUrl(url.href.replace(/\/$/, ""));
      })
      .catch(() => setLiveUrl(null));
  }, []);
  return liveUrl;
}

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
  Rules: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 4h-4a2 2 0 00-2 2v14a2 2 0 002 2h8a2 2 0 002-2V8l-6-4z" />
      <path d="M14 4v4h4" />
      <path d="M9 14h6M9 17h4" />
    </svg>
  ),
  Watchlist: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3l2.4 4.9 5.4.8-3.9 3.8.9 5.4-4.8-2.6-4.8 2.6.9-5.4L4.2 8.7l5.4-.8L12 3z" />
    </svg>
  ),
  Ingest: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
      <path d="M4 5h16M4 12h16M4 19h10" />
      <path d="M17 15v6M17 15l-2 2M17 15l2 2" strokeWidth="1.6" />
    </svg>
  ),
  Clients: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="8" height="8" rx="1.5" />
      <rect x="14" y="3" width="8" height="8" rx="1.5" />
      <rect x="8" y="13" width="8" height="8" rx="1.5" />
      <circle cx="6" cy="7" r="1" />
      <circle cx="18" cy="7" r="1" />
      <circle cx="12" cy="17" r="1" />
    </svg>
  ),
  Logs: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
      <path d="M4 5h16M4 9h12M4 13h14M4 17h8" />
      <circle cx="19" cy="17" r="3" strokeWidth="1.4" />
      <path d="M17.5 15.5l1 1 1.5-1.5" strokeWidth="1.4" />
    </svg>
  ),
  Console: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 6l5 5-5 5M11 17h9" />
      <circle cx="19" cy="17" r="0" />
    </svg>
  ),
  Settings: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 00.34 1.87l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.7 1.7 0 00-1.87-.34 1.7 1.7 0 00-1 1.55V21a2 2 0 11-4 0v-.09a1.7 1.7 0 00-1.11-1.55 1.7 1.7 0 00-1.87.34l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.7 1.7 0 00.34-1.87 1.7 1.7 0 00-1.55-1H3a2 2 0 110-4h.09a1.7 1.7 0 001.55-1.11 1.7 1.7 0 00-.34-1.87l-.06-.06a2 2 0 112.83-2.83l.06.06a1.7 1.7 0 001.87.34H9a1.7 1.7 0 001-1.55V3a2 2 0 114 0v.09a1.7 1.7 0 001 1.55 1.7 1.7 0 001.87-.34l.06-.06a2 2 0 112.83 2.83l-.06.06a1.7 1.7 0 00-.34 1.87V9a1.7 1.7 0 001.55 1H21a2 2 0 110 4h-.09a1.7 1.7 0 00-1.51 1z" />
    </svg>
  ),
};

// Scoped client viewers are restricted to their portal dashboard + alerts;
// the SOC-internal estate views belong to admins and analysts only.
function SocRoute({ user, children }) {
  if (user && user.role !== "admin" && user.role !== "analyst" && user.client_scope) {
    return <Navigate to="/" replace />;
  }
  return children;
}

// Grouped into Overview / Investigate / Govern per the command-center spec.
// `label` doubles as the ICONS key, so labels must not change.
const navGroups = [
  {
    label: "Overview",
    items: [
      { to: "/", label: "Dashboard", end: true },
      { to: "/analytics", label: "Analytics" },
      { to: "/fleet", label: "Fleet" },
      { to: "/clients", label: "Clients" },
    ],
  },
  {
    label: "Investigate",
    items: [
      { to: "/alerts", label: "Alerts" },
      { to: "/events", label: "Events" },
      { to: "/graph", label: "Graph" },
      { to: "/assets", label: "Assets" },
      { to: "/watchlist", label: "Watchlist" },
    ],
  },
  {
    label: "Govern",
    items: [
      { to: "/rules", label: "Rules" },
      { to: "/compliance", label: "Compliance" },
      { to: "/ingest", label: "Ingest" },
      { to: "/settings", label: "Settings" },
    ],
  },
];

// Scoped client viewers are read-only to one client: they may see their portal
// dashboard and the alert queue, but not the SOC-internal estate views
// (cross-client by design).
function navItemVisible(item, user) {
  if (!user) return true;
  if (item.to === "/settings" || item.to === "/ingest") return user.role === "admin";
  if (user.role !== "admin" && user.role !== "analyst" && user.client_scope) {
    return item.to === "/" || item.to === "/alerts";
  }
  return true;
}

export { navGroups, navItemVisible };

const TITLES = {
  "/": "Security overview",
  "/clients": "Client fleet",
  "/clients/onboard": "Onboarding",
  "/events": "Event triage",
  "/alerts": "Alert queue",
  "/rules": "Rules editor",
  "/watchlist": "Watchlist · blocklist",
  "/graph": "Entity graph",
  "/assets": "Asset registry",
  "/compliance": "Compliance briefs",
  "/analytics": "Performance analytics",
  "/fleet": "Fleet operations",
  "/ingest": "Live ingest",
  "/console": "Live console",
  "/settings": "Settings & admin",
};

export default function App() {
  const [ready, setReady] = useState(null);
  const [apiOffline, setApiOffline] = useState(false);
  const [loading, setLoading] = useState(false);
  const [clock, setClock] = useState(new Date());
  const [health, setHealth] = useState(null);
  const [authState, setAuthState] = useState(isPreview ? "authed" : "checking");
  const [user, setUser] = useState(null);
  const [theme, setTheme] = useState(() => (typeof window !== "undefined" ? localStorage.getItem("trinetra_theme") || "dark" : "dark"));
  const [bell, setBell] = useState({ alerts: [], open: false });
  const [openCaseCount, setOpenCaseCount] = useState(0);
  const liveUrl = useLiveUrl();
  const navigate = useNavigate();
  const location = useLocation();

  // Header alert bell — latest alerts, refreshed on a slow poll (a live
  // "unread" badge lands with the alert lifecycle feature). Only run once a
  // session exists so the pre-login mount can't fire unauthenticated 401s.
  useEffect(() => {
    if (authState !== "authed") return;
    let alive = true;
    const poll = () =>
      getAlerts(12)
        .then((d) => { if (alive) setBell((b) => ({ ...b, alerts: d.alerts || [] })); })
        .catch(() => {});
    poll();
    const t = setInterval(poll, 30000);
    return () => { alive = false; clearInterval(t); };
  }, [authState]);

  // Open-case badge on the Alerts rail item — quick heartbeat so the queue
  // count stays honest without opening the page.
  useEffect(() => {
    if (authState !== "authed") return;
    let alive = true;
    const poll = () => {
      if (document.hidden) return;
      getCaseStats()
        .then((s) => {
          if (!alive) return;
          setOpenCaseCount((s?.by_status?.open || 0) + (s?.by_status?.acknowledged || 0));
        })
        .catch(() => {});
    };
    poll();
    const t = setInterval(poll, 15000);
    return () => { alive = false; clearInterval(t); };
  }, [authState]);

  useEffect(() => {
    if (!bell.open) return;
    const close = () => setBell((b) => ({ ...b, open: false }));
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, [bell.open]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try { localStorage.setItem("trinetra_theme", theme); } catch (e) {}
  }, [theme]);

  // -------- session -----------------------------------------------------
  useEffect(() => {
    if (isPreview) {
      setUser({ username: "preview", role: "viewer" });
      setAuthState("authed");
      return;
    }
    if (getToken()) {
      authMe()
        .then((u) => { setUser(u); setAuthState("authed"); })
        .catch(() => { setToken(null); setAuthState("guest"); });
    } else {
      setAuthState("guest");
    }
  }, []);

  useEffect(() => {
    const onUnauthorized = () => {
      setToken(null);
      setAuthState("guest");
      navigate("/login");
    };
    window.addEventListener("trinetra:unauthorized", onUnauthorized);
    return () => window.removeEventListener("trinetra:unauthorized", onUnauthorized);
  }, [navigate]);

  const signOut = () => {
    logoutUser();
    setAuthState("guest");
    navigate("/login");
  };

  useEffect(() => {
    const clock = setInterval(() => setClock(new Date()), 1000);
    const check = () => {
      getHealth()
        .then((h) => {
          setReady(h.demo_ready === true);
          setHealth(h);
          setApiOffline(false);
        })
        .catch(() => {
          setReady(false);
          setApiOffline(true);
        });
    };
    check();
    const healthInt = setInterval(check, 30000);
    return () => {
      clearInterval(clock);
      clearInterval(healthInt);
    };
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

  if (authState === "checking") {
    return (
      <div className="grid h-full place-items-center">
        <div className="text-center">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-2 border-violet-600/30 border-t-emerald-400" />
          <p className="mono text-xs tracking-widest text-violet-300">VERIFYING SESSION…</p>
        </div>
      </div>
    );
  }

  if (authState === "guest" && !isPreview) {
    return <LoginPage onSuccess={(u) => { setUser(u); setAuthState("authed"); navigate("/"); }} />;
  }

  if (ready === null) {
    return (
      <div className="grid h-full place-items-center">
        <div className="text-center">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-2 border-violet-600/30 border-t-emerald-400" />
          <p className="mono text-xs tracking-widest text-violet-300">LINKING TO ULPP CORE…</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`relative flex min-h-screen ${location.pathname.startsWith("/report") ? "report-mode" : ""}`}>
      <CommandPalette theme={theme} setTheme={setTheme} role={user?.role} />
      {liveUrl && (
        <a
          href={liveUrl}
          target="_blank"
          rel="noreferrer"
          title={`Open the live TriNetra instance (${liveUrl})`}
          className="sticky top-0 z-40 flex items-center justify-center gap-2 border-b border-violet-600/20 bg-violet-600/10 px-3 py-1.5 text-center backdrop-blur-xl"
        >
          <span className="h-1.5 w-1.5 rounded-full bg-violet-500 pulse-dot-calm" />
          <span className="mono text-[10px] uppercase tracking-widest text-violet-300">
            live instance · {liveUrl.replace(/^https?:\/\//, "").replace(/\/$/, "")}
          </span>
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" className="text-violet-500">
            <path d="M7 17L17 7M9 7h8v8" />
          </svg>
        </a>
      )}
      <div className="bg-grid" aria-hidden />
      {/* ambient core glow behind content */}
      <div
        className="pointer-events-none fixed left-1/2 top-28 z-0 h-96 w-[60rem] -translate-x-1/2 rounded-full opacity-25"
        style={{ background: "radial-gradient(closest-side, rgba(167, 139, 196,0.18), transparent)" }}
        aria-hidden
      />

      {/* ------------------------------------------------------- nav rail */}
      <aside className="sticky top-0 z-20 flex h-screen w-60 shrink-0 flex-col border-r border-white/5 bg-[#070b15]/80 backdrop-blur-xl">
        {/* glow seat */}
        <div className="pointer-events-none absolute inset-x-0 top-0 h-32 bg-gradient-to-b from-violet-600/[0.07] to-transparent" aria-hidden />

        <div className="relative px-5 pb-5 pt-6">
          <Link to="/" className="group flex items-center gap-3">
            <div className="relative h-10 w-10 overflow-hidden rounded-xl border border-violet-600/40 bg-[#120a21] shadow-[0_0_24px_-4px_rgba(167, 139, 196,0.7)]">
              <img src={`${import.meta.env.BASE_URL}logo.png`} alt="TriNetra" className="h-full w-full object-cover" />
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
            {navGroups.map((group) => {
              const items = group.items.filter((item) => navItemVisible(item, user));
              // Drop the caption entirely when a role can see nothing in it.
              if (items.length === 0) return null;
              return (
                <div key={group.label} className="pb-1">
                  <p className="rail-group">{group.label}</p>
                  {items.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={item.end}
                      className={({ isActive }) => `rail-link ${isActive ? "active" : ""}`}
                    >
                      <span className="grid h-6 w-6 place-items-center opacity-80">{ICONS[item.label]}</span>
                      {item.label}
                      {item.label === "Alerts" && openCaseCount > 0 && (
                        <span className={`ml-auto grid h-4 min-w-4 place-items-center rounded-full bg-[#ec4899] px-1 text-[9px] font-bold text-[#0a0612] ${openCaseCount > 0 ? "pulse-dot-red" : ""}`}>
                          {openCaseCount > 99 ? "99+" : openCaseCount}
                        </span>
                      )}
                    </NavLink>
                  ))}
                </div>
              );
            })}
          </nav>
        </div>

        <div className="mt-auto space-y-3 px-4 pb-5">
          <div className="rounded-xl border border-white/5 bg-white/[0.03] p-3">
            {isPreview ? (
              <div className="flex items-center gap-2.5">
                <span className="h-2 w-2 rounded-full bg-purple-400" />
                <div>
                  <p className="text-[11px] font-medium text-purple-300">PREVIEW DATA</p>
                  <p className="text-[10px] text-violet-300">bundled demo dataset</p>
                </div>
              </div>
            ) : apiOffline ? (
              <div className="flex items-center gap-2.5">
                <span className="h-2 w-2 rounded-full bg-purple-400" />
                <div>
                  <p className="text-[11px] font-medium text-purple-300">STATIC PREVIEW</p>
                  <p className="text-[10px] text-violet-300">API not reachable from Pages</p>
                </div>
              </div>
            ) : ready ? (
              <div className="flex items-center gap-2.5">
                <span className="h-2 w-2 rounded-full bg-violet-500 pulse-dot-calm" />
                <div>
                  <p className="text-[11px] font-medium text-violet-300">DATA LINK ESTABLISHED</p>
                  <p className="text-[10px] text-violet-300">demo corpus on-line</p>
                </div>
              </div>
            ) : user?.role === "admin" ? (
              <button
                onClick={handleBootstrap}
                disabled={loading}
                className="btn-primary w-full text-center"
              >
                {loading ? "BOOTING…" : "RUN DEMO DATASET"}
              </button>
            ) : (
              <div>
                <p className="text-[11px] font-medium text-purple-300">AWAITING DATASET</p>
                <p className="text-[10px] text-violet-300">ask an admin to run the demo dataset</p>
              </div>
            )}
          </div>
          <div className="mono text-[10px] leading-relaxed tracking-wide text-violet-400">
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
              <p className="eyebrow">/{TITLES[location.pathname]
                  || (location.pathname.startsWith("/clients/") ? "log console" : null)
                  || "console"}</p>
            </div>
            <div className="flex items-center gap-5">
              <div className="relative">
                <button
                  onClick={(e) => { e.stopPropagation(); setBell((b) => ({ ...b, open: !b.open })); }}
                  title="Recent alerts"
                  className="relative grid h-9 w-9 place-items-center rounded-full border border-white/5 bg-white/[0.03] transition hover:border-violet-600/40"
                >
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="text-slate-300">
                    <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
                    <path d="M13.7 21a2 2 0 01-3.4 0" />
                  </svg>
                  {bell.alerts.length > 0 && (
                    <span className="absolute -right-1 -top-1 grid h-4 min-w-4 place-items-center rounded-full bg-pink-500 px-1 text-[9px] font-bold text-white">
                      {bell.alerts.length}
                    </span>
                  )}
                </button>
                {bell.open && (
                  <div className="glass absolute right-0 top-11 z-50 w-80 p-2 anim-fadeup">
                    <p className="eyebrow px-2 pb-2">Latest alerts</p>
                    {bell.alerts.length === 0 ? (
                      <p className="px-2 py-3 text-[12px] text-violet-300">No alerts yet.</p>
                    ) : (
                      <div className="max-h-80 space-y-1 overflow-y-auto">
                        {bell.alerts.map((a, i) => (
                          <button
                            key={a.alert_id || a.id || `${a.threat_class}_${a.timestamp || i}_${i}`}
                            onClick={() => { setBell((b) => ({ ...b, open: false })); navigate("/alerts"); }}
                            className="glass-row flex w-full items-center gap-2 p-2 text-left"
                          >
                            <SeverityDot severity={a.severity} />
                            <span className="mono min-w-0 flex-1 truncate text-[11px] text-slate-200">{a.threat_class}</span>
                            <span className="mono text-[10px] text-violet-300">{fmtClock(a.timestamp)}</span>
                          </button>
                        ))}
                      </div>
                    )}
                    <button
                      onClick={() => { setBell((b) => ({ ...b, open: false })); navigate("/alerts"); }}
                      className="btn-ghost mt-2 w-full text-center !py-1.5 text-[11px]"
                    >
                      open alert fan-out →
                    </button>
                  </div>
                )}
              </div>
              {!isPreview && (
                <>
                  <div className="hidden items-center gap-2.5 rounded-full border border-white/5 bg-white/[0.03] px-3 py-1.5 lg:flex">
                    <span className="grid h-5 w-5 place-items-center rounded-full bg-violet-600/20 text-[10px] font-bold text-violet-300">
                      {(user?.username || "?")[0]?.toUpperCase()}
                    </span>
                    <span className="mono text-[10px] uppercase tracking-widest text-violet-200">
                      {user?.username} · {user?.role}
                    </span>
                    {user?.client_scope && (
                      <span className="mono rounded border border-violet-500/30 bg-violet-500/10 px-1.5 py-0.5 text-[9px] uppercase tracking-widest text-violet-300">
                        {user.client_scope}
                      </span>
                    )}
                    <button
                      onClick={signOut}
                      className="mono text-[10px] uppercase tracking-widest text-violet-300 transition hover:text-pink-300"
                    >
                      sign out
                    </button>
                  </div>
                </>
              )}
              <div className="hidden items-center gap-2 rounded-full border border-white/5 bg-white/[0.03] px-3 py-1.5 lg:flex">
                <span className={`h-2 w-2 rounded-full ${health?.analyzer?.backend?.healthy ? "bg-violet-500 pulse-dot-calm" : "bg-purple-400 pulse-dot-red"}`} />
                <span className="mono text-[10px] uppercase tracking-widest text-violet-200">
                  {health ? `analyzer · ${health?.analyzer?.configured_backend || "…"}` : "api · offline"}
                </span>
              </div>
              <button
                  onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
                  title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
                  className="hidden items-center gap-2 rounded-full border border-white/5 bg-white/[0.03] px-3 py-1.5 transition hover:border-violet-600/40 lg:flex"
                >
                  {theme === "dark" ? (
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" className="text-purple-300">
                      <circle cx="12" cy="12" r="4.5" />
                      <path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M19.1 4.9l-1.8 1.8M6.7 17.3l-1.8 1.8" />
                    </svg>
                  ) : (
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="text-violet-300">
                      <path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z" />
                    </svg>
                  )}
                </button>
              <div className="mono text-right">
                <p className="text-sm font-semibold tabular-nums tracking-widest text-slate-200">
                  {clock.toLocaleTimeString("en-GB", { hour12: false })}
                </p>
                <p className="text-[10px] uppercase tracking-widest text-violet-400">
                  {clock.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })}
                </p>
              </div>
            </div>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1500px] flex-1 px-7 pb-14 pt-7">
          {apiOffline && (
            <div className="mb-5 rounded-xl border border-purple-500/25 bg-purple-500/[0.07] px-4 py-3 text-[11px] leading-relaxed text-purple-200/90">
              <span className="mono font-semibold tracking-widest text-purple-300">STATIC PREVIEW</span>
              {" — the Python API lives in the container, so this page shows the UI shell. Run it live: "}
              <code className="mono text-purple-100">docker run -p 8000:8000 ghcr.io/aditya226-sharma/trinetra:latest</code>
            </div>
          )}
          <Routes>
            <Route path="/clients" element={<SocRoute user={user}><ClientsPage /></SocRoute>} />
            <Route path="/clients/onboard" element={<SocRoute user={user}><OnboardingPage role={user?.role} /></SocRoute>} />
            <Route path="/clients/:id" element={<SocRoute user={user}><LogConsolePage /></SocRoute>} />
            <Route path="/" element={<DashboardPage role={user?.role} clientScope={user?.client_scope || ""} />} />
            <Route path="/incidents/:id" element={<IncidentPage role={user?.role} />} />
            <Route path="/events" element={<SocRoute user={user}><EventsPage /></SocRoute>} />
            <Route path="/alerts" element={<AlertsPage role={user?.role} />} />
            <Route path="/rules" element={<SocRoute user={user}><RulesPage role={user?.role} /></SocRoute>} />
            <Route path="/watchlist" element={<SocRoute user={user}><WatchlistPage role={user?.role} /></SocRoute>} />
            <Route path="/graph" element={<SocRoute user={user}><GraphPage /></SocRoute>} />
            <Route path="/assets" element={<SocRoute user={user}><AssetsPage /></SocRoute>} />
            <Route path="/compliance" element={<SocRoute user={user}><CompliancePage /></SocRoute>} />
            <Route path="/analytics" element={<SocRoute user={user}><AnalyticsPage /></SocRoute>} />
            <Route path="/fleet" element={<SocRoute user={user}><FleetPage role={user?.role} /></SocRoute>} />
            <Route path="/report/:assetId" element={<SocRoute user={user}><ReportPage /></SocRoute>} />
            <Route path="/ingest" element={user?.role === "admin" ? <IngestPage /> : <Navigate to="/" replace />} />
            <Route path="/console" element={<SocRoute user={user}><ConsolePage /></SocRoute>} />
            <Route path="/settings" element={user?.role === "admin" ? <SettingsPage role={user.role} /> : <Navigate to="/" replace />} />
            <Route path="/login" element={authState === "authed"
              ? <Navigate to="/" replace />
              : <LoginPage onSuccess={(u) => { setUser(u); setAuthState("authed"); navigate("/"); }} />} />
            <Route path="*" element={
              <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 px-6 text-center">
                <p className="mono text-3xl font-bold tracking-widest text-violet-500">404</p>
                <p className="mono text-[13px] uppercase tracking-widest text-violet-200">no such sector — this sector is off the map</p>
                <p className="max-w-md text-[12px] leading-relaxed text-violet-300">
                  The address you reached doesn't match any page in this console. Navigate back to the dashboard to keep scanning.
                </p>
                <Link to="/" className="btn-primary mono mt-2 !px-4 !py-2 text-[11px]">BACK TO DASHBOARD</Link>
              </div>
            } />
          </Routes>
        </main>

        <footer className="border-t border-white/5 px-7 py-3">
          <div className="flex items-center justify-between text-[10px] uppercase tracking-widest text-violet-400">
            <span>TriNetra · Universal Log Pre-processing</span>
            <span className="mono">normalize → dedup → modules → analyze</span>
          </div>
        </footer>
      </div>
    </div>
  );
}

function fmtClock(iso) {
  const ts = new Date(iso);
  if (Number.isNaN(ts.getTime())) return "";
  return ts.toLocaleTimeString("en-GB", { hour12: false, hour: "2-digit", minute: "2-digit" });
}