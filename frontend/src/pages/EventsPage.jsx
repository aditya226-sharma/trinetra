import React, { useEffect, useRef, useState } from "react";
import { searchEvents, getClients, getEvent, streamEvents } from "../lib/api";
import { SeverityDot, SeverityBadge, PageHeader, LiveBadge, PlainBadge, CodeBlock, Empty } from "../components/ui";

const CATEGORIES = ["", "flow", "auth", "application", "network", "system", "vpn"];
// Live agent sources (my log-agent collectors) are shown alongside the demo ones.
const SOURCES = ["", "netflow", "syslog", "json", "cef", "csv", "windows",
                 "windows_event_log", "macos_unified_log", "macos_system_log", "file_log",
                 "live_flow", "live_vpn"];
const SEV = ["", "critical", "error", "warning", "info"];

const CAT_GLYPH = {
  flow: <DiamondGlyph />,
  auth: <KeyGlyph />,
  application: <AppGlyph />,
  network: <NetGlyph />,
  system: <SysGlyph />,
  vpn: <VpnGlyph />,
};

export default function EventsPage() {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const PAGE = 60;
  const [query, setQuery] = useState("");
  const [src, setSrc] = useState("");
  const [sev, setSev] = useState("");
  const [cat, setCat] = useState("");
  const [client, setClient] = useState("");
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(false);
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState(null);

  // Live tail via the SSE /api/events/stream endpoint.
  const [live, setLive] = useState(false);
  const [liveActive, setLiveActive] = useState(false);
  const [liveCount, setLiveCount] = useState(0);
  const closeStream = useRef(() => {});
  const eventsRef = useRef(events);
  eventsRef.current = events;
  // LIVE-tail matching must read the *current* filter values — the closure
  // created when LIVE is toggled would otherwise capture stale ones forever.
  const filtersRef = useRef({ query: "", src: "", sev: "", cat: "", client: "" });
  filtersRef.current = { query, src, sev, cat, client };

  const stopLive = () => {
    closeStream.current?.();
    closeStream.current = () => {};
    setLiveActive(false);
  };

  const toggleLive = () => {
    if (live) {
      stopLive();
      setLive(false);
      return;
    }
    setLive(true);
    closeStream.current = streamEvents({
      onEvent: (ev) => {
        setLiveCount((n) => n + 1);
        // Prepend only matching the active filters when live is on.
        const matches = runFiltersMatch(ev, filtersRef.current);
        if (matches) {
          // Cap the prepended tail so a long live session can't balloon the DOM.
          setEvents((list) => [ev, ...list.filter((e) => e.event_id !== ev.event_id)].slice(0, 200));
          setTotal((t) => t + 1);
        }
      },
      onError: () => setLiveActive(false),
    });
    setLiveActive(true);
  };

  useEffect(() => stopLive, []);

  useEffect(() => {
    getClients()
      .then((d) => setClients(d.clients || []))
      .catch(() => {});
  }, []);

  const run = async (keepDetail = false, reset = true) => {
    setLoading(true);
    const nextOffset = reset ? 0 : offset;
    try {
      const data = await searchEvents({
        query,
        source_type: src,
        severity: sev,
        category: cat,
        client_id: client,
        limit: PAGE,
        offset: nextOffset,
      });
      if (reset) {
        setEvents(data.events);
      } else {
        // Append the next page, dropping any rows already shown (the LIVE
        // tail may have prepended some of them in the meantime).
        setEvents((prev) => {
          const seen = new Set(prev.map((e) => e.event_id));
          return [...prev, ...data.events.filter((e) => !seen.has(e.event_id))];
        });
      }
      setTotal(data.total);
      setOffset(nextOffset + data.events.length);
      if (!keepDetail) setDetail(null);
      setError(null);
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    } finally {
      setLoading(false);
    }
  };

  const loadingRef = useRef(false);
  const loadMore = async () => {
    if (loadingRef.current) return;
    loadingRef.current = true;
    try { await run(true, false); } finally { loadingRef.current = false; }
  };
  const hasMore = offset < total;
  const sentinelRef = useRef(null);

  // Infinite scroll: fetch the next page as the sentinel nears the viewport.
  // IntersectionObserver is primary; a passive scroll/resize fallback catches
  // throttled or unavailable IO (background tabs, older engines). Iterate over
  // the full corpus — with no filter selected that's everything the backend
  // holds, newest first, page after page.
  useEffect(() => {
    const el = sentinelRef.current;
    if (!el) return;
    const near = () => el.getBoundingClientRect().top < window.innerHeight + 700;
    const check = () => { if (near() && hasMore && !loading) loadMore(); };
    let obs = null;
    if (typeof IntersectionObserver !== "undefined") {
      obs = new IntersectionObserver(
        (entries) => { if (entries[0].isIntersecting) check(); },
        { rootMargin: "700px" }
      );
      obs.observe(el);
    }
    window.addEventListener("scroll", check, { passive: true });
    window.addEventListener("resize", check, { passive: true });
    return () => {
      if (obs) obs.disconnect();
      window.removeEventListener("scroll", check);
      window.removeEventListener("resize", check);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasMore, loading, offset]);

  useEffect(() => {
    // Live filtering: refresh whenever the search/filter inputs change
    // (chips toggle above the table). Enter / SEARCH still run instantly.
    const t = setTimeout(() => run(true), 250);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, src, sev, cat, client]);

  const filtersActive = Boolean(query || src || sev || cat || client);

  async function openDetail(e) {
    setDetail(null);
    try {
      const full = await getEvent(e.event_id);
      setDetail({ ...e, ...full, raw: full.raw ?? e.raw_event ?? null });
    } catch {
      setDetail(e);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Forensics · Event store"
        title="Event triage"
        sub="Search the normalized corpus — free-text over IPs, process names, messages and trace-ids, narrowed by source, client and category. Toggle LIVE to watch new events from your agents as they land."
        actions={
          <div className="flex items-center gap-3">
            <LiveBadge text={`${total} matched`} />
            <button
              onClick={toggleLive}
              className={`chip ${live ? "chip-on" : ""}`}
              style={live ? { borderColor: "rgba(52,211,153,0.6)", color: "#6ee7b7" } : undefined}
            >
              <span className={`mr-1.5 inline-block h-1.5 w-1.5 rounded-full ${liveActive ? "bg-emerald-400 pulse-dot" : "bg-slate-500"}`} />
              {liveActive ? `LIVE · ${liveCount} new` : "LIVE TAIL"}
            </button>
          </div>
        }
      />

      {/* systems: every agent / client currently in the store */}
      {clients.length > 0 && (
        <div className="glass p-3">
          <p className="eyebrow px-1 pb-2">Systems reporting</p>
          <div className="flex flex-wrap gap-2">
            {clients.map((c) => (
              <button
                key={c.client_id}
                onClick={() => setClient(client === c.client_id ? "" : c.client_id)}
                className={`chip ${client === c.client_id ? "chip-on" : ""}`}
                title={`${c.source_type} · ${c.events} events`}
              >
                <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-emerald-400" />
                <span className="mono">{c.client_id}</span>
                <span className="ml-1.5 text-[10px] text-slate-500">
                  {c.last_seen ? fmtAgo(c.last_seen) : `${c.events} evt`}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* search console */}
      <div className="glass p-4 anim-fadeup">
        <div className="flex flex-wrap items-center gap-3">
          <label className="relative min-w-[260px] flex-1">
            <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">
              <SearchGlyph />
            </span>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && run()}
              placeholder="search 203.0.113.5 · sshd · 10.10.1.10:80 …"
              className="field mono w-full py-2.5 pl-10 pr-3"
            />
          </label>
          <button onClick={() => run()} className="btn-primary" disabled={loading}>
            {loading ? "SCANNING…" : "SEARCH"}
          </button>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-2">
          <span className="eyebrow mr-1">SOURCE</span>
          {SOURCES.map((s) => (
            <button key={s || "none"} onClick={() => setSrc(s)} className={`chip ${src === s ? "chip-on" : ""}`}>
              {s || "all"}
            </button>
          ))}
          <span className="eyebrow mx-1">SEV</span>
          {SEV.map((s) => (
            <button key={s || "x"} onClick={() => setSev(s)} className={`chip ${sev === s ? "chip-on" : ""}`}>
              {s || "all"}
            </button>
          ))}
          <span className="eyebrow mx-1">CATEGORY</span>
          {CATEGORIES.map((c) => (
            <button key={c || "y"} onClick={() => setCat(c)} className={`chip ${cat === c ? "chip-on" : ""}`}>
              {c || "all"}
            </button>
          ))}
          <span className="eyebrow mx-1">CLIENT</span>
          <select value={client} onChange={(e) => setClient(e.target.value)} className="field mono px-3 py-1.5 text-[11px]">
            <option value="">all clients</option>
            {clients.map((c) => (
              <option key={c.client_id} value={c.client_id}>{c.client_id}</option>
            ))}
          </select>
          {filtersActive && (
            <button
              onClick={() => { setQuery(""); setSrc(""); setSev(""); setCat(""); setClient(""); setTimeout(run, 0); }}
              className="ml-auto text-[11px] text-slate-500 hover:text-emerald-300"
            >
              reset filters ×
            </button>
          )}
        </div>
      </div>

      {error && <div className="text-sm text-rose-400">{error}</div>}

      {/* feed + detail */}
      <div className="flex gap-6">
        <div className="min-w-0 flex-1 space-y-2">
          <p className="eyebrow px-1">
            {filtersActive ? `${total} matches in filtered corpus` : `${total} events in store`}
          </p>
          {events.length === 0 ? (
            <Empty title="No events match" hint="Loosen a filter or ingest fresh lines on the Ingest page." />
          ) : (
            events.map((e, i) => (
              <button
                key={e.event_id}
                onClick={() => openDetail(e)}
                className="glass-row group flex w-full items-center gap-3 p-3 text-left feed-in"
                style={{ animationDelay: `${Math.min(i, 12) * 35}ms` }}
              >
                <span className={`sev-strip ${stripCls(e.severity)}`} />
                <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-white/5 bg-white/5 text-slate-400 transition group-hover:text-emerald-300">
                  {CAT_GLYPH[e.category] || <EventGlyph />}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="flex items-center gap-2 text-[12.5px] text-slate-100">
                    <span className="mono">{e.message}</span>
                  </p>
                  <p className="mono mt-0.5 text-[10px] uppercase tracking-widest text-slate-500">
                    {e.client_id} · {e.source_type} · {e.category}
                  </p>
                  {e.fields?.src_ip && (
                    <p className="mono mt-1 text-[11px] text-cyan-300/80">
                      {e.fields.src_ip} → {e.fields.dst_ip || "?"}
                      {e.fields.dport ? `:${e.fields.dport}` : ""}
                    </p>
                  )}
                </div>
                <div className="shrink-0 text-right">
                  <p className="mono text-[11px] text-slate-500">{e.timestamp}</p>
                  <SeverityBadge severity={e.severity} />
                </div>
              </button>
            ))
          )}
          {events.length > 0 && (
            <div className="flex items-center justify-between pt-2">
              <p className="mono text-[10px] uppercase tracking-widest text-slate-600">
                showing {events.length.toLocaleString()} of {total.toLocaleString()}
              </p>
              {hasMore && (
                <span ref={sentinelRef} className="mono text-[10px] uppercase tracking-widest text-emerald-300/70">
                  {loading ? "LOADING…" : "SCROLL FOR MORE…"}
                </span>
              )}
            </div>
          )}
        </div>

        {detail && (
          <aside className="slide-in w-[360px] shrink-0">
            <div className="glass p-5">
              <div className="mb-4 flex items-start justify-between gap-2">
                <div>
                  <p className="eyebrow">Event detail</p>
                  <p className="mt-1 mono text-[13px] text-slate-100">{detail.event_id}</p>
                </div>
                <button onClick={() => setDetail(null)} className="grid h-7 w-7 place-items-center rounded-lg border border-white/10 text-slate-400 hover:text-slate-100">
                  ×
                </button>
              </div>
              <dl className="space-y-2 text-[12px]">
                <Row k="client" v={detail.client_id} />
                <Row k="category" v={detail.category} />
                <Row k="source" v={detail.source_type} />
                <Row k="trace" v={detail.trace_id} mono />
                <Row k="severity" v={<SeverityBadge severity={detail.severity} />} />
                <Row k="message" v={detail.message} />
              </dl>
              <p className="eyebrow mb-1.5 mt-5">Parsed fields</p>
              <CodeBlock maxH="max-h-44">{JSON.stringify(detail.fields, null, 2)}</CodeBlock>
              {detail.raw && (
                <details className="mt-3">
                  <summary className="cursor-pointer text-[11px] text-slate-500 hover:text-slate-300">
                    original raw line ({detail.raw.length} bytes)
                  </summary>
                  <CodeBlock maxH="max-h-40">{detail.raw}</CodeBlock>
                </details>
              )}
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}

function Row({ k, v, mono }) {
  return (
    <div className="grid grid-cols-[84px_1fr] gap-2">
      <dt className="text-slate-500">{k}</dt>
      <dd className={`break-all text-slate-300 ${mono ? "mono text-[11px]" : ""}`}>{v || "—"}</dd>
    </div>
  );
}

const stripCls = (sev) => {
  const m = { critical: "sev-critical", high: "sev-high", medium: "sev-warning", warning: "sev-warning", error: "sev-error", info: "sev-info", low: "sev-info" };
  return m[sev] || "sev-info";
};

// Mirrors the backend /api/events/search matching so live SSE events respect
// the currently active filters.
function runFiltersMatch(ev, { query = "", src = "", sev = "", cat = "", client = "" } = {}) {
  if (query) {
    const q = query.toLowerCase();
    const hay = [
      ev.message || "",
      ev.client_ip || "",
      ev.trace_id || "",
      JSON.stringify(ev.fields || {}),
    ].join(" ").toLowerCase();
    if (!hay.includes(q)) return false;
  }
  if (src && ev.source_type !== src) return false;
  if (sev && ev.severity !== sev) return false;
  if (cat && ev.category !== cat) return false;
  if (client && ev.client_id !== client) return false;
  return true;
}

function fmtAgo(iso) {
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return "";
  const delta = Math.max(0, Math.round((Date.now() - then.getTime()) / 1000));
  if (delta < 60) return "just now";
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}

const S = { width: "13", height: "13", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "1.8", strokeLinecap: "round", strokeLinejoin: "round" };
/* function declarations are hoisted — CAT_GLYPH may reference them from module top-level */
function SearchGlyph() { return <svg {...S} width="15" height="15"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" /></svg>; }
function EventGlyph() { return <svg {...S}><circle cx="12" cy="12" r="8" /><path d="M12 8v5" /></svg>; }
function DiamondGlyph() { return <svg {...S}><path d="M12 3l6 9-6 9-6-9 6-9z" /></svg>; }
function KeyGlyph() { return <svg {...S}><circle cx="8" cy="14" r="4" /><path d="M11 11l8-8M15 7l3 3M17 5l2 2" /></svg>; }
function NetGlyph() { return <svg {...S}><circle cx="6" cy="6" r="3" /><circle cx="18" cy="6" r="3" /><circle cx="12" cy="18" r="3" /><path d="M8.5 7.8l2 1.5M12 12v3M15.5 7.8l-2 1.5" /></svg>; }
function AppGlyph() { return <svg {...S}><rect x="4" y="3" width="16" height="12" rx="2" /><path d="M9 19h6M12 15v4" /></svg>; }
function SysGlyph() { return <svg {...S}><rect x="3" y="4" width="18" height="8" rx="2" /><rect x="3" y="15" width="18" height="5" rx="2" /><path d="M6 8h.01M6 17h.01" /></svg>; }
function VpnGlyph() { return <svg {...S}><path d="M4 8h16M4 16h16M8 4v16M16 4v16" /></svg>; }