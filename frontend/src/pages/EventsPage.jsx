import React, { useEffect, useRef, useState } from "react";
import { searchEvents, getClients, getEvent, streamEvents, exportCsv, enrichEntity, getCases } from "../lib/api";
import { SeverityDot, SeverityBadge, PageHeader, LiveBadge, PlainBadge, CodeBlock, Empty } from "../components/ui";

const CATEGORIES = ["", "flow", "auth", "application", "network", "system", "vpn"];
// Live agent sources (my log-agent collectors) are shown alongside the demo ones.
const SOURCES = ["", "netflow", "syslog", "json", "cef", "csv", "windows",
                 "windows_event_log", "macos_unified_log", "macos_system_log", "file_log",
                 "live_flow", "live_vpn"];
const SEV = ["", "critical", "error", "warning", "info"];
const THREATS = ["", "port_scan", "ddos", "c2_beaconing", "dga", "exfiltration"];

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
  const searchSeq = useRef(0);
  const detailSeq = useRef(0);
  const [query, setQuery] = useState("");
  const [src, setSrc] = useState("");
  const [sev, setSev] = useState("");
  const [cat, setCat] = useState("");
  const [client, setClient] = useState("");
  const [threat, setThreat] = useState("");
  const [fromTs, setFromTs] = useState("");
  const [toTs, setToTs] = useState("");
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(false);
  const [detail, setDetail] = useState(null);
  const [detailMeta, setDetailMeta] = useState(null); // geo + related cases + detection context for the open event
  const [error, setError] = useState(null);

  // Saved searches (persisted per-browser via localStorage).
  const [saved, setSaved] = useState(() => {
    try { return JSON.parse(localStorage.getItem("trinetra_saved_searches") || "[]"); }
    catch { return []; }
  });
  const persistSaved = (next) => {
    setSaved(next);
    try { localStorage.setItem("trinetra_saved_searches", JSON.stringify(next)); } catch {}
  };
  const saveSearch = () => {
    const f = { query, src, sev, cat, client, threat, fromTs, toTs };
    const name = window.prompt("Name this saved search:", query ? `search · ${query}` : `filter · ${threat || cat || "all"}`);
    if (!name) return;
    const next = [...saved.filter((s) => s.name !== name), { name, f }];
    persistSaved(next);
  };
  const applySaved = (f) => {
    setQuery(f.query || ""); setSrc(f.src || ""); setSev(f.sev || ""); setCat(f.cat || "");
    setClient(f.client || ""); setThreat(f.threat || ""); setFromTs(f.fromTs || ""); setToTs(f.toTs || "");
  };
  const dropSaved = (name) => persistSaved(saved.filter((s) => s.name !== name));

  // Live tail via the SSE /api/events/stream endpoint.
  const [live, setLive] = useState(false);
  const [liveActive, setLiveActive] = useState(false);
  const [liveCount, setLiveCount] = useState(0);
  const closeStream = useRef(() => {});
  const eventsRef = useRef(events);
  eventsRef.current = events;
  // LIVE-tail matching must read the *current* filter values — the closure
  // created when LIVE is toggled would otherwise capture stale ones forever.
  const filtersRef = useRef({ query: "", src: "", sev: "", cat: "", client: "", threat: "", fromTs: "", toTs: "" });
  filtersRef.current = { query, src, sev, cat, client, threat, fromTs, toTs };

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
        if (!ev || !ev.event_id) return; // SOC task/case envelopes aren't raw rows
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
    const my = ++searchSeq.current;
    setLoading(true);
    const nextOffset = reset ? 0 : offset;
    try {
      const data = await searchEvents({
        query,
        source_type: src,
        severity: sev,
        category: cat,
        client_id: client,
        threat_class: threat,
        ts_from: normTs(fromTs),
        ts_to: normTs(toTs),
        limit: PAGE,
        offset: nextOffset,
      });
      if (my !== searchSeq.current) return;
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
      if (my !== searchSeq.current) return;
      setError(e.response?.data?.detail || e.message);
    } finally {
      if (my === searchSeq.current) setLoading(false);
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
  }, [query, src, sev, cat, client, threat, fromTs, toTs]);

  const filtersActive = Boolean(query || src || sev || cat || client || threat || fromTs || toTs);

  const doExportCsv = async () => {
    try {
      const blob = await exportCsv({
        query,
        source_type: src,
        severity: sev,
        category: cat,
        client_id: client,
        threat_class: threat,
        ts_from: normTs(fromTs),
        ts_to: normTs(toTs),
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `trinetra-events-${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    }
  };

  async function openDetail(e) {
    const my = ++detailSeq.current;
    setDetail(null);
    setDetailMeta(null);
    try {
      const full = await getEvent(e.event_id);
      if (my !== detailSeq.current) return;
      const derived = deriveDetection(full);
      setDetail({ ...e, ...full, raw: full.raw ?? e.raw_event ?? null, ...derived });
      const meta = await enrichDetail(full, e);
      if (my === detailSeq.current) setDetailMeta(meta);
    } catch {
      if (my === detailSeq.current) setDetail(e);
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
            <button onClick={doExportCsv} className="btn-ghost" title="Export all matching events to CSV">
              <span className="mr-1.5 inline-block align-[-1px]">↓</span>CSV
            </button>
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
          <span className="eyebrow mx-1">THREAT</span>
          {THREATS.map((t) => (
            <button key={t || "t-none"} onClick={() => setThreat(t)} className={`chip ${threat === t ? "chip-on" : ""}`}>
              {t || "all"}
            </button>
          ))}
          <span className="eyebrow mx-1">TIME</span>
          <input type="datetime-local" value={fromTs} onChange={(e) => setFromTs(e.target.value)}
            className="field mono px-3 py-1.5 text-[11px]" title="From (UTC)" />
          <span className="text-[10px] text-slate-600">→</span>
          <input type="datetime-local" value={toTs} onChange={(e) => setToTs(e.target.value)}
            className="field mono px-3 py-1.5 text-[11px]" title="To (UTC)" />
          <button onClick={saveSearch} className="btn-ghost !px-3 !py-1.5 text-[11px]" title="Save this filter for later">
            ⊕ save
          </button>
          {filtersActive && (
            <button
              onClick={() => { setQuery(""); setSrc(""); setSev(""); setCat(""); setClient(""); setThreat(""); setFromTs(""); setToTs(""); }}
              className="ml-auto text-[11px] text-slate-500 hover:text-emerald-300"
            >
              reset filters ×
            </button>
          )}
        </div>
      </div>

      {saved.length > 0 && (
        <div className="glass p-3">
          <p className="eyebrow px-1 pb-2">Saved searches</p>
          <div className="flex flex-wrap items-center gap-2">
            {saved.map((s) => (
              <span key={s.name} className="flex items-center gap-1.5 rounded-full border border-emerald-500/25 bg-emerald-500/[0.07] px-2.5 py-1">
                <button onClick={() => applySaved(s.f)} className="mono text-[11px] text-emerald-300 hover:text-emerald-200">
                  {s.name}
                </button>
                <button onClick={() => dropSaved(s.name)} className="text-[11px] text-slate-500 hover:text-rose-300" title="Delete saved search">×</button>
              </span>
            ))}
          </div>
        </div>
      )}

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
          <aside className="slide-in w-[460px] shrink-0">
            <div className="glass max-h-[calc(100vh-120px)] overflow-y-auto p-5">
              <div className="mb-4 flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="eyebrow">Event detail</p>
                  <div className="mt-1 flex flex-wrap items-center gap-2">
                    <p className="mono text-[13px] text-slate-100">{detail.event_id}</p>
                    <SeverityBadge severity={detail.severity} />
                  </div>
                </div>
                <button onClick={() => { setDetail(null); setDetailMeta(null); }} className="grid h-7 w-7 place-items-center rounded-lg border border-white/10 text-slate-400 hover:text-slate-100">
                  ×
                </button>
              </div>

              <dl className="space-y-2 text-[12px]">
                <Row k="timestamp" v={detail.timestamp} mono />
                <Row k="log id" v={detail.trace_id || detail.event_id} mono />
                <Row k="event type" v={detail.category} />
                <Row k="event id" v={findEventCode(detail)} mono />
                <Row k="client" v={detail.client_id} />
                <Row k="source" v={detail.source_type} />
                <Row k="message" v={detail.message} />
              </dl>

              <p className="eyebrow mb-1.5 mt-5">Network</p>
              <dl className="space-y-2 text-[12px]">
                <Row k="src ip" v={<span className="flex flex-wrap items-center gap-2">{f(detail, "src_ip") ? <><span className="mono text-[11px]">{f(detail, "src_ip")}</span>{geoChip(detailMeta, f(detail, "src_ip"))}</> : "—"}</span>} />
                <Row k="dst ip" v={<span className="flex flex-wrap items-center gap-2">{f(detail, "dst_ip") ? <><span className="mono text-[11px]">{f(detail, "dst_ip")}</span>{geoChip(detailMeta, f(detail, "dst_ip"))}</> : "—"}</span>} />
                <Row k="src port" v={f(detail, "sport")} mono />
                <Row k="dst port" v={f(detail, "dport")} mono />
                <Row k="protocol" v={f(detail, "proto")} mono />
                <Row k="action" v={f(detail, "action")} />
              </dl>

              <p className="eyebrow mb-1.5 mt-5">Identity & system</p>
              <dl className="space-y-2 text-[12px]">
                <Row k="username" v={f(detail, "username", "user", "attempted_user", "account_name")} mono />
                <Row k="hostname" v={f(detail, "hostname")} mono />
                <Row k="device type" v={deviceType(detail)} />
                <Row k="process / app" v={f(detail, "process", "process_name", "provider", "application", "app")} mono />
                <Row k="trace" v={detail.trace_id} mono />
              </dl>

              {(detail.modulesList?.length > 0 || detail.threat) && (
                <>
                  <p className="eyebrow mb-1.5 mt-5">Detection</p>
                  <dl className="space-y-2 text-[12px]">
                    <Row k="threat signature" v={detail.threat || "—"} />
                    <Row k="detection rule" v={detectionRule(detail, detailMeta)} />
                    <Row k="mitre att&ck" v={mitreIds(detail)} />
                    <Row k="risk score" v={<RiskMeter detail={detail} />} />
                    <Row k="confidence" v={confidenceOf(detail)} />
                    {detail.modulesList.length > 0 && <Row k="modules" v={detail.modulesList.join(", ")} mono />}
                  </dl>
                </>
              )}

              {detail.raw && (
                <details className="mt-3">
                  <summary className="cursor-pointer text-[11px] text-slate-500 hover:text-slate-300">
                    raw log ({detail.raw.length} bytes)
                  </summary>
                  <CodeBlock maxH="max-h-40">{detail.raw}</CodeBlock>
                </details>
              )}

              <p className="eyebrow mb-1.5 mt-4">Normalized data</p>
              <CodeBlock maxH="max-h-44">{JSON.stringify(detail.fields || {}, null, 2)}</CodeBlock>

              <p className="eyebrow mb-1.5 mt-4">Related events</p>
              <RelatedEvents detail={detail} onOpen={(id) => { const fetcher = { event_id: id }; openDetail(fetcher); }} />

              <p className="eyebrow mb-1.5 mt-4">Investigation</p>
              <InvestigationPanel detail={detail} meta={detailMeta} />

              {detail.trace_id && detail.trace_events && detail.trace_events.length > 0 && (
                <TraceTimeline events={detail.trace_events} current={detail.event_id} />
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
    <div className="grid grid-cols-[96px_1fr] gap-2">
      <dt className="text-slate-500">{k}</dt>
      <dd className={`break-all text-slate-300 ${mono ? "mono text-[11px]" : ""}`}>{v || "—"}</dd>
    </div>
  );
}

// -- forensic detail enrichment -------------------------------------------

// MITRE ATT&CK technique ids per threat class (mirrors backend compliance.py).
const MITRE_MAP = {
  port_scan: ["T1046", "T1046.001"],
  ddos: ["T1498"],
  c2_beaconing: ["T1071.001"],
  dga_dns: ["T1568.002"],
  data_exfiltration: ["T1048"],
  weak_ipsec_config: ["T1021.004", "T1552"],
  vpn_ok: [],
  exfiltration: ["T1048"],
};

const DEVICE_BY_SOURCE = {
  windows: "Windows host",
  windows_event_log: "Windows host",
  macos_unified_log: "macOS host",
  macos_system_log: "macOS host",
  syslog: "Linux / network device",
  netflow: "flow exporter",
  cef: "CEF appliance",
  csv: "CSV feed",
  json: "JSON feed",
  file_log: "file log",
  live_flow: "flow sensor",
  live_vpn: "VPN gateway",
};

// Which single field value to show for the requested attribute, preferring the
// normalized fields blob (any alias) before falling back to the event root.
function f(detail, ...keys) {
  const blob = detail?.fields || {};
  for (const k of keys) {
    const v = blob[k];
    if (v !== undefined && v !== null && v !== "") return v;
  }
  for (const k of keys) {
    const v = detail?.[k];
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return null;
}

// Windows events carry their own event code (e.g. 4624); otherwise the UES id.
function findEventCode(detail) {
  return f(detail, "event_id", "code", "record_id") ?? detail?.event_id ?? "—";
}

function deviceType(detail) {
  return f(detail, "device_type", "device") || DEVICE_BY_SOURCE[detail?.source_type] || detail?.source_type || "—";
}

function confidenceOf(detail) {
  const mf = detail?.module_findings || {};
  const first = firstFinding(detail);
  const conf = first?.confidence ?? mf?.confidence ?? detail?.fields?.confidence;
  return conf != null ? `${Math.round(Number(conf) * 100)}%` : "—";
}

function firstFinding(detail) {
  const mf = detail?.module_findings || {};
  for (const mod of Object.keys(mf)) {
    const val = mf[mod];
    if (Array.isArray(val)) {
      const hit = val.find((m) => m && typeof m === "object" && m.threat_class);
      if (hit) return hit;
      const hit2 = val.find((m) => m && typeof m === "object");
      if (hit2) return hit2;
    } else if (val && typeof val === "object" && val.threat_class) {
      return val;
    } else if (val && typeof val === "object") {
      return val;
    }
  }
  return null;
}

// Normalize module_findings into [threat_class, ...] + first finding object.
function deriveDetection(detail) {
  const mf = detail?.module_findings || {};
  const modulesList = Object.keys(mf).filter((mod) => {
    const v = mf[mod];
    return Array.isArray(v) ? v.length > 0 : Boolean(v);
  });
  let threat = firstFinding(detail)?.threat_class || null;
  if (!threat && detail?.fields?.threat_class) threat = detail.fields.threat_class;
  const confidence = confidenceOf(detail);
  return { modulesList, threat, confidence };
}

// SOC detection rule that produced this finding: prefer a matched case's
// rule_id/name, else the analyzer's rule label.
function detectionRule(detail, meta = {}) {
  const matched = meta?.relatedCases?.[0];
  if (matched?.rule_id) return matched.rule_id;
  if (matched?.source_kind === "flow") return "correlated flow detection";
  if (detail?.threat) return `${detail.threat} detector`;
  return "—";
}

function mitreIds(detail) {
  const t = detail?.threat;
  if (!t) return "—";
  if (MITRE_MAP[t]?.length) return MITRE_MAP[t].join(" · ");
  return "—";
}

function RiskMeter({ detail }) {
  const sevRank = {
    critical: 95, high: 80, error: 75, medium: 60, warning: 55, low: 30, info: 25,
  }[detail?.severity] ?? 25;
  const conf = firstFinding(detail)?.confidence;
  const score = Math.round(conf != null ? sevRank * 0.6 + Number(conf) * 100 * 0.4 : sevRank);
  const color = score >= 80 ? "from-rose-500 to-orange-500" : score >= 50 ? "from-amber-500 to-orange-400" : "from-emerald-500 to-cyan-500";
  return (
    <div className="flex items-center gap-2">
      <span className={`mono text-[11px] ${score >= 80 ? "text-rose-300" : score >= 50 ? "text-amber-300" : "text-emerald-300"}`}>{score}/100</span>
      <span className="h-1.5 w-20 overflow-hidden rounded-full bg-white/5">
        <span className={`bar-grow block h-full rounded-full bg-gradient-to-r ${color}`} style={{ width: `${score}%` }} />
      </span>
    </div>
  );
}

function geoChip(meta, ip) {
  if (!ip || !meta?.geo?.[ip]) return null;
  const g = meta.geo[ip];
  return (
    <span className="mono rounded border border-white/10 px-1.5 py-0.5 text-[9.5px] text-cyan-300/80" title={ip}>
      {[g.country, g.city].filter(Boolean).join(" · ") || (g.asn ? `AS${g.asn}` : "geo")}
    </span>
  );
}

function RelatedEvents({ detail, onOpen }) {
  const ids = new Set();
  (detail?.trace_events || []).forEach((ev) => ids.add(ev.event_id));
  const finding = firstFinding(detail);
  if (finding) {
    const mf = detail?.module_findings || {};
    for (const mod of Object.keys(mf)) {
      const val = mf[mod];
      const list = Array.isArray(val) ? val : val?.event_ids ? [val.event_ids] : [];
      list.forEach((item) => {
        const arr = Array.isArray(item) ? item : [item];
        arr.forEach((x) => ids.add(String(x)));
      });
    }
  }
  ids.delete(detail?.event_id);
  const related = [...ids].slice(0, 40);
  if (related.length === 0) return <p className="text-[11px] text-slate-600">no correlated events</p>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {related.map((id) => (
        <button
          key={id}
          onClick={() => onOpen(id)}
          className="mono max-w-[180px] truncate rounded-md border border-white/10 bg-white/5 px-2 py-1 text-[10px] text-slate-400 transition hover:border-cyan-500/40 hover:text-cyan-300"
          title="open related event"
        >
          {id}
        </button>
      ))}
    </div>
  );
}

function InvestigationPanel({ detail, meta }) {
  const cases = meta?.relatedCases || [];
  if (cases.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-white/10 p-3 text-[11px] text-slate-600">
        not linked to any SOC case · {meta?.loading ? "correlating…" : "no alert created for this event"}
      </div>
    );
  }
  const statusMap = {
    open: "border-rose-500/30 bg-rose-500/10 text-rose-300",
    investigation: "border-amber-500/30 bg-amber-500/10 text-amber-300",
    acknowledged: "border-amber-500/30 bg-amber-500/10 text-amber-300",
    closed: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
    resolved: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  };
  return (
    <div className="space-y-2">
      {cases.map((c) => (
        <div key={c.id} className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`mono rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-widest ${statusMap[c.status] || "border-white/10 text-slate-400"}`}>{c.status || "open"}</span>
            <span className="mono text-[10.5px] text-slate-400">{c.threat_class}</span>
            {c.assignee && <span className="mono text-[10px] text-emerald-300">@{c.assignee}</span>}
          </div>
          <p className="mono mt-1.5 break-all text-[10px] text-slate-500">case {c.id}</p>
          <p className="mt-1 text-[11px] text-slate-300">{c.message || "—"}</p>
          {(c.notes || []).length > 0 && (
            <div className="mt-2 space-y-1">
              {(c.notes || []).map((n, ni) => (
                <p key={ni} className="mono rounded bg-black/30 px-2 py-1 text-[10px] text-amber-200/80">
                  <span className="text-slate-600">[{n.ts || ""}] {n.actor || ""}</span> — {n.note || ""}
                </p>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// Correlate the open event with geo enrichment + any SOC cases that reference it.
async function enrichDetail(full, e) {
  const fields = full?.fields || e?.fields || {};
  const want = new Set([fields.src_ip, fields.dst_ip, e?.client_ip].filter(Boolean));
  const geo = {};
  await Promise.all([...want].map(async (ip) => {
    try {
      const r = await enrichEntity("ip", ip);
      if (r?.geo && Object.keys(r.geo).length) geo[ip] = r.geo;
    } catch { /* enrichment is best-effort */ }
  }));
  try {
    const { cases = [] } = await getCases({ limit: 500 });
    const relatedCases = cases.filter((c) => {
      const ev = c?.evidence || {};
      const evIds = [ev.event_id, ...(Array.isArray(ev.event_ids) ? ev.event_ids : [])].filter(Boolean).map(String);
      const flowIds = String(c?.flows || "").split(",").map((s) => s.trim()).filter(Boolean);
      const source = String(c?.source_value || "");
      return evIds.includes(full?.event_id)
        || flowIds.includes(full?.event_id)
        || source === full?.event_id
        || (full?.fields?.threat_class && c?.threat_class === full.fields.threat_class && flowIds.length > 0);
    });
    return { geo, relatedCases };
  } catch {
    return { geo, relatedCases: [] };
  }
}

function TraceTimeline({ events, current }) {
  const sorted = [...events].sort(
    (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
  );
  const shown = sorted.length > 30 ? sorted.slice(Math.max(0, sorted.length - 30)) : sorted;
  return (
    <div className="mt-5">
      <details open>
        <summary className="cursor-pointer text-[11px] text-slate-500 hover:text-slate-300">
          trace timeline · {sorted.length} events
        </summary>
        <ol className="mt-3 space-y-0 border-l border-white/10 pl-4">
          {shown.map((ev) => {
            const isCurrent = ev.event_id === current;
            return (
              <li key={ev.event_id} className="relative pb-3">
                <span
                  className={`absolute -left-[19px] top-1 h-2 w-2 rounded-full ${
                    isCurrent ? "bg-emerald-400 pulse-dot-green" : "bg-slate-600"
                  }`}
                />
                <div className={`flex items-center gap-2 text-[10.5px] ${isCurrent ? "text-emerald-300" : "text-slate-400"}`}>
                  <span className={`mono ${isCurrent ? "sev-critical" : "sev-info"}`}>
                    {ev.category || "system"}
                  </span>
                  <span className="ml-auto">{(ev.timestamp || "").slice(11, 19)}Z</span>
                </div>
                <p className={`mt-0.5 truncate text-[11px] ${isCurrent ? "text-slate-100" : "text-slate-500"}`}>
                  {ev.message || "—"}
                </p>
                {ev.fields && ev.fields.threat_class && (
                  <p className="text-[9.5px] uppercase tracking-wider text-amber-400/80">
                    ⚠ {ev.fields.threat_class}
                  </p>
                )}
              </li>
            );
          })}
        </ol>
      </details>
    </div>
  );
}

const stripCls = (sev) => {
  const m = { critical: "sev-critical", high: "sev-high", medium: "sev-warning", warning: "sev-warning", error: "sev-error", info: "sev-info", low: "sev-info" };
  return m[sev] || "sev-info";
};

// Mirrors the backend /api/events/search matching so live SSE events respect
// the currently active filters.
function runFiltersMatch(ev, { query = "", src = "", sev = "", cat = "", client = "", threat = "", fromTs = "", toTs = "" } = {}) {
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
  if (threat) {
    const f = ev.fields || {};
    const mf = f.module_findings || {};
    const evtc = String(mf?.find?.((m) => m.threat_class)?.threat_class ||
                        mf?.network_threat?.threat_class ||
                        f.threat_class || "").toLowerCase();
    if (!evtc.includes(threat.toLowerCase())) return false;
  }
  if (fromTs && ev.timestamp && ev.timestamp < normTs(fromTs)) return false;
  if (toTs && ev.timestamp && ev.timestamp > normTs(toTs)) return false;
  return true;
}

// datetime-local values arrive as "YYYY-MM-DDTHH:mm"; normalize to the store's
// second-resolution UTC timestamps so range comparisons stay lexicographic.
function normTs(value) {
  return value ? `${value}:00` : "";
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