import React, { useEffect, useState } from "react";
import { searchEvents, getClients } from "../lib/api";
import { SeverityDot, SeverityBadge, PageHeader, LiveBadge, PlainBadge, CodeBlock, Empty } from "../components/ui";

const CATEGORIES = ["", "flow", "auth", "application", "network", "system", "vpn"];
const SOURCES = ["", "netflow", "syslog", "json", "cef", "csv", "windows"];
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
  const [query, setQuery] = useState("");
  const [src, setSrc] = useState("");
  const [sev, setSev] = useState("");
  const [cat, setCat] = useState("");
  const [client, setClient] = useState("");
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(false);
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    getClients()
      .then((d) => setClients(d.clients || []))
      .catch(() => {});
  }, []);

  const run = async (keepDetail = false) => {
    setLoading(true);
    try {
      const data = await searchEvents({
        query,
        source_type: src,
        severity: sev,
        category: cat,
        client_id: client,
        limit: 60,
      });
      setEvents(data.events);
      setTotal(data.total);
      if (!keepDetail) setDetail(null);
      setError(null);
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Live filtering: refresh whenever the search/filter inputs change
    // (chips toggle above the table). Enter / SEARCH still run instantly.
    const t = setTimeout(() => run(true), 250);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, src, sev, cat, client]);

  const filtersActive = Boolean(query || src || sev || cat || client);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Forensics · Event store"
        title="Event triage"
        sub="Search the normalized corpus — free-text over IPs, process names, messages and trace-ids, narrowed by source, client and category."
        actions={<LiveBadge text={`${total} matched`} />}
      />

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
                onClick={() => setDetail(e)}
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
  const m = { critical: "sev-critical", high: "sev-high", medium: "sev-warning", error: "sev-error", info: "sev-info", low: "sev-info" };
  return m[sev] || "sev-info";
};

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