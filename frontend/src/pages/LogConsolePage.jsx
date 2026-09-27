import React, { useCallback, useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { searchEvents, getClients, streamEvents } from "../lib/api";
import { PageHeader, SeverityBadge, SeverityDot, Empty, PlainBadge, SectionTitle, CodeBlock } from "../components/ui";

const MAX_LINES = 2000;

// Cloudflare quick tunnels buffer SSE heavily, so live tails also poll the
// search endpoint on an interval as a catch-up fallback (deduped by event_id).
const POLL_MS = 8000;

const SEV_ORDER = ["critical", "error", "warning", "high", "medium", "info", "low"];
const CAT_ORDER = ["auth", "network", "system", "application", "vpn", "flow", "other"];

function fmtAgo(iso) {
  if (!iso) return "—";
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return "—";
  const delta = Math.max(0, Math.round((Date.now() - then.getTime()) / 1000));
  if (delta < 60) return "just now";
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}

function uniq(values) {
  return [...new Set(values.filter(Boolean))];
}

export default function LogConsolePage() {
  const { id } = useParams();
  let clientId = id || "";
  try {
    clientId = decodeURIComponent(clientId);
  } catch {
    /* malformed escape in route — fall back to the raw id */
  }

  const [lines, setLines] = useState([]);
  const [total, setTotal] = useState(0);
  const [live, setLive] = useState(true);
  const [paused, setPaused] = useState(false);
  const [liveCount, setLiveCount] = useState(0);
  const [filter, setFilter] = useState("");
  const [showRaw, setShowRaw] = useState(false);
  const [sevFilter, setSevFilter] = useState("");
  const [catFilter, setCatFilter] = useState("");
  const [srcFilter, setSrcFilter] = useState("");
  const [selected, setSelected] = useState(null);
  const [clientMeta, setClientMeta] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const scrollRef = useRef(null);
  const autoScroll = useRef(true);
  const linesRef = useRef(lines);
  linesRef.current = lines;
  const closeStream = useRef(() => {});
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  // Events that arrive while FREEZE is on are held here and replayed on resume
  // (instead of being silently dropped from the live tail).
  const missedRef = useRef([]);
  const pollRef = useRef(null);
  const pollInFlight = useRef(false);

  // Newest lines are PREPENDED, so "following live" means pinned at the TOP.
  // Scrolling up/down into history disables auto-follow until the user returns.
  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    const atTop = el.scrollTop < 40;
    autoScroll.current = atTop;
  }, []);

  // Load initial history
  useEffect(() => {
    let alive = true;
    setLoading(true);
    searchEvents({ client_id: clientId, limit: 200 })
      .then((d) => {
        if (!alive) return;
        const sorted = d.events || [];
        setLines(sorted);
        setTotal(d.total || 0);
        setError(null);
      })
      .catch((e) => alive && setError(e.message))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [clientId]);

  // Load client metadata
  useEffect(() => {
    getClients()
      .then((d) => {
        const found = (d.clients || []).find((c) => c.client_id === clientId);
        setClientMeta(found || null);
      })
      .catch(() => {});
  }, [clientId]);

  // SSE stream
  useEffect(() => {
    if (!live) {
      closeStream.current?.();
      closeStream.current = () => {};
      return;
    }
    closeStream.current = streamEvents({
      clientFilter: clientId,
      onEvent: (ev) => {
        if (!ev || !ev.event_id) return; // SOC task/case envelopes aren't raw rows
        setLiveCount((n) => n + 1);
        if (pausedRef.current) {
          missedRef.current.push(ev);
          return;
        }
        setLines((prev) => {
          const next = [ev, ...prev.filter((e) => e.event_id !== ev.event_id)];
          return next.length > MAX_LINES ? next.slice(0, MAX_LINES) : next;
        });
        setTotal((t) => t + 1);
      },
    });
    return () => closeStream.current?.();
  }, [live, clientId]);

  // Poll catch-up: quick tunnels buffer/drop SSE, so periodically re-sync the
  // tail against the search endpoint and merge any events that didn't arrive
  // over the stream (deduped by event_id, newest kept at the top).
  useEffect(() => {
    if (!live) return () => clearInterval(pollRef.current);
    const tick = async () => {
      if (pollInFlight.current) return;
      pollInFlight.current = true;
      try {
        const d = await searchEvents({ client_id: clientId, limit: 100 });
        const seen = new Set(linesRef.current.map((e) => e.event_id));
        const fresh = (d.events || []).filter((e) => e.event_id && !seen.has(e.event_id));
        if (fresh.length > 0) {
          if (pausedRef.current) {
            missedRef.current.push(...fresh);
          } else {
            setLines((prev) => {
              const freshIds = new Set(fresh.map((e) => e.event_id));
              const next = [...fresh, ...prev.filter((e) => !freshIds.has(e.event_id))];
              return next.length > MAX_LINES ? next.slice(0, MAX_LINES) : next;
            });
          }
        }
        if (typeof d.total === "number") setTotal(d.total);
      } catch {
        /* transient search failure — fall back to pure SSE until next tick */
      } finally {
        pollInFlight.current = false;
      }
    };
    tick();
    pollRef.current = setInterval(tick, POLL_MS);
    return () => clearInterval(pollRef.current);
  }, [live, clientId]);

  // Resume: replay the events buffered while frozen, most recent first.
  useEffect(() => {
    if (paused) return;
    const missed = missedRef.current;
    missedRef.current = [];
    if (missed.length === 0) return;
    setLines((prev) => {
      const seen = new Set(prev.map((e) => e.event_id));
      const byId = new Map();
      missed.forEach((e) => { if (e.event_id) byId.set(e.event_id, e); });
      const fresh = [...byId.values()].filter((e) => !seen.has(e.event_id));
      fresh.sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0));
      let next = [...fresh, ...prev];
      if (next.length > MAX_LINES) next = next.slice(0, MAX_LINES);
      return next;
    });
  }, [paused]);

  // Auto-scroll
  useEffect(() => {
    if (autoScroll.current && scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [lines]);

  // Filter options derived from the live buffer (always in sync with the data)
  const sevCounts = uniq(lines.map((e) => e.severity));
  const catCounts = uniq(lines.map((e) => e.category));
  const srcCounts = uniq(lines.map((e) => e.source_type));
  const sevOptions = uniq([...SEV_ORDER.filter((s) => sevCounts.includes(s)), ...sevCounts.filter((s) => !SEV_ORDER.includes(s))]);
  const catOptions = uniq([...CAT_ORDER.filter((c) => catCounts.includes(c)), ...catCounts.filter((c) => !CAT_ORDER.includes(c))]);
  const srcOptions = uniq([srcFilter, ...srcCounts]);

  const filtered = lines.filter((e) => {
    if (sevFilter && e.severity !== sevFilter) return false;
    if (catFilter && e.category !== catFilter) return false;
    if (srcFilter && e.source_type !== srcFilter) return false;
    if (filter) {
      const q = filter.toLowerCase();
      const hay = [
        e.message || "",
        e.client_ip || "",
        e.trace_id || "",
        e.event_id || "",
        e.source_type || "",
        e.category || "",
        e.client_id || "",
        JSON.stringify(e.fields || {}),
      ].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const resetFilters = () => {
    setFilter("");
    setSevFilter("");
    setCatFilter("");
    setSrcFilter("");
  };

  const isOnline = clientMeta?.status === "online";

  return (
    <div className="space-y-4">
      {/* Header */}
      <PageHeader
        eyebrow={`Client · ${clientId}`}
        title={
          <span className="flex items-center gap-3">
            <span className={`inline-block h-2.5 w-2.5 rounded-full ${isOnline ? "bg-emerald-400 pulse-dot" : "bg-slate-500"}`} />
            {clientMeta?.hostname || clientId}
          </span>
        }
        sub={
          <span className="flex flex-wrap items-center gap-3">
            {clientMeta?.platform && <PlainBadge cls="!text-cyan-300">{clientMeta.platform}</PlainBadge>}
            {clientMeta?.agent_version && <PlainBadge>v{clientMeta.agent_version}</PlainBadge>}
            {clientMeta?.ip && <PlainBadge>{clientMeta.ip}</PlainBadge>}
            {clientMeta?.source_types?.map((st) => (
              <PlainBadge key={st}>{st}</PlainBadge>
            ))}
            <span className="mono text-[11px] text-slate-500">
              {total.toLocaleString()} events · {isOnline ? "online" : `last seen ${fmtAgo(clientMeta?.last_seen)}`}
            </span>
          </span>
        }
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={() => setLive(!live)}
              className={`chip ${live ? "chip-on" : ""}`}
              style={live ? { borderColor: "rgba(52,211,153,0.6)", color: "#6ee7b7" } : undefined}
            >
              <span className={`mr-1.5 inline-block h-1.5 w-1.5 rounded-full ${live && !paused ? "bg-emerald-400 pulse-dot" : "bg-slate-500"}`} />
              {live ? (paused ? "PAUSED" : `LIVE · ${liveCount}`) : "PAUSED"}
            </button>
            {live && (
              <button
                onClick={() => setPaused(!paused)}
                className="chip"
              >
                {paused ? "▶ RESUME" : "⏸ FREEZE"}
              </button>
            )}
          </div>
        }
      />

      {/* Client information */}
      <ClientInfo meta={clientMeta} total={total} isOnline={isOnline} />

      {/* Filter & search */}
      <section className="glass p-4 anim-fadeup">
        <SectionTitle
          right={
            <span className="mono text-[10px] uppercase tracking-widest text-slate-500">
              {filtered.length} / {lines.length} lines
            </span>
          }
        >
          Filter & search
        </SectionTitle>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative min-w-[220px] flex-1">
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="search messages, ip, trace_id, fields…"
              className="field mono w-full py-1.5 px-3 pr-8 text-[12px]"
            />
            {filter && (
              <button
                onClick={() => setFilter("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 transition hover:text-slate-200"
                title="clear search"
              >
                ✕
              </button>
            )}
          </div>
          <button
            onClick={() => setShowRaw(!showRaw)}
            className={`chip ${showRaw ? "chip-on" : ""}`}
          >
            {showRaw ? "RAW" : "PARSED"}
          </button>
          <button
            onClick={resetFilters}
            disabled={!filter && !sevFilter && !catFilter && !srcFilter}
            className="chip disabled:opacity-40"
          >
            ⨯ RESET
          </button>
        </div>

        {sevOptions.length > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            <span className="mono mr-1 text-[9px] uppercase tracking-widest text-slate-600">severity</span>
            <button
              onClick={() => setSevFilter("")}
              className={`chip text-[10px] ${sevFilter === "" ? "chip-on" : ""}`}
            >
              all
            </button>
            {sevOptions.map((s) => (
              <button
                key={s}
                onClick={() => setSevFilter(sevFilter === s ? "" : s)}
                className={`chip text-[10px] ${sevFilter === s ? "chip-on" : ""}`}
              >
                {s}
              </button>
            ))}
          </div>
        )}

        {catOptions.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <span className="mono mr-1 text-[9px] uppercase tracking-widest text-slate-600">category</span>
            <button
              onClick={() => setCatFilter("")}
              className={`chip text-[10px] ${catFilter === "" ? "chip-on" : ""}`}
            >
              all
            </button>
            {catOptions.map((c) => (
              <button
                key={c}
                onClick={() => setCatFilter(catFilter === c ? "" : c)}
                className={`chip text-[10px] ${catFilter === c ? "chip-on" : ""}`}
              >
                {c}
              </button>
            ))}
          </div>
        )}

        {srcOptions.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <span className="mono mr-1 text-[9px] uppercase tracking-widest text-slate-600">source</span>
            <button
              onClick={() => setSrcFilter("")}
              className={`chip text-[10px] ${srcFilter === "" ? "chip-on" : ""}`}
            >
              all
            </button>
            {srcOptions.map((s) => (
              <button
                key={s}
                onClick={() => setSrcFilter(srcFilter === s ? "" : s)}
                className={`chip text-[10px] ${srcFilter === s ? "chip-on" : ""}`}
              >
                {s}
              </button>
            ))}
          </div>
        )}
      </section>

      {error && <div className="text-sm text-red-400">{error}</div>}

      {/* Selected log detail */}
      {selected && <EventDetail event={selected} onClose={() => setSelected(null)} />}

      {/* Log terminal */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="h-[min(60vh,640px)] min-h-[320px] overflow-y-auto rounded-xl border border-white/5 bg-black/60 p-4 font-mono text-[12px] leading-relaxed"
      >
        {loading ? (
          <div className="flex h-full items-center justify-center text-slate-500">Loading logs…</div>
        ) : filtered.length === 0 ? (
          <Empty title="No log lines" hint="Waiting for events from this client…" />
        ) : (
          filtered.map((e, i) => (
            <LogLine
              key={e.event_id || i}
              event={e}
              showRaw={showRaw}
              active={selected?.event_id === e.event_id}
              onSelect={setSelected}
            />
          ))
        )}
        {!loading && filtered.length > 0 && filtered.length < lines.length && (
          <p className="sticky bottom-0 bg-black/80 py-1 text-center text-[10px] text-slate-600">
            showing {filtered.length} of {lines.length} lines — clear filters to see the rest
          </p>
        )}
      </div>
    </div>
  );
}

function ClientInfo({ meta, total, isOnline }) {
  return (
    <section className="glass p-4 anim-fadeup">
      <SectionTitle
        right={<span className="mono text-[10px] uppercase tracking-widest text-slate-500">fleet registry · GET /api/clients</span>}
      >
        Client information
      </SectionTitle>
      <div className="grid gap-x-6 gap-y-2.5 sm:grid-cols-2 xl:grid-cols-4">
        <InfoTile k="Client ID" v={meta?.client_id || "—"} mono />
        <InfoTile k="Hostname" v={meta?.hostname || "—"} mono />
        <InfoTile k="Status" v={isOnline ? "🟢 online" : "⚪ offline"} mono />
        <InfoTile k="Platform" v={meta?.platform || "—"} />
        <InfoTile k="Agent version" v={meta?.agent_version ? `v${meta.agent_version}` : "—"} />
        <InfoTile k="IP address" v={meta?.ip || "—"} mono />
        <InfoTile k="Total events" v={(total ?? 0).toLocaleString()} mono />
        <InfoTile k="Events (5m)" v={(meta?.events_recent ?? 0).toLocaleString()} mono />
        <InfoTile k="First seen" v={fmtAgo(meta?.first_seen)} />
        <InfoTile k="Last seen" v={fmtAgo(meta?.last_seen)} />
        <InfoTile k="Heartbeat" v={fmtAgo(meta?.heartbeat_at)} />
        <InfoTile k="Token" v={meta?.token_id ? `…${meta.token_id.slice(-6)}` : "—"} mono />
      </div>
      {meta?.source_types?.length > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-1.5 border-t border-white/5 pt-3">
          <span className="mono mr-1 text-[9px] uppercase tracking-widest text-slate-600">source_types</span>
          {meta.source_types.map((st) => (
            <span key={st} className="mono rounded border border-cyan-400/20 bg-cyan-400/10 px-2 py-0.5 text-[10px] text-cyan-300">
              {st}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}

function InfoTile({ k, v, mono }) {
  return (
    <div className="min-w-0">
      <p className="text-[9px] uppercase tracking-widest text-slate-600">{k}</p>
      <p className={`mt-0.5 truncate text-[13px] text-slate-200 ${mono ? "mono" : ""}`}>{v}</p>
    </div>
  );
}

function EventDetail({ event: e, onClose }) {
  const ts = e.timestamp ? new Date(e.timestamp) : null;
  const time = ts && !Number.isNaN(ts.getTime())
    ? ts.toLocaleString("en-GB", { hour12: false })
    : "—";
  const fields = e.fields && typeof e.fields === "object" ? e.fields : {};
  const mf = e.module_findings || fields.module_findings;
  return (
    <section className="glass overflow-hidden anim-fadeup">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="mono text-[11px] tracking-widest text-slate-500">event detail</span>
          <SeverityBadge severity={e.severity} />
          {e.category && <PlainBadge cls="!text-cyan-300">{e.category}</PlainBadge>}
          {e.source_type && <PlainBadge>{e.source_type}</PlainBadge>}
          {e.client_ip && <PlainBadge cls="!text-slate-400">{e.client_ip}</PlainBadge>}
        </div>
        <button onClick={onClose} className="chip">✕ close</button>
      </div>

      <div className="space-y-4 p-4">
        <div className="mono flex flex-wrap items-center gap-x-5 gap-y-1 text-[11px] text-slate-500">
          <span>ts <b className="text-slate-300">{time}</b></span>
          {e.client_id && <span>client <b className="text-slate-300">{e.client_id}</b></span>}
          {fields.host && <span>host <b className="text-slate-300">{fields.host}</b></span>}
          {fields.src && fields.dst && (
            <span>
              flow <b className="text-cyan-300">{fields.src}</b>
              {fields.sport ? `:${fields.sport}` : ""} →{" "}
              <b className="text-cyan-300">{fields.dst}</b>
              {fields.dport ? `:${fields.dport}` : ""} · {fields.proto}
            </span>
          )}
        </div>

        <div>
          <p className="eyebrow mb-1">message</p>
          <p className="text-[13px] leading-relaxed text-slate-200">{e.message || "(no message)"}</p>
        </div>

        {Object.keys(fields).length > 0 && <FieldTable fields={fields} />}

        <div className={`grid gap-4 ${mf ? "lg:grid-cols-2" : "lg:grid-cols-1"}`}>
          <div>
            <p className="eyebrow mb-1">raw_event · lossless</p>
            <CodeBlock maxH="max-h-44">{e.raw_event || e.raw || "—"}</CodeBlock>
          </div>
          {mf && (
            <div>
              <p className="eyebrow mb-1">module_findings</p>
              <CodeBlock maxH="max-h-44">{typeof mf === "string" ? mf : JSON.stringify(mf, null, 2)}</CodeBlock>
            </div>
          )}
        </div>

        <div className="mono flex flex-wrap gap-x-6 gap-y-1 border-t border-white/5 pt-3 text-[10px] text-slate-600">
          <span>event_id <b className="text-slate-400">{e.event_id || "—"}</b></span>
          <span>trace_id <b className="text-slate-400">{e.trace_id || "—"}</b></span>
        </div>
      </div>
    </section>
  );
}

function FieldTable({ fields }) {
  const entries = Object.entries(fields);
  return (
    <div>
      <p className="eyebrow mb-1">fields</p>
      <div className="overflow-hidden rounded-lg border border-white/10">
        <div className="max-h-52 overflow-y-auto">
          <table className="w-full text-left text-[11px]">
            <tbody>
              {entries.map(([k, v]) => (
                <tr key={k} className="border-b border-white/5 last:border-0">
                  <td className="mono w-44 px-2.5 py-1.5 align-top text-slate-500">{k}</td>
                  <td className="break-all px-2.5 py-1.5 text-slate-300">
                    {typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function LogLine({ event: e, showRaw, active, onSelect }) {
  const sevColor = {
    critical: "text-red-400",
    error: "text-violet-400",
    warning: "text-amber-400",
    info: "text-slate-300",
    low: "text-slate-400",
  }[e.severity] || "text-slate-300";

  const ts = e.timestamp ? new Date(e.timestamp) : null;
  const time = ts && !Number.isNaN(ts.getTime()) ? ts.toLocaleTimeString("en-GB", { hour12: false }) : "";
  const text = showRaw
    ? (e.raw_event || e.raw || e.message || (e.fields ? JSON.stringify(e.fields) : ""))
    : e.message || "(no message)";

  return (
    <button
      type="button"
      onClick={() => onSelect(e)}
      title="view event detail"
      className={`group flex w-full cursor-pointer gap-3 px-1 py-0.5 text-left transition hover:bg-white/[0.04] ${active ? "bg-emerald-500/10" : ""}`}
    >
      <span className="shrink-0 text-slate-600">{time}</span>
      <SeverityDot severity={e.severity} />
      <span className={`min-w-0 flex-1 break-all ${showRaw ? "text-slate-400" : sevColor}`}>
        {text}
      </span>
      <span className="hidden shrink-0 text-[10px] text-slate-600 group-hover:inline">
        {e.source_type}
        {e.fields?.channel ? ` · ${e.fields.channel}` : ""}
      </span>
      <span className={`shrink-0 text-[12px] ${active ? "text-emerald-300" : "text-slate-700 group-hover:text-emerald-300"}`}>›</span>
    </button>
  );
}