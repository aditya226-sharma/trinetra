import React, { useCallback, useEffect, useRef, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { searchEvents, getClients, streamEvents } from "../lib/api";
import { PageHeader, SeverityBadge, SeverityDot, Empty, PlainBadge } from "../components/ui";

const MAX_LINES = 2000;

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
        const sorted = (d.events || []).reverse();
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

  // Resume: replay the events buffered while frozen, most recent first.
  useEffect(() => {
    if (paused) return;
    const missed = missedRef.current;
    missedRef.current = [];
    if (missed.length === 0) return;
    setLines((prev) => {
      const seen = new Set(prev.map((e) => e.event_id));
      const fresh = missed.filter((e) => !seen.has(e.event_id));
      let next = [...fresh.reverse(), ...prev];
      if (next.length > MAX_LINES) next = next.slice(0, MAX_LINES);
      return next;
    });
    setTotal((t) => t + fresh.length);
  }, [paused]);

  // Auto-scroll
  useEffect(() => {
    if (autoScroll.current && scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [lines]);

  const filtered = lines.filter((e) => {
    if (sevFilter && e.severity !== sevFilter) return false;
    if (filter) {
      const q = filter.toLowerCase();
      const hay = [
        e.message || "",
        e.client_ip || "",
        e.trace_id || "",
        e.source_type || "",
        JSON.stringify(e.fields || {}),
      ].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const isOnline = clientMeta?.status === "online";

  return (
    <div className="flex h-[calc(100vh-8rem)] flex-col gap-4">
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
              {" · "}first {fmtAgo(clientMeta?.first_seen)}
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

      {/* Controls bar */}
      <div className="glass flex flex-wrap items-center gap-3 px-4 py-2.5">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter messages…"
          className="field mono w-60 py-1.5 px-3 text-[12px]"
        />
        <div className="flex items-center gap-1.5">
          {["", "critical", "error", "warning", "info"].map((s) => (
            <button
              key={s || "all-sev"}
              onClick={() => setSevFilter(s)}
              className={`chip text-[10px] ${sevFilter === s ? "chip-on" : ""}`}
            >
              {s || "all"}
            </button>
          ))}
        </div>
        <button
          onClick={() => setShowRaw(!showRaw)}
          className={`chip ${showRaw ? "chip-on" : ""}`}
        >
          {showRaw ? "RAW" : "PARSED"}
        </button>
        <span className="ml-auto mono text-[10px] text-slate-600">
          {filtered.length} / {lines.length} lines
        </span>
      </div>

      {error && <div className="text-sm text-rose-400">{error}</div>}

      {/* Log terminal */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto rounded-xl border border-white/5 bg-black/60 p-4 font-mono text-[12px] leading-relaxed"
      >
        {loading ? (
          <div className="flex h-full items-center justify-center text-slate-500">Loading logs…</div>
        ) : filtered.length === 0 ? (
          <Empty title="No log lines" hint="Waiting for events from this client…" />
        ) : (
          filtered.map((e, i) => (
            <LogLine key={e.event_id || i} event={e} showRaw={showRaw} />
          ))
        )}
      </div>
    </div>
  );
}

function LogLine({ event: e, showRaw }) {
  const sevColor = {
    critical: "text-rose-400",
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
    <div className="flex gap-3 py-0.5 hover:bg-white/[0.02] group">
      <span className="shrink-0 text-slate-600">{time}</span>
      <SeverityDot severity={e.severity} />
      <span className="min-w-0 flex-1 break-all text-slate-300">
        {text}
      </span>
      <span className="hidden shrink-0 text-[10px] text-slate-600 group-hover:inline">
        {e.source_type}
        {e.fields?.channel ? ` · ${e.fields.channel}` : ""}
      </span>
    </div>
  );
}
