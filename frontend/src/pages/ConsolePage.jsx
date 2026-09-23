import React, { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { searchEvents, streamEvents } from "../lib/api";
import { PageHeader, SeverityDot, Empty, PlainBadge } from "../components/ui";

const MAX_LINES = 2000;

// Cloudflare quick tunnels buffer SSE heavily, so live tails also poll the
// search endpoint on an interval as a catch-up fallback (deduped by event_id).
const POLL_MS = 8000;

// System-wide live console: every event the pipeline accepts, streamed in
// newest-first. Same engine as a client's log console, but global.
export default function ConsolePage() {
  const [lines, setLines] = useState([]);
  const [total, setTotal] = useState(0);
  const [live, setLive] = useState(true);
  const [paused, setPaused] = useState(false);
  const [liveCount, setLiveCount] = useState(0);
  const [filter, setFilter] = useState("");
  const [showRaw, setShowRaw] = useState(false);
  const [sevFilter, setSevFilter] = useState("");
  const [clientFilter, setClientFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const scrollRef = useRef(null);
  const autoScroll = useRef(true);
  const closeStream = useRef(() => {});
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const missedRef = useRef([]);
  const linesRef = useRef(lines);
  linesRef.current = lines;
  const pollRef = useRef(null);
  const pollInFlight = useRef(false);

  // Newest lines are PREPENDED, so "following live" means pinned at the TOP.
  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    autoScroll.current = el.scrollTop < 40;
  }, []);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    searchEvents({ limit: 200 })
      .then((d) => {
        if (!alive) return;
        setLines(d.events || []);
        setTotal(d.total || 0);
        setError(null);
      })
      .catch((e) => alive && setError(e.message))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    if (!live) {
      closeStream.current?.();
      closeStream.current = () => {};
      return;
    }
    closeStream.current = streamEvents({
      onEvent: (ev) => {
        // Only raw telemetry rows belong here; task/case notifications from
        // the SOC stream are envelopes without event_id — skip them.
        if (!ev || !ev.event_id) return;
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
  }, [live]);

  // Poll catch-up: quick tunnels buffer/drop SSE, so periodically re-sync the
  // tail against the search endpoint and merge any events that didn't arrive
  // over the stream (deduped by event_id, newest kept at the top).
  useEffect(() => {
    if (!live) return () => clearInterval(pollRef.current);
    const tick = async () => {
      if (pollInFlight.current) return;
      pollInFlight.current = true;
      try {
        const d = await searchEvents({ limit: 100 });
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
  }, [live]);

  // Resume: replay events buffered while frozen, most recent first.
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

  useEffect(() => {
    if (autoScroll.current && scrollRef.current) scrollRef.current.scrollTop = 0;
  }, [lines]);

  const filtered = lines.filter((e) => {
    if (sevFilter && e.severity !== sevFilter) return false;
    if (clientFilter && e.client_id !== clientFilter) return false;
    if (filter) {
      const cqf = filter.toLowerCase();
      const hay = [
        e.message || "",
        e.client_ip || "",
        e.trace_id || "",
        e.source_type || "",
        e.client_id || "",
        JSON.stringify(e.fields || {}),
      ].join(" ").toLowerCase();
      if (hay.includes(cqf)) return true;
      return false;
    }
    return true;
  });

  return (
    <div className="flex h-[calc(100vh-8rem)] flex-col gap-4">
      <PageHeader
        eyebrow="Telemetry · every event, every agent"
        title="Live console"
        sub={
          <span className="flex flex-wrap items-center gap-3">
            <PlainBadge cls="!text-cyan-300">system-wide</PlainBadge>
            <span className="mono text-[11px] text-slate-500">
              {total.toLocaleString()} events in store
            </span>
            <Link to="/events" className="mono text-[11px] text-emerald-300 hover:text-emerald-200">open triage →</Link>
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
              <button onClick={() => setPaused(!paused)} className="chip">
                {paused ? "▶ RESUME" : "⏸ FREEZE"}
              </button>
            )}
          </div>
        }
      />

      <div className="glass flex flex-wrap items-center gap-3 px-4 py-2.5">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter messages, ips, trace-ids, clients…"
          className="field mono w-72 py-1.5 px-3 text-[12px]"
        />
        <input
          value={clientFilter}
          onChange={(e) => setClientFilter(e.target.value)}
          placeholder="client id"
          className="field mono w-44 py-1.5 px-3 text-[12px]"
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
        <button onClick={() => setShowRaw(!showRaw)} className={`chip ${showRaw ? "chip-on" : ""}`}>
          {showRaw ? "RAW" : "PARSED"}
        </button>
        <span className="ml-auto mono text-[10px] text-slate-600">
          {filtered.length} / {lines.length} lines
        </span>
      </div>

      {error && <div className="text-sm text-rose-400">{error}</div>}

      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto rounded-xl border border-white/5 bg-black/60 p-4 font-mono text-[12px] leading-relaxed"
      >
        {loading ? (
          <div className="flex h-full items-center justify-center text-slate-500">Loading console…</div>
        ) : filtered.length === 0 ? (
          <Empty title="No lines" hint="Waiting for events from your agents…" />
        ) : (
          filtered.map((e, i) => <LogLine key={e.event_id || i} event={e} showRaw={showRaw} />)
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
    <div className="group flex gap-3 py-0.5 hover:bg-white/[0.02]">
      <span className="shrink-0 text-slate-600">{time}</span>
      <SeverityDot severity={e.severity} />
      <span className={`min-w-0 flex-1 break-all ${sevColor}`}>{text}</span>
      <span className="hidden shrink-0 text-[10px] text-slate-600 group-hover:inline">
        {e.client_id}
        {e.source_type ? ` · ${e.source_type}` : ""}
      </span>
    </div>
  );
}