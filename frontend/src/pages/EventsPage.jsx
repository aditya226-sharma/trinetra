import React, { useEffect, useState } from "react";
import { searchEvents } from "../lib/api";
import { SeverityBadge } from "../components/ui";

export default function EventsPage() {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [query, setQuery] = useState("");
  const [src, setSrc] = useState("");
  const [sev, setSev] = useState("");
  const [loading, setLoading] = useState(false);
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState(null);

  const run = async () => {
    setLoading(true);
    setDetail(null);
    try {
      const { data } = await searchEvents({
        query,
        source_type: src,
        severity: sev,
        limit: 60,
      });
      setEvents(data.events);
      setTotal(data.total);
      setError(null);
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Event triage</h1>
      <div className="flex flex-wrap gap-2">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="search IP / message / trace…"
          className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm outline-none focus:border-emerald-500"
        />
        <select
          value={src}
          onChange={(e) => setSrc(e.target.value)}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
        >
          <option value="">all sources</option>
          {["netflow", "syslog", "json", "cef", "csv", "windows"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <select
          value={sev}
          onChange={(e) => setSev(e.target.value)}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
        >
          <option value="">all severities</option>
          {["critical", "error", "warning", "info"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <button
          onClick={run}
          className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950"
        >
          {loading ? "…" : "Search"}
        </button>
      </div>

      {error && <div className="text-sm text-red-400">{error}</div>}

      <div className="flex gap-6">
        <div className="flex-1 space-y-2">
          <p className="text-xs text-slate-500">{total} events stored</p>
          {events.map((e) => (
            <button
              key={e.event_id}
              onClick={() => setDetail(e)}
              className="block w-full rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-left hover:border-emerald-500/50"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs text-slate-400">{e.timestamp}</span>
                <SeverityBadge severity={e.severity} />
              </div>
              <p className="mt-1 truncate text-sm text-slate-200">
                [{e.source_type}/{e.category}] {e.message}
              </p>
              {e.fields?.src_ip && (
                <p className="mt-1 text-xs text-slate-500">
                  {e.fields.src_ip} → {e.fields.dst_ip || "?"}
                </p>
              )}
            </button>
          ))}
        </div>

        {detail && (
          <div className="w-96 shrink-0 space-y-3 rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold">Event detail</h2>
              <button onClick={() => setDetail(null)} className="text-slate-500">×</button>
            </div>
            <dl className="space-y-1 text-xs">
              <DetailRow k="event_id" v={detail.event_id} />
              <DetailRow k="trace_id" v={detail.trace_id} />
              <DetailRow k="client" v={detail.client_id} />
              <DetailRow k="category" v={detail.category} />
              <DetailRow k="source" v={detail.source_type} />
              <DetailRow k="msg" v={detail.message} />
            </dl>
            <pre className="max-h-56 overflow-y-auto rounded-lg bg-slate-950 p-2 text-[11px] text-slate-400">
              {JSON.stringify(detail.fields, null, 2)}
            </pre>
            {detail.raw && (
              <details>
                <summary className="cursor-pointer text-xs text-slate-400">
                  raw event ({detail.raw.length} bytes)
                </summary>
                <pre className="mt-1 max-h-40 overflow-y-auto rounded-lg bg-slate-950 p-2 text-[11px] text-slate-400">
                  {detail.raw}
                </pre>
              </details>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function DetailRow({ k, v }) {
  return (
    <div className="grid grid-cols-[90px_1fr] gap-2">
      <dt className="text-slate-500">{k}</dt>
      <dd className="break-all text-slate-300">{v || "—"}</dd>
    </div>
  );
}