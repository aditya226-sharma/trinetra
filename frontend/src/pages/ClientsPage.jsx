import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getClients } from "../lib/api";
import { PageHeader, Empty, PulseDot, PlainBadge } from "../components/ui";

function fmtAgo(iso) {
  if (!iso) return "never";
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return "—";
  const delta = Math.max(0, Math.round((Date.now() - then.getTime()) / 1000));
  if (delta < 60) return "just now";
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}

function fmtRate(events, windowSec) {
  if (!windowSec || events === 0) return "—";
  const eps = events / windowSec;
  if (eps >= 1) return `${eps.toFixed(1)} evt/s`;
  return `${(eps * 60).toFixed(1)} evt/min`;
}

const PLATFORM_ICON = {
  darwin: "macOS",
  linux: "Linux",
  windows: "Windows",
};

export default function ClientsPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState("all"); // all | online | offline
  const navigate = useNavigate();

  useEffect(() => {
    let alive = true;
    const load = () => {
      if (document.hidden) return;
      getClients()
        .then((d) => alive && setData(d))
        .catch((e) => alive && setError(e.message));
    };
    load();
    const id = setInterval(load, 15000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  if (error) return <div className="text-sm text-pink-500">Failed to load fleet: {error}</div>;
  if (!data) return <div className="text-violet-300">Loading fleet…</div>;

  const totals = data?.totals ?? {};
  const clients = Array.isArray(data?.clients) ? data.clients : [];
  const filtered = clients
    .filter((c) => {
      if (filter === "online" && c.status !== "online") return false;
      if (filter === "offline" && c.status !== "offline") return false;
      if (q) {
        const ql = q.toLowerCase();
        return (
          c.client_id.toLowerCase().includes(ql) ||
          (c.hostname || "").toLowerCase().includes(ql) ||
          (c.platform || "").toLowerCase().includes(ql)
        );
      }
      return true;
    });

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Fleet · Client registry"
        title={
          <>
            Client <span className="text-grad-emerald">fleet</span>
          </>
        }
        sub={`${totals.online ?? 0} online · ${totals.offline ?? 0} offline · ${totals.events ?? 0} total events`}
        actions={
          <div className="flex items-center gap-2">
            <Link
              to="/clients/onboard"
              className="rounded-lg border border-violet-600/30 bg-violet-600/10 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-violet-300 transition hover:bg-violet-600/20"
            >
              + Onboard agent
            </Link>
            <LiveBadgeInline online={totals.online ?? 0} total={totals.clients ?? 0} />
          </div>
        }
      />

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <MiniKpi label="Clients" value={totals.clients ?? 0} tone="calm" />
        <MiniKpi label="Online" value={totals.online ?? 0} tone="info" />
        <MiniKpi label="Total events" value={totals.events ?? 0} tone="brand" />
        <MiniKpi label="Recent (5m)" value={totals.events_recent ?? 0} tone="alert" sub={fmtRate(totals.events_recent, 300)} />
      </div>

      {/* filters */}
      <div className="glass flex flex-wrap items-center gap-3 px-4 py-3">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="search clients…"
          className="field mono w-60 py-2 px-3 text-[12px]"
        />
        {["all", "online", "offline"].map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`chip ${filter === f ? "chip-on" : ""}`}
          >
            {f === "online" && <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-violet-500" />}
            {f === "offline" && <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-[#2e1f4a]" />}
            {f}
          </button>
        ))}
        <span className="ml-auto mono text-[10px] text-violet-400">
          {filtered.length} shown
        </span>
      </div>

      {/* fleet grid */}
      {filtered.length === 0 ? (
        <Empty title="No clients match" hint="Agents will appear here once they send a heartbeat or ingest events." />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((c, i) => (
            <ClientCard
              key={c.client_id}
              c={c}
              delay={i * 40}
              onOpen={() => navigate(`/clients/${encodeURIComponent(c.client_id)}`)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function ClientCard({ c, delay, onOpen }) {
  const isOnline = c.status === "online";
  const handleKey = (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onOpen();
    }
  };
  return (
    <div
      onClick={onOpen}
      onKeyDown={handleKey}
      role="button"
      tabIndex={0}
      aria-label={`Open details for ${c.client_id}`}
      className="glass-row group relative cursor-pointer overflow-hidden p-4 anim-fadeup transition hover:border-violet-600/40"
      style={{ animationDelay: `${delay}ms` }}
    >
      {/* status stripe */}
      <span
        className={`absolute left-0 top-0 h-full w-1 ${isOnline ? "bg-violet-500" : "bg-[#3b2a5c]"}`}
        style={isOnline ? { boxShadow: "0 0 12px rgba(167, 139, 196,0.6)" } : undefined}
      />

      <div className="pl-3">
        {/* header row */}
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className={`inline-block h-2 w-2 rounded-full ${isOnline ? "bg-violet-500 pulse-dot-calm" : "bg-[#2e1f4a]"}`} />
              <span className="mono text-[14px] font-semibold text-slate-100 truncate">{c.client_id}</span>
            </div>
            <p className="mt-0.5 mono text-[11px] text-violet-300 truncate">
              {c.hostname || c.client_id}
            </p>
          </div>
          <span className="shrink-0 rounded-lg border border-violet-600/30 bg-violet-600/10 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-violet-300 transition group-hover:bg-violet-600/20">
            Open Logs
          </span>
        </div>

        {/* metadata row */}
        <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px]">
          {c.platform && (
            <PlainBadge cls="!text-violet-300">
              {PLATFORM_ICON[c.platform] || c.platform}
            </PlainBadge>
          )}
          {c.agent_version && (
            <PlainBadge>v{c.agent_version}</PlainBadge>
          )}
          {c.ip && (
            <PlainBadge cls="!text-violet-200">{c.ip}</PlainBadge>
          )}
        </div>

        {/* source types */}
        {c.source_types?.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {c.source_types.map((st) => (
              <span key={st} className="mono rounded bg-white/5 px-2 py-0.5 text-[10px] text-violet-200">
                {st}
              </span>
            ))}
          </div>
        )}

        {/* stats */}
        <div className="mt-3 grid grid-cols-3 gap-3 border-t border-white/5 pt-3">
          <div>
            <p className="mono text-[18px] font-bold text-slate-100">{(c.events ?? 0).toLocaleString()}</p>
            <p className="text-[10px] uppercase tracking-widest text-violet-400">total</p>
          </div>
          <div>
            <p className="mono text-[18px] font-bold text-violet-300">{c.events_recent ?? 0}</p>
            <p className="text-[10px] uppercase tracking-widest text-violet-400">recent</p>
          </div>
          <div>
            <p className="mono text-[11px] text-violet-200">{fmtAgo(c.last_seen)}</p>
            <p className="text-[10px] uppercase tracking-widest text-violet-400">last seen</p>
          </div>
        </div>

        {/* first seen + heartbeat */}
        <div className="mt-2 flex items-center gap-4 text-[10px] text-violet-400">
          {c.first_seen && <span>first {fmtAgo(c.first_seen)}</span>}
          {c.heartbeat_at && <span>heartbeat {fmtAgo(c.heartbeat_at)}</span>}
        </div>
      </div>
    </div>
  );
}

function MiniKpi({ label, value, tone, sub }) {
  // One hue family, so the four tiles are separated by tint rather than hue.
  const tones = {
    calm: "text-violet-300",
    info: "text-purple-300",
    brand: "text-fuchsia-400",
    alert: "text-pink-400",
  };
  return (
    <div className="glass px-4 py-3">
      <p className="eyebrow">{label}</p>
      <p className={`mono mt-1 text-[22px] font-bold ${tones[tone] || "text-slate-100"}`}>{value.toLocaleString()}</p>
      {sub && <p className="mono mt-1 text-[11px] text-violet-300">{sub}</p>}
    </div>
  );
}

function LiveBadgeInline({ online, total }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-violet-600/30 bg-violet-600/10 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-violet-300">
      <span className="inline-block h-1.5 w-1.5 rounded-full bg-violet-500 pulse-dot-calm" />
      {online}/{total} online
    </span>
  );
}
