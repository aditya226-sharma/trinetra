import React, { useEffect, useState } from "react";
import { addWatchEntry, getWatchlist, removeWatchEntry, toggleWatchEntry } from "../lib/api";
import { PageHeader, PlainBadge, Empty } from "../components/ui";

const KINDS = ["ip", "client", "user", "domain", "asset"];

export default function WatchlistPage({ role }) {
  const isAdmin = role === "admin";
  const [tab, setTab] = useState("watchlist");
  const [entries, setEntries] = useState([]);
  const [kind, setKind] = useState("ip");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [msg, setMsg] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  const refresh = (list) =>
    getWatchlist(list || tab).then((d) => { setEntries(d.entries); setErr(null); }).catch((e) => setErr(e.message));

  useEffect(() => { refresh(); }, [tab]);

  const submit = async (e) => {
    e.preventDefault();
    if (!value.trim()) return;
    setBusy(true); setMsg(null); setErr(null);
    try {
      const r = await addWatchEntry(tab, kind, value.trim(), reason.trim());
      setMsg(`Added ${r.entry.kind} ${r.entry.value} → ${tab}.`);
      setValue(""); setReason("");
      refresh();
    } catch (ex) {
      setErr(ex.response?.data?.detail || ex.message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (k, v) => {
    try {
      await removeWatchEntry(tab, k, v);
      refresh();
    } catch (ex) {
      setErr(ex.response?.data?.detail || ex.message);
    }
  };

  const toggle = async (k, v, active) => {
    try {
      await toggleWatchEntry(tab, k, v, active);
      refresh();
    } catch (ex) {
      setErr(ex.response?.data?.detail || ex.message);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="soc · reference lists"
        title="Watchlist · blocklist"
        sub="Watch for high-value entities; block hostile ones outright. Matches rise as cases in the alert queue — block hits are critical and flag the stored event."
        actions={<PlainBadge cls="!text-emerald-300">{entries.length} entries</PlainBadge>}
      />

      <div className="flex items-center gap-2">
        {["watchlist", "blocklist"].map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`chip mono ${tab === t ? "chip-on" : ""}`}>
            {t}
          </button>
        ))}
      </div>

      <form onSubmit={submit} className="glass flex flex-wrap items-end gap-3 p-4 anim-fadeup">
        {!isAdmin && (
          <div className="w-full rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2 text-[12px] text-slate-400">
            Read-only view — <span className="mono text-slate-200">admins</span> maintain the reference lists.
          </div>
        )}
        {isAdmin && (<>
        <label className="block">
          <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-slate-500">entity kind</span>
          <select value={kind} onChange={(e) => setKind(e.target.value)} className="field mono px-3 py-2">
            {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
        </label>
        <label className="block min-w-[180px] flex-1">
          <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-slate-500">value</span>
          <input value={value} onChange={(e) => setValue(e.target.value)} placeholder={kind === "ip" ? "203.0.113.7" : "value"} className="field mono w-full px-3 py-2" />
        </label>
        <label className="block min-w-[200px] flex-1">
          <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-slate-500">reason</span>
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="why is this entity watched / blocked" className="field w-full px-3 py-2" />
        </label>
        <button type="submit" disabled={busy} className="btn-primary mono !px-4 !py-2 text-[11px]">
          {busy ? "ADDING…" : `ADD TO ${tab}`}
        </button>
        {msg && <span className="mono text-[11px] text-emerald-400">✓ {msg}</span>}
        {err && <span className="mono text-[11px] text-red-400">✗ {err}</span>}
        </>)}
      </form>

      {entries.length === 0 ? (
        <Empty title={`${tab} is empty`} hint="Add an entity above — it becomes live policy immediately." />
      ) : (
        <div className="glass overflow-hidden anim-fadeup">
          <div className="flex items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
            <p className="mono text-[11px] tracking-widest text-slate-500">{tab} :: {entries.length}</p>
          </div>
          <div className="divide-y divide-white/[0.04]">
            {entries.map((en, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-3">
                <span className="mono w-16 shrink-0 text-[10px] uppercase tracking-widest text-cyan-300">{en.kind}</span>
                <span className={`mono min-w-0 flex-1 truncate text-[13px] ${en.active ? "text-slate-100" : "text-slate-500 line-through"}`}>{en.value}</span>
                <span className="hidden max-w-[220px] truncate text-[11px] text-slate-500 lg:block" title={en.reason}>{en.reason || "—"}</span>
                <span className="mono hidden shrink-0 text-[10px] text-slate-600 md:block">{en.created_by}</span>
                {isAdmin && (<>
                  <button onClick={() => toggle(en.kind, en.value, !en.active)} className={`chip mono !px-2 !py-1 text-[10px] ${en.active ? "chip-on" : ""}`}>
                    {en.active ? "ON" : "OFF"}
                  </button>
                  <button onClick={() => remove(en.kind, en.value)} className="mono text-[11px] text-red-400 hover:text-red-300">✕</button>
                </>)}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}