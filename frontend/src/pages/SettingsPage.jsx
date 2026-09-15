import React, { useEffect, useState } from "react";
import { changePassword, getAudit, getStorageStats, setRetention } from "../lib/api";
import { PageHeader, PlainBadge } from "../components/ui";

const VALID = [1, 7, 30, 90, 365, 0];

function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}

export default function SettingsPage() {
  const [storage, setStorage] = useState(null);
  const [days, setDays] = useState(30);
  const [pruneNow, setPruneNow] = useState(false);
  const [retentMsg, setRetentMsg] = useState(null);
  const [retentErr, setRetentErr] = useState(null);
  const [busy, setBusy] = useState(false);

  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pwMsg, setPwMsg] = useState(null);
  const [pwErr, setPwErr] = useState(null);
  const [pwBusy, setPwBusy] = useState(false);

  const [audit, setAudit] = useState([]);

  const refreshStorage = () =>
    getStorageStats().then((s) => { setStorage(s); setDays(s.retention_days); }).catch(() => {});

  useEffect(() => {
    refreshStorage();
    getAudit(100).then((d) => setAudit(d.entries || [])).catch(() => {});
  }, []);

  const applyRetention = async () => {
    setBusy(true); setRetentMsg(null); setRetentErr(null);
    try {
      const r = await setRetention(days, pruneNow);
      setRetentMsg(`Retention set to ${r.retention_days} days${r.events != null ? ` — pruned ${r.events} events, ${r.raw_records} raw records now` : ""}.`);
      refreshStorage();
    } catch (e) {
      setRetentErr(e.response?.data?.detail || e.message);
    } finally {
      setBusy(false);
    }
  };

  const submitPassword = async (e) => {
    e.preventDefault();
    setPwMsg(null); setPwErr(null);
    if (next.length < 6) { setPwErr("New password must be at least 6 characters."); return; }
    if (next !== confirm) { setPwErr("New password and confirmation do not match."); return; }
    setPwBusy(true);
    try {
      await changePassword(cur, next);
      setPwMsg("Password rotated. Other sessions stay valid until their token expires.");
      setCur(""); setNext(""); setConfirm("");
    } catch (err) {
      setPwErr(err.response?.data?.detail || err.message);
    } finally {
      setPwBusy(false);
    }
  };

  const session = decodeSession();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="admin · storage · audit"
        title="Settings & admin"
        sub="Retention policy, your sign-in credentials, and the trail of privileged actions — all recorded in the audit store."
        actions={<PlainBadge cls="!text-cyan-300">phase-2 console</PlainBadge>}
      />

      <div className="grid gap-6 xl:grid-cols-2">
        {/* -------------------------------------------- storage & retention */}
        <section className="glass overflow-hidden anim-fadeup">
          <div className="flex items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
            <p className="mono text-[11px] tracking-widest text-slate-500">storage :: event store</p>
            <PlainBadge>retention {storage ? `${storage.retention_days}d` : "…"}</PlainBadge>
          </div>
          <div className="p-5">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Stat value={storage ? storage.events.toLocaleString() : "…"} label="events stored" />
              <Stat value={storage ? storage.raw_records.toLocaleString() : "…"} label="raw records" />
              <Stat value={storage ? fmtBytes(storage.event_db_bytes) : "…"} label="event db" />
              <Stat value={storage ? fmtBytes(storage.raw_store_bytes) : "…"} label="raw store" />
            </div>
            {storage?.cutoff && (
              <p className="mono mt-3 text-[10px] text-slate-600">
                prune cutoff: keeping events newer than {storage.cutoff}
              </p>
            )}

            <p className="eyebrow mb-2 mt-5">Retention policy</p>
            <div className="flex flex-wrap items-center gap-2">
              {VALID.map((d) => (
                <button
                  key={d}
                  onClick={() => setDays(d)}
                  className={`chip mono ${days === d ? "chip-on" : ""}`}
                >
                  {d === 0 ? "keep all" : d === 1 ? "1 day" : `${d} days`}
                </button>
              ))}
            </div>
            <label className="mt-3 flex items-center gap-2 text-[12px] text-slate-400">
              <input type="checkbox" checked={pruneNow} onChange={(e) => setPruneNow(e.target.checked)} className="accent-emerald-400" />
              apply immediately (prune now)
            </label>
            <div className="mt-4 flex items-center gap-3">
              <button onClick={applyRetention} disabled={busy || !storage} className="btn-primary mono !px-4 !py-2 text-[11px]">
                {busy ? "APPLYING…" : "APPLY RETENTION"}
              </button>
              {retentMsg && <span className="mono text-[11px] text-emerald-400">{retentMsg}</span>}
              {retentErr && <span className="mono text-[11px] text-rose-400">✗ {retentErr}</span>}
            </div>
          </div>
        </section>

        {/* -------------------------------------------- password change */}
        <section className="glass overflow-hidden anim-fadeup" style={{ animationDelay: "60ms" }}>
          <div className="flex items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
            <p className="mono text-[11px] tracking-widest text-slate-500">identity :: credentials</p>
            <PlainBadge>{session.role || "…"}</PlainBadge>
          </div>
          <form onSubmit={submitPassword} className="space-y-4 p-5">
            <Field label="current password">
              <input type="password" value={cur} onChange={(e) => setCur(e.target.value)} className="field mono w-full px-3 py-2" autoComplete="current-password" />
            </Field>
            <Field label="new password">
              <input type="password" value={next} onChange={(e) => setNext(e.target.value)} className="field mono w-full px-3 py-2" autoComplete="new-password" />
            </Field>
            <Field label="confirm new password">
              <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} className="field mono w-full px-3 py-2" autoComplete="new-password" />
            </Field>
            {pwMsg && <p className="mono text-[11px] text-emerald-400">✓ {pwMsg}</p>}
            {pwErr && <p className="mono text-[11px] text-rose-400">✗ {pwErr}</p>}
            <button type="submit" disabled={pwBusy} className="btn-primary mono !px-4 !py-2 text-[11px]">
              {pwBusy ? "ROTATING…" : "CHANGE PASSWORD"}
            </button>
          </form>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-white/5 px-5 py-3 text-[11px] text-slate-500">
            <span>signed in as <span className="mono text-slate-300">{session.username}</span></span>
            {session.remaining ? (
              <span className="mono">session expires in {session.remaining}</span>
            ) : (
              <span className="mono">session expiry from token</span>
            )}
            <span className="text-slate-600">JWT-secured · rotations recorded to audit</span>
          </div>
        </section>
      </div>

      {/* ------------------------------------------------ audit trail */}
      <section className="glass overflow-hidden anim-fadeup" style={{ animationDelay: "120ms" }}>
        <div className="flex items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
          <p className="mono text-[11px] tracking-widest text-slate-500">audit trail :: newest first</p>
          <PlainBadge>{audit.length} entries</PlainBadge>
        </div>
        {audit.length === 0 ? (
          <p className="px-5 py-6 text-center text-[12px] text-slate-500">
            No privileged actions recorded yet — logins, ingests, token changes and retention edits will appear here.
          </p>
        ) : (
          <div className="terminal max-h-[18rem] overflow-y-auto p-3">
            {audit.map((a, i) => (
              <div key={i} className="flex gap-3 border-b border-white/[0.04] px-2 py-1.5 text-[11px]">
                <span className="mono shrink-0 text-slate-600">{a.ts.replace("T", " ").slice(0, 19)}</span>
                <span className="mono w-32 shrink-0 truncate text-slate-400">{a.actor}</span>
                <span className="mono shrink-0 text-emerald-300/90">{a.action}</span>
                <span className="min-w-0 flex-1 truncate text-slate-500" title={a.detail}>{a.detail}</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function Stat({ value, label }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
      <p className="text-grad-emerald text-xl font-bold leading-none mono">{value}</p>
      <p className="mono mt-1.5 text-[9px] uppercase tracking-widest text-slate-500">{label}</p>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label className="block">
      <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-slate-500">{label}</span>
      {children}
    </label>
  );
}

function decodeSession() {
  try {
    const raw = localStorage.getItem("trinetra_token") || "";
    const payload = JSON.parse(atob(raw.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    const remaining = Math.max(0, Math.floor((payload.exp || 0) - Date.now() / 1000));
    const h = Math.floor(remaining / 3600);
    const m = Math.floor((remaining % 3600) / 60);
    return {
      username: payload.sub,
      role: payload.role,
      remaining: remaining > 0 ? `${h}h ${m}m` : "expired",
    };
  } catch {
    return {};
  }
}