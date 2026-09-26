import React, { useEffect, useState } from "react";
import { changePassword, deleteUser, getAudit, getCollectors, getNotifications, getStorageStats, getUsers, registerUser, runDigest, saveNotifications, setCollectors, setRetention, testNotifications } from "../lib/api";
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

  // collectors
  const [collectors, setCollectorsState] = useState(null);
  const [syslogEnabled, setSyslogEnabled] = useState(false);
  const [syslogPort, setSyslogPort] = useState(1514);
  const [tailEndpoint, setTailEndpoint] = useState("");
  const [tailingPaths, setTailingPaths] = useState([]);
  const [demoEnabled, setDemoEnabled] = useState(false);
  const [demoDelay, setDemoDelay] = useState(300);
  const [colMsg, setColMsg] = useState(null);
  const [colErr, setColErr] = useState(null);
  const [colBusy, setColBusy] = useState(false);

  // notifications / delivery
  const [notif, setNotif] = useState(null);
  const [notifMsg, setNotifMsg] = useState(null);
  const [notifErr, setNotifErr] = useState(null);
  const [notifBusy, setNotifBusy] = useState(false);
  const [testBusy, setTestBusy] = useState(false);
  const [digestBusy, setDigestBusy] = useState(false);

  // users & roles (RBAC)
  const [roster, setRoster] = useState(null);
  const [uName, setUName] = useState("");
  const [uPass, setUPass] = useState("");
  const [uRole, setURole] = useState("analyst");
  const [uMsg, setUMsg] = useState(null);
  const [uErr, setUErr] = useState(null);
  const [uBusy, setUBusy] = useState(false);

  const refreshRoster = () =>
    getUsers().then((d) => { setRoster(d.users || []); setUErr(null); }).catch(() => {});

  const refreshCollectors = () =>
    getCollectors().then(({ config, running }) => {
      setCollectorsState(running);
      setSyslogEnabled(Boolean(config.syslog?.enabled));
      setSyslogPort(config.syslog?.port || 1514);
      setTailingPaths((config.tailers || []).map((t) => t.path).filter(Boolean));
      setDemoEnabled(Boolean(config.demo?.enabled));
      setDemoDelay(config.demo?.replay_delay_s || 300);
    }).catch(() => {});

  const applyCollectors = async () => {
    setColBusy(true); setColMsg(null); setColErr(null);
    try {
      const patch = {
        syslog: { enabled: syslogEnabled, port: Number(syslogPort) || 1514 },
        tailers: tailingPaths.filter(Boolean).map((path) => ({ path, source: "file_log" })),
        demo: { enabled: demoEnabled, replay_delay_s: Math.max(5, Number(demoDelay) || 300) },
      };
      const r = await setCollectors(patch);
      setCollectorsState(r.running);
      setColMsg("Collectors reconfigured — threads restarted.");
      refreshStorage();
    } catch (e) {
      setColErr(e.response?.data?.detail || e.message);
    } finally {
      setColBusy(false);
    }
  };

  const refreshStorage = () =>
    getStorageStats().then((s) => { setStorage(s); setDays(s.retention_days); }).catch(() => {});

  const refreshNotif = () =>
    getNotifications().then((n) => { setNotif(n); setNotifErr(null); }).catch(() => {});

  useEffect(() => {
    refreshStorage();
    refreshCollectors();
    refreshNotif();
    refreshRoster();
    getAudit(100).then((d) => setAudit(d.entries || [])).catch(() => {});
  }, []);

  const applyNotif = async () => {
    setNotifBusy(true); setNotifMsg(null); setNotifErr(null);
    try {
      const patch = {
        enabled: notif.enabled,
        severity_min: notif.severity_min,
        email: {
          host: notif.email.host, port: Number(notif.email.port) || 587,
          sender: notif.email.sender, recipient: notif.email.recipient,
          username: notif.email.username, password: notif.email.password,
        },
        webhook: { url: notif.webhook.url, secret: notif.webhook.secret },
        digest: { enabled: notif.digest.enabled, hour_utc: Math.max(0, Math.min(23, Number(notif.digest.hour_utc) || 0)) },
      };
      const saved = await saveNotifications(patch);
      setNotif(saved);
      setNotifMsg("Delivery config saved — new alerts and the digest fan out from the next trigger.");
    } catch (e) {
      setNotifErr(e.response?.data?.detail || e.message);
    } finally {
      setNotifBusy(false);
    }
  };

  const sendTest = async () => {
    setTestBusy(true); setNotifMsg(null); setNotifErr(null);
    try {
      const r = await testNotifications();
      const summary = (r.results || [])
        .map((x) => `${x.transport}=${x.status}${x.http_status ? `(${x.http_status})` : ""}`)
        .join(" ");
      setNotifMsg(`Test dispatched — ${summary}.`);
    } catch (e) {
      setNotifErr(e.response?.data?.detail || e.message);
    } finally {
      setTestBusy(false);
    }
  };

  const sendDigest = async () => {
    setDigestBusy(true); setNotifMsg(null); setNotifErr(null);
    try {
      const r = await runDigest(true);
      setNotifMsg(`Digest sent — ${r.cases_in_window} cases in window (${(r.results || []).map((x) => `${x.transport}=${x.status}`).join(" ")}).`);
    } catch (e) {
      setNotifErr(e.response?.data?.detail || e.message);
    } finally {
      setDigestBusy(false);
    }
  };

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

  const createUser = async (e) => {
    e.preventDefault();
    if (!uName.trim() || uPass.length < 6) { setUErr("Username required and password min 6 chars."); return; }
    setUBusy(true); setUMsg(null); setUErr(null);
    try {
      await registerUser(uName.trim(), uPass, uRole);
      setUMsg(`Created ${uName.trim()} (${uRole}).`);
      setUName(""); setUPass("");
      refreshRoster();
    } catch (ex) {
      setUErr(ex.response?.data?.detail || ex.message);
    } finally {
      setUBusy(false);
    }
  };

  const handleDeleteUser = async (username) => {
    if (!window.confirm(`Delete account ${username}? This cannot be undone.`)) return;
    try {
      await deleteUser(username);
      setUMsg(`Deleted ${username}.`);
      refreshRoster();
    } catch (ex) {
      setUErr(ex.response?.data?.detail || ex.message);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="admin · storage · audit"
        title="Settings & admin"
        sub="Retention policy, your sign-in credentials, and the trail of privileged actions — all recorded in the audit store."
        actions={<PlainBadge cls="!text-violet-300">admin console</PlainBadge>}
      />

      {/* users & roles (RBAC) */}
      <section className="glass overflow-hidden anim-fadeup">
        <div className="flex items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
          <p className="mono text-[11px] tracking-widest text-violet-300">users &amp; roles :: rbac</p>
          <PlainBadge cls="!text-violet-300">{roster ? `${roster.length} accounts` : "…"}</PlainBadge>
        </div>
        <div className="p-5">
          <form onSubmit={createUser} className="flex flex-wrap items-end gap-3">
            <label className="block min-w-[160px] flex-1">
              <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-violet-300">username</span>
              <input value={uName} onChange={(e) => setUName(e.target.value)} placeholder="soc-analyst" className="field mono w-full px-3 py-2" />
            </label>
            <label className="block min-w-[160px] flex-1">
              <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-violet-300">password</span>
              <input value={uPass} onChange={(e) => setUPass(e.target.value)} type="password" placeholder="min 6 chars" className="field mono w-full px-3 py-2" />
            </label>
            <label className="block">
              <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-violet-300">role</span>
              <select value={uRole} onChange={(e) => setURole(e.target.value)} className="field mono px-3 py-2">
                <option value="analyst">analyst</option>
                <option value="admin">admin</option>
                <option value="viewer">viewer</option>
              </select>
            </label>
            <button type="submit" disabled={uBusy} className="btn-primary mono !px-4 !py-2 text-[11px]">
              {uBusy ? "CREATING…" : "CREATE USER"}
            </button>
            {uMsg && <span className="mono text-[11px] text-violet-500">✓ {uMsg}</span>}
            {uErr && <span className="mono text-[11px] text-pink-500">✗ {uErr}</span>}
          </form>

          <div className="mt-4 divide-y divide-white/[0.04]">
            {(roster || []).map((u) => (
              <div key={u.username} className="flex items-center gap-3 py-2.5">
                <span className="grid h-7 w-7 shrink-0 place-items-center rounded-full bg-violet-600/20 text-[11px] font-bold text-violet-300">
                  {(u.username || "?")[0]?.toUpperCase()}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="mono text-[13px] text-slate-100">{u.username}{u.username === session?.username && <span className="text-violet-300"> (you)</span>}</p>
                  <p className="mono text-[10px] text-violet-400">{u.created_at}</p>
                </div>
                <PlainBadge cls={u.role === "admin" ? "!text-violet-300" : u.role === "analyst" ? "!text-violet-300" : "!text-violet-200"}>{u.role}</PlainBadge>
                {u.username !== session?.username && (
                  <button onClick={() => handleDeleteUser(u.username)} className="mono text-[11px] text-pink-500 hover:text-pink-300">✕</button>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-2">
        {/* -------------------------------------------- storage & retention */}
        <section className="glass overflow-hidden anim-fadeup">
          <div className="flex items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
            <p className="mono text-[11px] tracking-widest text-violet-300">storage :: event store</p>
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
              <p className="mono mt-3 text-[10px] text-violet-400">
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
            <label className="mt-3 flex items-center gap-2 text-[12px] text-violet-200">
              <input type="checkbox" checked={pruneNow} onChange={(e) => setPruneNow(e.target.checked)} className="accent-emerald-400" />
              apply immediately (prune now)
            </label>
            <div className="mt-4 flex items-center gap-3">
              <button onClick={applyRetention} disabled={busy || !storage} className="btn-primary mono !px-4 !py-2 text-[11px]">
                {busy ? "APPLYING…" : "APPLY RETENTION"}
              </button>
              {retentMsg && <span className="mono text-[11px] text-violet-500">{retentMsg}</span>}
              {retentErr && <span className="mono text-[11px] text-pink-500">✗ {retentErr}</span>}
            </div>
          </div>
        </section>

        {/* -------------------------------------------- password change */}
        <section className="glass overflow-hidden anim-fadeup" style={{ animationDelay: "60ms" }}>
          <div className="flex items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
            <p className="mono text-[11px] tracking-widest text-violet-300">identity :: credentials</p>
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
            {pwMsg && <p className="mono text-[11px] text-violet-500">✓ {pwMsg}</p>}
            {pwErr && <p className="mono text-[11px] text-pink-500">✗ {pwErr}</p>}
            <button type="submit" disabled={pwBusy} className="btn-primary mono !px-4 !py-2 text-[11px]">
              {pwBusy ? "ROTATING…" : "CHANGE PASSWORD"}
            </button>
          </form>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-white/5 px-5 py-3 text-[11px] text-violet-300">
            <span>signed in as <span className="mono text-slate-300">{session.username}</span></span>
            {session.remaining ? (
              <span className="mono">session expires in {session.remaining}</span>
            ) : (
              <span className="mono">session expiry from token</span>
            )}
            <span className="text-violet-400">JWT-secured · rotations recorded to audit</span>
          </div>
        </section>
      </div>

      {/* ------------------------------------------------ collectors */}
      <section className="glass overflow-hidden anim-fadeup" style={{ animationDelay: "90ms" }}>
        <div className="flex items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
          <p className="mono text-[11px] tracking-widest text-violet-300">collectors :: live sources</p>
          <div className="flex items-center gap-2">
            {collectors?.syslog_active && <PlainBadge cls="!text-violet-300">syslog :{collectors.syslog_port}</PlainBadge>}
            {collectors?.tailer_active && <PlainBadge cls="!text-violet-300">tail -f</PlainBadge>}
            {collectors?.demo_active && <PlainBadge cls="!text-purple-300">demo replay</PlainBadge>}
            {!collectors && <PlainBadge>…</PlainBadge>}
          </div>
        </div>
        <div className="grid gap-5 p-5 lg:grid-cols-3">
          {/* syslog */}
          <div className="space-y-3">
            <p className="eyebrow">Syslog UDP receiver</p>
            <label className="flex items-center gap-2 text-[12px] text-slate-300">
              <input
                type="checkbox"
                checked={syslogEnabled}
                onChange={(e) => setSyslogEnabled(e.target.checked)}
                className="accent-emerald-400"
              />
              listener enabled
            </label>
            <label className="block">
              <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-violet-300">port</span>
              <input
                value={syslogPort}
                disabled={!syslogEnabled}
                onChange={(e) => setSyslogPort(e.target.value)}
                className="field mono w-full px-3 py-2 disabled:opacity-40"
              />
            </label>
            <p className="text-[10.5px] leading-relaxed text-violet-300">
              RFC 3164/5424 datagrams over UDP, normalized then deduped like any other source.
            </p>
          </div>

          {/* tailers */}
          <div className="space-y-3">
            <p className="eyebrow">File tailers</p>
            <div className="flex gap-2">
              <input
                value={tailEndpoint}
                onChange={(e) => setTailEndpoint(e.target.value)}
                placeholder="/var/log/nginx/access.log"
                className="field mono w-full px-3 py-2"
              />
              <button
                onClick={() => {
                  const p = tailEndpoint.trim();
                  if (p && !tailingPaths.includes(p)) {
                    setTailingPaths((xs) => [...xs, p]);
                    setTailEndpoint("");
                  }
                }}
                className="btn-secondary mono !px-3 !py-2 text-[11px]"
              >
                ADD
              </button>
            </div>
            <div className="space-y-1.5">
              {tailingPaths.length === 0 && (
                <p className="text-[10.5px] text-violet-400">No files being followed.</p>
              )}
              {tailingPaths.map((p) => (
                <div key={p} className="flex items-center gap-2 rounded-lg border border-white/5 bg-white/[0.02] px-2.5 py-1.5">
                  <span className="mono min-w-0 flex-1 truncate text-[11px] text-slate-300">{p}</span>
                  <button
                    onClick={() => setTailingPaths((xs) => xs.filter((x) => x !== p))}
                    className="text-[11px] text-pink-500 hover:text-pink-300"
                  >
                    ✕
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* demo replay */}
          <div className="space-y-3">
            <p className="eyebrow">Demo replay</p>
            <label className="flex items-center gap-2 text-[12px] text-slate-300">
              <input
                type="checkbox"
                checked={demoEnabled}
                onChange={(e) => setDemoEnabled(e.target.checked)}
                className="accent-emerald-400"
              />
              replay demo corpus to the live pipeline
            </label>
            <label className="block">
              <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-violet-300">pause between passes (s)</span>
              <input
                value={demoDelay}
                onChange={(e) => setDemoDelay(e.target.value)}
                className="field mono w-full px-3 py-2"
              />
            </label>
            <p className="text-[10.5px] leading-relaxed text-violet-300">
              Cycles the bundled incident story with a quiet gap so dedup keeps the store healthy.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 border-t border-white/5 px-5 py-3">
          <button onClick={applyCollectors} disabled={colBusy} className="btn-primary mono !px-4 !py-2 text-[11px]">
            {colBusy ? "RESTARTING…" : "APPLY COLLECTORS"}
          </button>
          {colMsg && <span className="mono text-[11px] text-violet-500">✓ {colMsg}</span>}
          {colErr && <span className="mono text-[11px] text-pink-500">✗ {colErr}</span>}
        </div>
      </section>

      {/* ------------------------------------------------ notifications */}
      <section className="glass overflow-hidden anim-fadeup" style={{ animationDelay: "110ms" }}>
        <div className="flex items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
          <p className="mono text-[11px] tracking-widest text-violet-300">delivery :: alert fan-out · digest</p>
          <div className="flex items-center gap-2">
            {notif && <PlainBadge cls={notif.enabled ? "!text-violet-300" : "!text-violet-200"}>{notif.enabled ? "enabled" : "muted"}</PlainBadge>}
            {notif?.webhook?.url && <PlainBadge cls="!text-violet-300">webhook</PlainBadge>}
            {notif?.email?.host && <PlainBadge cls="!text-violet-300">smtp</PlainBadge>}
            {notif?.digest?.enabled && <PlainBadge cls="!text-purple-300">digest {notif.digest.hour_utc}:00z</PlainBadge>}
          </div>
        </div>
        {notif ? (
          <div className="p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
              <label className="flex items-center gap-2 text-[12px] text-slate-300">
                <input type="checkbox" checked={notif.enabled} onChange={(e) => setNotif((n) => ({ ...n, enabled: e.target.checked }))} className="accent-emerald-400" />
                fan-out enabled
              </label>
              <label className="flex items-center gap-2 text-[12px] text-slate-300">
                <span className="eyebrow">min severity</span>
                <select value={notif.severity_min} onChange={(e) => setNotif((n) => ({ ...n, severity_min: e.target.value }))} className="field mono px-3 py-1.5 text-[11px]">
                  {["info", "warning", "error", "critical"].map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </label>
              <label className="flex items-center gap-2 text-[12px] text-slate-300">
                <input type="checkbox" checked={notif.digest.enabled} onChange={(e) => setNotif((n) => ({ ...n, digest: { ...n.digest, enabled: e.target.checked } }))} className="accent-emerald-400" />
                daily digest
              </label>
              <label className="flex items-center gap-2 text-[12px] text-slate-300">
                <span className="eyebrow">UTC hour</span>
                <input type="number" min="0" max="23" value={notif.digest.hour_utc} onChange={(e) => setNotif((n) => ({ ...n, digest: { ...n.digest, hour_utc: e.target.value } }))} className="field mono w-16 px-2 py-1.5 text-[11px]" />
              </label>
            </div>

            <div className="mt-4 grid gap-4 lg:grid-cols-3">
              <div className="space-y-2">
                <p className="eyebrow">SMTP</p>
                <Field label="host"><input value={notif.email.host} onChange={(e) => setNotif((n) => ({ ...n, email: { ...n.email, host: e.target.value } }))} placeholder="smtp.example.com" className="field mono w-full px-3 py-1.5 text-[11px]" /></Field>
                <Field label="port"><input type="number" value={notif.email.port} onChange={(e) => setNotif((n) => ({ ...n, email: { ...n.email, port: e.target.value } }))} className="field mono w-full px-3 py-1.5 text-[11px]" /></Field>
                <Field label="sender"><input value={notif.email.sender} onChange={(e) => setNotif((n) => ({ ...n, email: { ...n.email, sender: e.target.value } }))} placeholder="trinetra@acme.io" className="field mono w-full px-3 py-1.5 text-[11px]" /></Field>
                <Field label="recipient"><input value={notif.email.recipient} onChange={(e) => setNotif((n) => ({ ...n, email: { ...n.email, recipient: e.target.value } }))} placeholder="soc@acme.io" className="field mono w-full px-3 py-1.5 text-[11px]" /></Field>
                <Field label="username / password"><input value={notif.email.username} onChange={(e) => setNotif((n) => ({ ...n, email: { ...n.email, username: e.target.value } }))} placeholder="username (optional)" className="field mono w-full px-3 py-1.5 text-[11px]" /><input value={notif.email.password} onChange={(e) => setNotif((n) => ({ ...n, email: { ...n.email, password: e.target.value } }))} type="password" placeholder="••••••••" className="field mono mt-1.5 w-full px-3 py-1.5 text-[11px]" /></Field>
              </div>
              <div className="space-y-2">
                <p className="eyebrow">Webhook</p>
                <Field label="endpoint URL"><input value={notif.webhook.url} onChange={(e) => setNotif((n) => ({ ...n, webhook: { ...n.webhook, url: e.target.value } }))} placeholder="https://alertflow.example.com/hook" className="field mono w-full px-3 py-1.5 text-[11px]" /></Field>
                <Field label="shared secret"><input value={notif.webhook.secret} onChange={(e) => setNotif((n) => ({ ...n, webhook: { ...n.webhook, secret: e.target.value } }))} type="password" placeholder="X-Trinetra-Secret" className="field mono w-full px-3 py-1.5 text-[11px]" /></Field>
                <p className="text-[10.5px] leading-relaxed text-violet-300">
                  POSTs a JSON envelope {"{type,severity,title,body}"} to the endpoint. Console logging is always on.
                </p>
              </div>
              <div className="flex flex-col justify-end gap-2">
                <button onClick={applyNotif} disabled={notifBusy} className="btn-primary mono !px-4 !py-2 text-[11px]">
                  {notifBusy ? "SAVING…" : "SAVE DELIVERY CONFIG"}
                </button>
                <button onClick={sendTest} disabled={testBusy} className="btn-secondary mono !px-4 !py-2 text-[11px]">
                  {testBusy ? "SENDING…" : "SEND TEST ALERT"}
                </button>
                <button onClick={sendDigest} disabled={digestBusy} className="btn-ghost mono !px-4 !py-2 text-[11px]">
                  {digestBusy ? "SENDING…" : "RUN DIGEST NOW"}
                </button>
                {notifMsg && <span className="mono text-[11px] text-violet-500">✓ {notifMsg}</span>}
                {notifErr && <span className="mono text-[11px] text-pink-500">✗ {notifErr}</span>}
              </div>
            </div>
          </div>
        ) : (
          <p className="px-5 py-6 text-center text-[12px] text-violet-300">Loading delivery config…</p>
        )}
      </section>

      {/* ------------------------------------------------ audit trail */}
      <section className="glass overflow-hidden anim-fadeup" style={{ animationDelay: "120ms" }}>
        <div className="flex items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
          <p className="mono text-[11px] tracking-widest text-violet-300">audit trail :: newest first</p>
          <PlainBadge>{audit.length} entries</PlainBadge>
        </div>
        {audit.length === 0 ? (
          <p className="px-5 py-6 text-center text-[12px] text-violet-300">
            No privileged actions recorded yet — logins, ingests, token changes and retention edits will appear here.
          </p>
        ) : (
          <div className="terminal max-h-[18rem] overflow-y-auto p-3">
            {audit.map((a, i) => (
              <div key={i} className="flex gap-3 border-b border-white/[0.04] px-2 py-1.5 text-[11px]">
                <span className="mono shrink-0 text-violet-400">{(a.ts || "").replace("T", " ").slice(0, 19)}</span>
                <span className="mono w-32 shrink-0 truncate text-violet-200">{a.actor}</span>
                <span className="mono shrink-0 text-violet-300/90">{a.action}</span>
                <span className="min-w-0 flex-1 truncate text-violet-300" title={a.detail}>{a.detail}</span>
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
      <p className="mono mt-1.5 text-[9px] uppercase tracking-widest text-violet-300">{label}</p>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label className="block">
      <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-violet-300">{label}</span>
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
      username: payload.sub || payload.username || payload.preferred_username || "unknown",
      role: payload.role || "viewer",
      remaining: remaining > 0 ? `${h}h ${m}m` : "expired",
    };
  } catch {
    return {};
  }
}