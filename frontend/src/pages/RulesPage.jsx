import React, { useEffect, useState } from "react";
import { createRule, deleteRule, getRules, toggleRule, updateRule } from "../lib/api";
import { PageHeader, PlainBadge, Empty, CodeBlock } from "../components/ui";

const OPS = ["eq", "neq", "contains", "regex"];
const FIELDS = ["severity", "source_type", "category", "client_id", "client_ip", "message", "fields.user", "fields.host", "fields.src_ip", "fields.dst_host", "fields.port", "fields.action", "fields.channel"];
const SEV_FLORS = ["info", "warning", "error", "critical"];

const BLANK = { name: "", description: "", source_types: [], categories: [], min_severity: "warning", action: "alert", match: [{ field: "severity", op: "eq", value: "error" }], enabled: true };

export default function RulesPage({ role }) {
  const isAdmin = role === "admin";
  const [rules, setRules] = useState([]);
  const [form, setForm] = useState(BLANK);
  const [editingId, setEditingId] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  const refresh = () => getRules().then((d) => setRules(d.rules)).catch((e) => setErr(e.message));
  useEffect(() => { refresh(); }, []);

  const setCond = (idx, patch) => {
    const match = form.match.map((c, i) => (i === idx ? { ...c, ...patch } : c));
    setForm((f) => ({ ...f, match }));
  };

  const save = async (e) => {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      if (editingId) await updateRule(editingId, form);
      else await createRule(form);
      setForm(BLANK); setEditingId(null);
      refresh();
    } catch (ex) {
      setErr(ex.response?.data?.detail || ex.message);
    } finally {
      setBusy(false);
    }
  };

  const startEdit = (r) => {
    setEditingId(r.id);
    setForm({ ...r, match: (r.match || []).map((c) => ({ ...c })) });
    setErr(null);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const toggle = async (id, enabled) => {
    try { await toggleRule(id, !enabled); refresh(); } catch (ex) { setErr(ex.response?.data?.detail || ex.message); }
  };

  const remove = async (id) => {
    if (!window.confirm("Delete this rule?")) return;
    try { await deleteRule(id); if (editingId === id) { setEditingId(null); setForm(BLANK); } refresh(); }
    catch (ex) { setErr(ex.response?.data?.detail || ex.message); }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="soc · detection rules"
        title="Rules editor"
        sub="Write signature conditions over the normalized UES event — every match becomes an alert case tagged custom::<rule>."
        actions={<PlainBadge cls="!text-violet-300">{rules.length} rules</PlainBadge>}
      />

      {!isAdmin && (
        <div className="rounded-xl border border-white/5 bg-white/[0.02] px-4 py-3 text-[12px] text-violet-200 anim-fadeup">
          Read-only view — <span className="mono text-slate-200">admins</span> enable, edit, and delete rules.
        </div>
      )}

      {/* editor (admin only) */}
      {isAdmin && (
      <form onSubmit={save} className="glass space-y-4 p-5 anim-fadeup">
        <div className="flex flex-wrap items-end gap-3">
          <label className="block min-w-[220px] flex-1">
            <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-violet-300">rule name</span>
            <input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="e.g. repeated failed logins" className="field mono w-full px-3 py-2" />
          </label>
          <label className="block">
            <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-violet-300">min severity</span>
            <select value={form.min_severity} onChange={(e) => setForm((f) => ({ ...f, min_severity: e.target.value }))} className="field mono px-3 py-2">
              {SEV_FLORS.map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
          <label className="block">
            <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-violet-300">action</span>
            <select value={form.action} onChange={(e) => setForm((f) => ({ ...f, action: e.target.value }))} className="field mono px-3 py-2">
              <option value="alert">alert (+ deliver)</option>
              <option value="notify">case only</option>
            </select>
          </label>
        </div>
        <label className="block">
          <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-violet-300">description</span>
          <input value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} className="field w-full px-3 py-2" />
        </label>

        <div>
          <p className="eyebrow mb-2">Match conditions (all must hold)</p>
          <div className="space-y-2">
            {form.match.map((c, idx) => (
              <div key={idx} className="flex flex-wrap items-center gap-2">
                <select value={c.field} onChange={(e) => setCond(idx, { field: e.target.value })} className="field mono px-3 py-2">
                  {FIELDS.concat([c.field]).filter((f, i, a) => a.indexOf(f) === i).map((f) => <option key={f} value={f}>{f}</option>)}
                </select>
                <select value={c.op} onChange={(e) => setCond(idx, { op: e.target.value })} className="field mono px-3 py-2">
                  {OPS.map((o) => <option key={o}>{o}</option>)}
                </select>
                <input value={c.value} onChange={(e) => setCond(idx, { value: e.target.value })} placeholder="value" className="field mono w-44 px-3 py-2" />
                <button type="button" onClick={() => setForm((f) => ({ ...f, match: f.match.filter((_, i) => i !== idx) }))} className="mono text-[11px] text-pink-500 hover:text-pink-300">✕</button>
              </div>
            ))}
          </div>
          <button type="button" onClick={() => setForm((f) => ({ ...f, match: [...f.match, { field: "message", op: "contains", value: "" }] }))} className="btn-ghost mono mt-2 !px-3 !py-1.5 text-[11px]">
            + condition
          </button>
        </div>

        <div className="flex items-center gap-3 border-t border-white/5 pt-3">
          <button type="submit" disabled={busy || !form.name.trim()} className="btn-primary mono !px-4 !py-2 text-[11px]">
            {busy ? "SAVING…" : editingId ? "UPDATE RULE" : "CREATE RULE"}
          </button>
          {editingId && (
            <button type="button" onClick={() => { setEditingId(null); setForm(BLANK); }} className="btn-ghost mono !px-3 !py-2 text-[11px]">
              cancel edit
            </button>
          )}
          {err && <span className="mono text-[11px] text-pink-500">✗ {err}</span>}
        </div>
      </form>
      )}

      {/* rules table */}
      {rules.length === 0 ? (
        <Empty title="No rules yet" hint="Create a rule above — enabled rules evaluate every normalized event." />
      ) : (
        <div className="glass overflow-hidden anim-fadeup">
          <div className="flex items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
            <p className="mono text-[11px] tracking-widest text-violet-300">rules :: {rules.length} configured</p>
          </div>
          <div className="divide-y divide-white/[0.04]">
            {rules.map((r) => (
              <div key={r.id} className={`flex flex-col gap-2 px-4 py-3 ${r.enabled ? "" : "opacity-60"}`}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="mono text-[13px] font-semibold text-slate-100">{r.name}</span>
                  <PlainBadge cls="!text-purple-300">custom::{r.id}</PlainBadge>
                  <PlainBadge>min {r.min_severity}</PlainBadge>
                  <PlainBadge cls="!text-violet-200">{r.action}</PlainBadge>
                  {r.categories?.length > 0 && <PlainBadge cls="!text-violet-300">{r.categories.join("/")}</PlainBadge>}
                  <div className="ml-auto flex items-center gap-2">
                    {isAdmin && (
                      <>
                        <button
                          onClick={() => toggle(r.id, r.enabled)}
                          className={`chip mono !px-2 !py-1 text-[10px] ${r.enabled ? "chip-on" : ""}`}
                        >
                          {r.enabled ? "ENABLED" : "DISABLED"}
                        </button>
                        <button onClick={() => startEdit(r)} className="btn-ghost mono !px-3 !py-1.5 text-[10.5px]">edit</button>
                        <button onClick={() => remove(r.id)} className="mono text-[11px] text-pink-500 hover:text-pink-300">✕</button>
                      </>
                    )}
                  </div>
                </div>
                {r.description && <p className="text-[11px] text-violet-300">{r.description}</p>}
                <details className="text-[11px] text-violet-300">
                  <summary className="eyebrow cursor-pointer">match conditions</summary>
                  <CodeBlock maxH="max-h-40">{JSON.stringify(r.match || [], null, 2)}</CodeBlock>
                </details>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}