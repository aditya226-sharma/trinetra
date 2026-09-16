import React, { useEffect, useState } from "react";
import { getClients, getAgents, mintAgent, revokeAgent } from "../lib/api";
import { PageHeader, GlassCard, Empty, PlainBadge, PulseDot } from "../components/ui";

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

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export default function FleetPage({ role }) {
  const [clients, setClients] = useState([]);
  const [agents, setAgents] = useState([]);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);
  const [mintLabel, setMintLabel] = useState("");
  const [mintClient, setMintClient] = useState("");
  const canMint = role === "admin";

  const loadAgents = () => getAgents().then((d) => setAgents(d.agents || [])).catch(() => {});

  useEffect(() => {
    Promise.all([getClients(), getAgents()])
      .then(([c, a]) => {
        setClients(c.clients || []);
        setAgents(a.agents || []);
      })
      .catch((e) => setError(e.message));
  }, []);

  const doMint = async () => {
    setError(null);
    setNotice(null);
    try {
      const res = await mintAgent(mintLabel, mintClient);
      setNotice(`Token minted: ${res.token_id}${res.client_id ? ` → bound to ${res.client_id}` : " (unbound)"}`);
      setMintLabel("");
      setMintClient("");
      loadAgents();
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    }
  };

  const doRevoke = async (tokenId) => {
    setError(null);
    setNotice(null);
    if (!window.confirm(`Revoke token ${tokenId}?\nThis disables that agent immediately.`)) return;
    try {
      await revokeAgent(tokenId);
      setNotice(`Token ${tokenId} revoked`);
      loadAgents();
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    }
  };

  const byClient = new Map(clients.map((c) => [c.client_id, c]));

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations · fleet + credentials"
        title="Fleet"
        sub="Live client registry with heartbeat status and the minted agent-token inventory — bind, track, and revoke per-machine credentials."
        actions={<PlainBadge cls="uppercase">{clients.length} clients · {agents.length} tokens</PlainBadge>}
      />

      {error && <div className="text-sm text-rose-400">{error}</div>}
      {notice && <div className="text-sm text-emerald-400">{notice}</div>}

      <GlassCard title="Agent tokens" right={<PlainBadge>mint · revoke</PlainBadge>}>
        {canMint && (
        <div className="mb-5 grid gap-3 sm:grid-cols-[1fr_1fr_auto]">
          <input
            value={mintLabel}
            onChange={(e) => setMintLabel(e.target.value)}
            placeholder="label, e.g. vpn-gw-beta"
            className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-[12.5px] outline-none placeholder:text-slate-600 focus:border-emerald-500/40"
          />
          <input
            value={mintClient}
            onChange={(e) => setMintClient(e.target.value)}
            placeholder="client_id (pre-bind, optional)"
            className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-[12.5px] outline-none placeholder:text-slate-600 focus:border-emerald-500/40"
          />
          <button
            onClick={doMint}
            disabled={!mintLabel.trim() && !mintClient.trim()}
            className="rounded-xl border border-emerald-500/40 bg-emerald-500/15 px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-emerald-300 hover:bg-emerald-500/25 disabled:opacity-40"
          >
            Mint token
          </button>
        </div>
        )}

        {agents.length === 0 ? (
          <Empty title="No agent tokens" hint="Mint a per-machine token above; agents authenticate with X-Agent-Token." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="eyebrow !text-[10px]">
                  <th className="pb-2 pr-3">Token</th>
                  <th className="pb-2 pr-3">Label</th>
                  <th className="pb-2 pr-3">Bound client</th>
                  <th className="pb-2 pr-3">Last used</th>
                  <th className="pb-2 pr-3">State</th>
                  <th className="pb-2"></th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => {
                  const cl = a.client_id ? byClient.get(a.client_id) : null;
                  return (
                    <tr key={a.token_id} className="border-t border-white/5">
                      <td className="py-2.5 pr-3 mono text-slate-300">{a.token_id}</td>
                      <td className="py-2.5 pr-3 text-slate-200">{a.label || "—"}</td>
                      <td className="py-2.5 pr-3">
                        {a.client_id ? (
                          <span className="mono text-emerald-300">{a.client_id}</span>
                        ) : (
                          <span className="text-slate-500">unbound</span>
                        )}
                        {cl && (
                          <span className="ml-1.5 text-[10px] text-slate-500">
                            · {cl.status === "online" ? <span className="text-emerald-400">online</span> : "offline"}
                            {a.enabled ? "" : " · disabled"}
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 pr-3 text-slate-400">{fmtAgo(a.last_used)}</td>
                      <td className="py-2.5 pr-3">
                        {a.enabled ? (
                          <PulseDot color="bg-emerald-400" cls="pulse-dot-green" />
                        ) : (
                          <span className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[10px] uppercase text-rose-300">revoked</span>
                        )}
                      </td>
                      <td className="py-2.5 text-right">
                        {a.enabled && canMint && (
                          <button
                            onClick={() => doRevoke(a.token_id)}
                            className="rounded-lg border border-rose-500/30 px-2.5 py-1 text-[10px] uppercase tracking-wider text-rose-300 hover:bg-rose-500/15"
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </GlassCard>

      <GlassCard title="Client registry" right={<PlainBadge>heartbeats</PlainBadge>}>
        {clients.length === 0 ? (
          <Empty title="No clients yet" hint="Agents will appear once they heartbeat or post events." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="eyebrow !text-[10px]">
                  <th className="pb-2 pr-3"></th>
                  <th className="pb-2 pr-3">Client</th>
                  <th className="pb-2 pr-3">Platform</th>
                  <th className="pb-2 pr-3">Source</th>
                  <th className="pb-2 pr-3">Events</th>
                  <th className="pb-2 pr-3">Last seen</th>
                  <th className="pb-2 pr-3">Token</th>
                </tr>
              </thead>
              <tbody>
                {clients.map((c) => (
                  <tr key={c.client_id} className="border-t border-white/5">
                    <td className="py-2.5 pr-3">
                      {c.status === "online" ? (
                        <span className="inline-block h-2 w-2 rounded-full bg-emerald-400 pulse-dot-green" />
                      ) : (
                        <span className="inline-block h-2 w-2 rounded-full bg-slate-600" />
                      )}
                    </td>
                    <td className="py-2.5 pr-3">
                      <span className="mono text-slate-200">{c.client_id}</span>
                      {c.hostname && c.hostname !== c.client_id && (
                        <span className="ml-1.5 text-[10px] text-slate-500">({c.hostname})</span>
                      )}
                    </td>
                    <td className="py-2.5 pr-3 text-slate-400">{c.platform || "—"}</td>
                    <td className="py-2.5 pr-3 text-slate-400">{(c.source_types || []).join(", ") || "—"}</td>
                    <td className="py-2.5 pr-3 mono text-slate-300">
                      {(c.events ?? 0).toLocaleString()}
                      {c.events_recent > 0 && (
                        <span className="ml-1.5 text-[10px] text-emerald-400">+{c.events_recent} /5m</span>
                      )}
                    </td>
                    <td className="py-2.5 pr-3 text-slate-400">{fmtAgo(c.last_seen)}</td>
                    <td className="py-2.5 pr-3">
                      {c.token_id ? (
                        <span className="mono text-[10.5px] text-slate-500">{c.token_id}</span>
                      ) : (
                        <span className="text-[10px] text-amber-400/80 uppercase">shared</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </GlassCard>
    </div>
  );
}