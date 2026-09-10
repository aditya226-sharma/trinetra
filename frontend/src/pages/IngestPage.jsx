import React, { useEffect, useState } from "react";
import { ingestLines, getClients, searchEvents } from "../lib/api";
import { Card, SeverityBadge } from "../components/ui";

const SOURCES = ["syslog", "cef", "json", "csv", "netflow", "windows"];
const SAMPLES = {
  syslog: "<134>Sep 10 09:00:01 web01 sshd: Failed password for invalid user root from 203.0.113.9 port 51122 ssh2",
  cef: "CEF:0|Fortinet|FortiGate|v7.4.0|0001|IPS:ET RULE|5|src=203.0.113.9 dst=10.10.1.20 spt=51234 dpt=4444 proto=tcp act=detect",
  json: '{"ts": "Sep 10 09:00:01", "src": "10.10.1.20", "dst": "198.51.100.9", "proto": "tcp", "sport": 47777, "dport": 443, "pkts": 3, "bytes": 2100, "flags": "SA"}',
  netflow: "Sep 10 09:00:01\t10.10.1.20\t198.51.100.9\ttcp\t47777\t443\t3\t2100\tSA",
  windows: "Level=3 Provider=Microsoft-Windows-Security-Auditing EventID=4625 Computer=WIN-FW1 Account Name=admin",
  csv: "Sep 10 09:00:01,203.0.113.9,10.10.1.20,tcp,51234,4444,5,800,S",
};

export default function IngestPage() {
  const [source, setSource] = useState("syslog");
  const [clientId, setClientId] = useState("");
  const [host, setHost] = useState("");
  const [lines, setLines] = useState("");
  const [knownClients, setKnownClients] = useState([]);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [sending, setSending] = useState(false);
  const [stored, setStored] = useState(0);

  const refreshStored = () =>
    searchEvents({ limit: 1 })
      .then((d) => setStored(d.total))
      .catch(() => {});

  useEffect(() => {
    refreshStored();
    getClients()
      .then((d) => setKnownClients(d.clients || []))
      .catch(() => {});
  }, []);

  const submit = async () => {
    setSending(true);
    setError(null);
    try {
      const parsed = lines
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((raw) => ({ raw, source, client_id: clientId, host_hint: host }));
      if (parsed.length === 0) {
        setError("Paste at least one raw log line.");
        setSending(false);
        return;
      }
      const { data } = await ingestLines(parsed);
      setResult(data);
      refreshStored();
      setLines("");
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    } finally {
      setSending(false);
    }
  };

  const sample = () =>
    setLines(
      Array.from({ length: 3 }, (_, i) => SAMPLES[source]).join("\n"),
    );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Ingest logs</h1>
        <p className="text-sm text-slate-400">
          Feed real logs into the ULPF pipeline — normalize → dedup → modules →
          analyzer. Everything lands in the event store and graph immediately.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1fr_360px]">
        <Card title="New ingest">
          <div className="grid gap-4 sm:grid-cols-3">
            <label className="block">
              <span className="mb-1 block text-xs text-slate-500">Source format</span>
              <select
                value={source}
                onChange={(e) => setSource(e.target.value)}
                className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm outline-none focus:border-emerald-500"
              >
                {SOURCES.map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-slate-500">Client</span>
              <input
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                list="client-list"
                placeholder="e.g. web01"
                className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm outline-none focus:border-emerald-500"
              />
              <datalist id="client-list">
                {knownClients.map((c) => (
                  <option key={c.client_id} value={c.client_id} />
                ))}
              </datalist>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-slate-500">Host hint</span>
              <input
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="reporter hostname"
                className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm outline-none focus:border-emerald-500"
              />
            </label>
          </div>

          <textarea
            value={lines}
            onChange={(e) => setLines(e.target.value)}
            rows={10}
            placeholder="One raw log line per row — paste syslog lines, CEF events, netflow rows, JSON objects…"
            className="mt-4 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-emerald-500"
          />

          <div className="mt-4 flex items-center gap-3">
            <button
              onClick={submit}
              disabled={sending}
              className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-60"
            >
              {sending ? "Processing…" : "Ingest"}
            </button>
            <button
              onClick={sample}
              className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:border-slate-500"
            >
              Insert sample lines
            </button>
            <span className="text-xs text-slate-500">
              {stored} events in store
            </span>
          </div>
          {error && <div className="mt-3 text-sm text-red-400">{error}</div>}
        </Card>

        <Card title="Pipeline result">
          {!result ? (
            <p className="text-sm text-slate-500">
              Ingested lines are parsed per the selected format, deduplicated by
              fingerprint, run through Module A (flows), wired into the graph,
              and gated through the analyzer — alerts from this batch appear
              here and on the Alerts page.
            </p>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3 text-center">
                <div className="rounded-lg bg-slate-950 p-3">
                  <p className="text-2xl font-bold text-emerald-400">{result.accepted}</p>
                  <p className="text-xs text-slate-500">accepted</p>
                </div>
                <div className="rounded-lg bg-slate-950 p-3">
                  <p className="text-2xl font-bold text-red-400">{result.failed}</p>
                  <p className="text-xs text-slate-500">failed</p>
                </div>
              </div>
              <p className="text-xs text-slate-500">
                {result.total} events now in store · {result.alerts.length} new alerts
              </p>
              {result.alerts.length > 0 && (
                <div className="space-y-2">
                  {[...result.alerts].reverse().map((a, i) => (
                    <div key={i} className="rounded-lg bg-slate-950 p-2 text-xs">
                      {typeof a === "string" ? (
                        <span className="text-slate-300">{a}</span>
                      ) : (
                        <span className="flex items-center gap-2">
                          <SeverityBadge severity={a.severity || "high"} />
                          <span className="font-mono text-slate-200">{a.threat_class}</span>
                          <span className="text-slate-500">conf {a.confidence}</span>
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}