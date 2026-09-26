import React, { useEffect, useRef, useState } from "react";
import { ingestLines, ingestBulkFile, getClients, searchEvents, getAnalytics } from "../lib/api";
import { PageHeader, LiveBadge, SeverityBadge, PlainBadge, Empty, SectionTitle } from "../components/ui";
import { Donut, Sparkline } from "../components/charts";

const SOURCES = ["syslog", "cef", "json", "csv", "netflow", "windows"];
const SAMPLES = {
  syslog: "<134>Sep 10 09:00:01 web01 sshd: Failed password for invalid user root from 203.0.113.9 port 51122 ssh2",
  cef: "CEF:0|Fortinet|FortiGate|v7.4.0|0001|IPS:ET RULE|5|src=203.0.113.9 dst=10.10.1.20 spt=51234 dpt=4444 proto=tcp act=detect",
  json: '{"ts": "Sep 10 09:00:01", "src": "10.10.1.20", "dst": "198.51.100.9", "proto": "tcp", "sport": 47777, "dport": 443, "pkts": 3, "bytes": 2100, "flags": "SA"}',
  netflow: "Sep 10 09:00:01\t10.10.1.20\t198.51.100.9\ttcp\t47777\t443\t3\t2100\tSA",
  windows: "Level=3 Provider=Microsoft-Windows-Security-Auditing EventID=4625 Computer=WIN-FW1 Account Name=admin",
  csv: "Sep 10 09:00:01,203.0.113.9,10.10.1.20,tcp,51234,4444,5,800,S",
};

const PIPELINE_STAGES = ["normalize", "dedup", "modules", "analyzer"];

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
  const [stage, setStage] = useState(-1);
  const stageRef = useRef(-1);

  const [bulkFile, setBulkFile] = useState(null);
  const [bulkSource, setBulkSource] = useState("");
  const [bulkResult, setBulkResult] = useState(null);
  const [bulkError, setBulkError] = useState(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  const fileRef = useRef(null);

  const [analytics, setAnalytics] = useState(null);

  const refreshStored = () =>
    searchEvents({ limit: 1 })
      .then((d) => setStored(d.total))
      .catch(() => {});

  const refreshAnalytics = () =>
    getAnalytics(48)
      .then(setAnalytics)
      .catch(() => {});

  useEffect(() => {
    refreshStored();
    getClients()
      .then((d) => setKnownClients(d.clients || []))
      .catch(() => {});
    refreshAnalytics();
  }, []);

  // drive the terminal stage animation during ingest
  useEffect(() => {
    if (!sending) return;
    stageRef.current = 0;
    setStage(0);
    const id = setInterval(() => {
      if (stageRef.current >= PIPELINE_STAGES.length - 1) {
        clearInterval(id);
        return;
      }
      stageRef.current += 1;
      setStage(stageRef.current);
    }, 260);
    return () => clearInterval(id);
  }, [sending]);

  const submit = async () => {
    setSending(true);
    setStage(0);
    setError(null);
    setResult(null);
    try {
      const parsed = lines
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((raw) => ({ raw, source, client_id: clientId, host_hint: host }));
      if (parsed.length === 0) {
        setError("Paste at least one raw log line.");
        setSending(false);
        setStage(-1);
        return;
      }
      const data = await ingestLines(parsed);
      setStage(PIPELINE_STAGES.length);
      setResult(data);
      refreshStored();
      refreshAnalytics();
      setLines("");
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
      setStage(-1);
    } finally {
      setTimeout(() => setSending(false), 400);
    }
  };

  const sample = () =>
    setLines(Array.from({ length: 3 }, (_, i) => SAMPLES[source]).join("\n"));

  const uploadBulk = async () => {
    if (!bulkFile) return;
    setBulkBusy(true);
    setBulkResult(null);
    setBulkError(null);
    try {
      const data = await ingestBulkFile(bulkFile, { source: bulkSource, clientId });
      setBulkResult(data);
      refreshStored();
      refreshAnalytics();
    } catch (e) {
      setBulkError(e.response?.data?.detail || e.message);
    } finally {
      setBulkBusy(false);
    }
  };

  const lineCount = lines.split("\n").filter((l) => l.trim()).length;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="ULP pipeline · edge interface"
        title="Live ingest"
        sub="Feed raw log lines straight into the pipeline — normalize → dedup → modules → analyzer in one shot. Everything lands in the store and graph immediately."
        actions={
          <>
            <span className="mono text-[11px] text-violet-300">{stored} events in store</span>
            <LiveBadge text="Port /api/ingest" />
          </>
        }
      />

      <div className="grid gap-6 xl:grid-cols-[1.5fr_1fr]">
        {/* ------------------------------------------------ terminal console */}
        <section className="glass overflow-hidden anim-fadeup">
          {/* terminal chrome */}
          <div className="flex items-center gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
            <span className="h-2.5 w-2.5 rounded-full bg-pink-500/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-purple-400/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-violet-500/80" />
            <p className="mono ml-3 text-[11px] tracking-widest text-violet-300">
              trinetra@{source} — ingest console
            </p>
          </div>

          <div className="terminal p-5">
            {/* source tabs */}
            <div className="mb-4 flex flex-wrap gap-1.5">
              {SOURCES.map((s) => (
                <button
                  key={s}
                  onClick={() => setSource(s)}
                  className={`mono rounded-md border px-2.5 py-1 text-[11px] transition ${
                    source === s
                      ? "border-violet-600/60 bg-violet-600/10 text-violet-300"
                      : "border-white/10 bg-white/[0.03] text-violet-300 hover:text-slate-200"
                  }`}
                >
                  $ {s}
                </button>
              ))}
            </div>

            {/* meta fields */}
            <div className="mb-4 grid gap-3 sm:grid-cols-2">
              <label className="block">
                <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-violet-300">
                  client_id
                </span>
                <input
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                  list="client-list"
                  placeholder="web01"
                  className="field mono w-full px-3 py-2"
                />
                <datalist id="client-list">
                  {knownClients.map((c) => (
                    <option key={c.client_id} value={c.client_id} />
                  ))}
                </datalist>
              </label>
              <label className="block">
                <span className="mono mb-1 block text-[10px] uppercase tracking-widest text-violet-300">
                  host_hint
                </span>
                <input
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="reporter hostname"
                  className="field mono w-full px-3 py-2"
                />
              </label>
            </div>

            {/* raw lines */}
            <textarea
              value={lines}
              onChange={(e) => setLines(e.target.value)}
              rows={11}
              placeholder={'$ paste raw log lines…\n<134>Sep 10 09:00:01 web01 sshd: Failed password for invalid user root from 203.0.113.9 port 51122 ssh2'}
              className="mono w-full resize-y rounded-lg border border-white/10 bg-black/50 px-3.5 py-3 text-[12px] leading-relaxed text-violet-200/90 caret-emerald-400 outline-none placeholder:text-violet-400 focus:border-violet-600/50 focus:shadow-[0_0_0_3px_rgba(167, 139, 196,0.08)]"
            />

            {/* artist bar */}
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <button onClick={submit} disabled={sending} className="btn-primary mono">
                {sending ? "PIPELINING…" : "▶ INGEST"}
              </button>
              <button onClick={sample} className="btn-ghost mono text-[11px]">
                INSERT SAMPLE ×3
              </button>
              <span className="mono ml-auto text-[10px] text-violet-400">
                buffer: {lineCount} line{lineCount === 1 ? "" : "s"}
              </span>
            </div>

            {/* stage tracker */}
            <div className="mt-4 flex items-center gap-2">
              {PIPELINE_STAGES.map((p, i) => (
                <React.Fragment key={p}>
                  {i > 0 && <span className="text-violet-500">›</span>}
                  <span
                    className={`mono rounded-md border px-2 py-0.5 text-[10px] uppercase tracking-widest transition ${
                      sending && stage >= i
                        ? "border-violet-600/60 bg-violet-600/10 text-violet-300"
                        : result && stage >= PIPELINE_STAGES.length
                          ? "border-violet-600/40 text-violet-500/80"
                          : "border-white/5 text-violet-400"
                    }`}
                  >
                    {sending && stage === i && <Blink />} {p}
                  </span>
                </React.Fragment>
              ))}
              {!sending && result && (
                <span className="ml-auto mono text-[10px] text-violet-500">✓ batch complete</span>
              )}
            </div>

            {error && (
              <p className="mono mt-3 text-[12px] text-pink-500">✗ {error}</p>
            )}
          </div>
        </section>

        {/* ------------------------------------------------ pipeline result */}
        <section className="glass overflow-hidden anim-fadeup" style={{ animationDelay: "80ms" }}>
          <div className="flex items-center gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
            <span className="h-1.5 w-1.5 rounded-full bg-violet-500 pulse-dot-calm" />
            <p className="mono text-[11px] tracking-widest text-violet-300">output :: last batch</p>
          </div>
          <div className="terminal p-5">
            {!result ? (
              <Empty
                title="No batch processed yet"
                hint="Paste lines and hit INGEST — the pipeline verdict prints here."
              />
            ) : (
              <div className="space-y-5">
                <div className="grid grid-cols-3 gap-3">
                  <div className="rounded-xl border border-violet-600/20 bg-violet-600/5 p-3 text-center">
                    <p className="text-grad-emerald text-3xl font-bold leading-none mono">{result.accepted}</p>
                    <p className="mono mt-1.5 text-[10px] uppercase tracking-widest text-violet-300">accepted</p>
                  </div>
                  <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-3 text-center">
                    <p className="text-grad-warn text-3xl font-bold leading-none mono">{result.duplicates ?? 0}</p>
                    <p className="mono mt-1.5 text-[10px] uppercase tracking-widest text-violet-300">duplicates</p>
                  </div>
                  <div className="rounded-xl border border-pink-500/20 bg-pink-500/5 p-3 text-center">
                    <p className="text-grad-danger text-3xl font-bold leading-none mono">{result.failed}</p>
                    <p className="mono mt-1.5 text-[10px] uppercase tracking-widest text-violet-300">failed</p>
                  </div>
                </div>

                <div className="mono text-[11px] leading-relaxed text-violet-300">
                  <p>$ store.total <span className="text-violet-300">→ {result.total}</span></p>
                  <p>$ alerts.batch <span className="text-purple-300">→ {result.alerts.length}</span></p>
                  {result.accepted > 0 && (
                    <p className="text-violet-500">✓ {result.accepted} lines accepted{failedNote(result)}</p>
                  )}
                  {(result.duplicates ?? 0) > 0 && (
                    <p className="text-purple-300">↺ {result.duplicates} lines deduplicated — identical event already in store</p>
                  )}
                  {(result.ignored ?? 0) > 0 && (
                    <p className="text-violet-200">· {result.ignored} lines consumed as format scaffolding (e.g. CSV header) — raw preserved</p>
                  )}
                  {result.failed > 0 && (
                    <p className="text-pink-500">✗ {result.failed} lines rejected — blank or malformed input</p>
                  )}
                </div>

                {result.alerts.length > 0 && (
                  <div>
                    <p className="eyebrow mb-2">Fan-out verdicts</p>
                    <div className="space-y-2">
                      {[...result.alerts].reverse().map((a, i) => (
                        <div key={i} className="glass-row flex items-center gap-2 px-3 py-2 text-[12px]">
                          {typeof a === "string" ? (
                            <span className="mono text-slate-300">{a}</span>
                          ) : (
                            <>
                              <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${a.severity === "critical" ? "bg-pink-500 pulse-dot-red" : "bg-purple-400"}`} />
                              <SeverityBadge severity={a.severity} />
                              <span className="mono text-slate-200">{a.threat_class}</span>
                              <span className="ml-auto text-[10px] text-violet-300">conf {a.confidence}</span>
                            </>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </section>
      </div>

      {/* ------------------------------------------------ ingest telemetry graphs */}
      <section className="grid gap-6 xl:grid-cols-2 anim-fadeup" style={{ animationDelay: "120ms" }}>
        <div className="glass p-5">
          <SectionTitle
            right={<span className="mono text-[10px] uppercase tracking-widest text-violet-300">GET /api/analytics</span>}
          >
            Share by source
          </SectionTitle>
          {analytics ? (
            <SourceDonut obj={analytics.by_source_type} total={analytics.totals?.events_total} />
          ) : (
            <Empty title="Awaiting telemetry" hint="Source mix plots here from the store roll-up." />
          )}
        </div>

        <div className="glass p-5">
          <SectionTitle
            right={<span className="mono text-[10px] uppercase tracking-widest text-violet-300">last {analytics?.window_hours || 48}h · every ingest</span>}
          >
            Ingest volume
          </SectionTitle>
          {analytics ? (
            <VolumeChart series={analytics.time_series} total={analytics.totals?.events_in_window} />
          ) : (
            <Empty title="Awaiting telemetry" hint="Event volume per bucket plots here as lines are ingested." />
          )}
        </div>
      </section>

      {/* ------------------------------------------------ bulk upload */}
      <section className="glass overflow-hidden anim-fadeup" style={{ animationDelay: "140ms" }}>
        <div className="flex items-center justify-between gap-2 border-b border-white/5 bg-black/40 px-4 py-2.5">
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-purple-400 pulse-dot" />
            <p className="mono text-[11px] tracking-widest text-violet-300">bulk :: file upload</p>
          </div>
          <PlainBadge>csv · json · jsonl</PlainBadge>
        </div>
        <div className="p-5">
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => fileRef.current?.click()}
              className="btn-ghost mono text-[11px]"
            >
              {bulkFile ? `✓ ${bulkFile.name}` : "CHOOSE FILE"}
            </button>
            <input
              ref={fileRef}
              type="file"
              hidden
              accept=".csv,.json,.jsonl,.log,.txt"
              onChange={(e) => { setBulkFile(e.target.files[0] || null); setBulkResult(null); setBulkError(null); }}
            />
            <select value={bulkSource} onChange={(e) => setBulkSource(e.target.value)} className="field mono px-3 py-2 text-[11px]">
              <option value="">source: auto</option>
              {SOURCES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <button onClick={uploadBulk} disabled={bulkBusy || !bulkFile} className="btn-primary mono">
              {bulkBusy ? "UPLOADING…" : "↑ UPLOAD"}
            </button>
            <span className="mono text-[10px] text-violet-400">
              client_id from the field above · rows go through the full pipeline
            </span>
          </div>

          {bulkError && <p className="mono mt-3 text-[12px] text-pink-500">✗ {bulkError}</p>}

          {bulkResult && (
            <div className="mt-4 grid gap-3 sm:grid-cols-4">
              <div className="rounded-xl border border-violet-600/20 bg-violet-600/5 p-3 text-center">
                <p className="text-grad-emerald text-2xl font-bold leading-none mono">{bulkResult.accepted}</p>
                <p className="mono mt-1 text-[9px] uppercase tracking-widest text-violet-300">accepted</p>
              </div>
              <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-3 text-center">
                <p className="text-grad-warn text-2xl font-bold leading-none mono">{bulkResult.duplicates ?? 0}</p>
                <p className="mono mt-1 text-[9px] uppercase tracking-widest text-violet-300">duplicates</p>
              </div>
              <div className="rounded-xl border border-pink-500/20 bg-pink-500/5 p-3 text-center">
                <p className="text-grad-danger text-2xl font-bold leading-none mono">{bulkResult.failed}</p>
                <p className="mono mt-1 text-[9px] uppercase tracking-widest text-violet-300">failed</p>
              </div>
              <div className="rounded-xl border border-violet-600/20 bg-violet-600/5 p-3 text-center">
                <p className="text-grad-emerald text-2xl font-bold leading-none mono">{bulkResult.total.toLocaleString()}</p>
                <p className="mono mt-1 text-[9px] uppercase tracking-widest text-violet-300">total in store</p>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

function failedNote(r) {
  const n = (r.duplicates ?? 0) > 0 ? ` · ${r.duplicates} deduped` : "";
  return r.failed > 0 ? `${n} · ${r.failed} rejected` : n;
}

function Blink() {
  return <span className="inline-block h-3 w-1.5 animate-pulse bg-violet-500 align-middle" style={{ verticalAlign: "-2px" }} />;
}

/* --------------------------------------------------------------- ingest graphs */
const SRC_COLORS = ["#a855f7", "#ec4899", "#c084fc", "#7c3aed", "#f472b6", "#a78bfa"];

function SourceDonut({ obj = {}, total }) {
  const entries = Object.entries(obj).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    return <Empty title="No events in store yet" hint="Accepted lines are bucketed by source_type for this chart." />;
  }
  const head = entries.slice(0, 6);
  const rest = entries.slice(6).reduce((s, [, v]) => s + v, 0);
  const segments = head.map(([label, value], i) => ({
    label,
    value,
    color: SRC_COLORS[i % SRC_COLORS.length],
  }));
  if (rest > 0) segments.push({ label: "other", value: rest, color: "#6b5b8a" });
  return (
    <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-center">
      <Donut size={168} thickness={18} centerValue={(total ?? 0).toLocaleString()} centerLabel="events" segments={segments} />
      <div className="w-full space-y-1.5">
        {segments.map((s) => (
          <div key={s.label} className="flex items-center gap-2 text-[12px]">
            <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: s.color, boxShadow: `0 0 8px ${s.color}` }} />
            <span className="mono truncate text-slate-300">{s.label}</span>
            <span className="ml-auto mono tabular-nums text-violet-300">{s.value.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function VolumeChart({ series = [], total }) {
  const data = (series || []).map((b) => b.events ?? 0);
  if (data.length === 0) {
    return <Empty title="No events in window" hint="Hourly buckets appear here once the store grows." />;
  }
  if (data.length < 2) data.push(0);
  const peak = Math.max(...data);
  const mean = Math.round(data.reduce((s, v) => s + v, 0) / data.length);
  return (
    <div>
      <Sparkline data={data} color="#a855f7" width={620} height={92} />
      <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-[10.5px] text-violet-300">
        <span className="mono">peak <b className="text-violet-300">{peak.toLocaleString()}</b> events/bucket</span>
        <span className="mono">mean <b className="text-slate-300">{mean.toLocaleString()}</b>/bucket</span>
        <span className="mono">window total <b className="text-violet-300">{(total ?? 0).toLocaleString()}</b></span>
      </div>
    </div>
  );
}