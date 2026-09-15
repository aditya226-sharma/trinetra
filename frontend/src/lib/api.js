import axios from "axios";
import { getToken, setToken } from "./auth";

// Requests go through the Vite dev proxy (/api -> FastAPI) so the browser
// needs no CORS config in local dev either. A build may point VITE_API_BASE
// at a deployed FastAPI origin; the default "/api" keeps everything
// same-origin for the Docker image.
const BASE = (import.meta.env.VITE_API_BASE || "/api").replace(/\/+$/, "");
const api = axios.create({ baseURL: BASE, timeout: 30000 });

// The deploy origin the agent config should point at (used by OnboardingPage).
// Prefer the explicit VITE_API_BASE host when one is set (tunnel / custom
// domain), falling back to the browser's origin for same-origin deploys.
export const apiBase = BASE;
export const apiOrigin = BASE.startsWith("http")
  ? BASE.replace(/\/api\/?$/, "")
  : (typeof window !== "undefined" ? window.location.origin : "");

// Attach the dashboard bearer token to every request.
api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// A 401 anywhere (except the login call itself) means the session expired.
api.interceptors.response.use(
  (res) => res,
  (err) => {
    const url = String(err?.config?.url || "");
    if (err?.response?.status === 401 && !OFFLINE && !url.includes("/auth/login")) {
      setToken(null);
      window.dispatchEvent(new Event("trinetra:unauthorized"));
    }
    return Promise.reject(err);
  }
);

// ---------------------------------------------------------------------------
// GitHub Pages preview mode: the Python backend cannot run there, so the
// Pages build embeds the canonical demo corpus (scripts/export_snapshot.py)
// and serves it locally with identical response shapes. Data-driven pages,
// search and drill-downs work exactly like the live product.
// ---------------------------------------------------------------------------
const OFFLINE = import.meta.env.VITE_OFFLINE_DEMO === "1";

let snapshot = null;

// Import is hoisted statically; doing it lazily keeps it out of live builds.
async function loadSnapshot() {
  if (snapshot) return snapshot;
  const mod = await import("./demo-snapshot.json");
  snapshot = { ...mod.default, events: mod.default.sample_events || [] };
  return snapshot;
}

function offlineSearch(list, { query = "", source_type = "", severity = "", category = "", client_id = "", threat_class = "", ts_from = "", ts_to = "" } = {}) {
  const q = query.trim().toLowerCase();
  const tc = threat_class.trim().toLowerCase();
  return list.filter((e) => {
    if (q) {
      // Same fields the backend /api/events/search matches against:
      // message, trace_id, client_ip, and the serialized fields blob.
      const hay = [
        e.message || "",
        e.client_ip || "",
        e.trace_id || "",
        JSON.stringify(e.fields || {}),
      ].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    if (source_type && e.source_type !== source_type) return false;
    if (severity && e.severity !== severity) return false;
    if (category && e.category !== category) return false;
    if (client_id && e.client_id !== client_id) return false;
    if (tc) {
      const f = e.fields || {};
      const mf = f.module_findings || {};
      const evtc = String(mf?.find?.((m) => m.threat_class)?.threat_class ||
                          mf?.network_threat?.threat_class ||
                          f.threat_class || "").toLowerCase();
      if (!evtc.includes(tc)) return false;
    }
    if (ts_from && e.timestamp && e.timestamp < ts_from) return false;
    if (ts_to && e.timestamp && e.timestamp > ts_to) return false;
    return true;
  });
}

export async function bootstrapDemo(reset = true) {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return { status: "ok", ...s.dashboard };
  }
  const { data } = await api.post("/demo/run", null, { params: { reset } });
  return data;
}

export async function getHealth() {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return s.health;
  }
  const { data } = await api.get("/health");
  return data;
}

export async function getDashboard() {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return s.dashboard;
  }
  const { data } = await api.get("/dashboard");
  return data;
}

export async function getGraph() {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return s.graph;
  }
  const { data } = await api.get("/graph");
  return data;
}

export async function getAssets() {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return s.assets;
  }
  const { data } = await api.get("/assets");
  return data;
}

export async function getAssetRelations(ip) {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return s.relations[ip] || { asset: null, edges: [], findings: [], compliance: { controls: [], affected_findings: [] } };
  }
  const { data } = await api.get(`/assets/${encodeURIComponent(ip)}/relations`);
  return data;
}

export async function getCompliance(assetId) {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return s.compliance_by_asset[assetId] || { asset_id: assetId, affected_findings: [], controls: [] };
  }
  const { data } = await api.get(`/compliance/${encodeURIComponent(assetId)}`);
  return data;
}

export async function getComplianceMappings() {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return s.compliance_mappings;
  }
  const { data } = await api.get("/compliance");
  return data;
}

export async function getAlerts(limit = 100) {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return { alerts: s.alerts.alerts.slice(0, limit), count: s.alerts.count, sent: s.alerts.sent };
  }
  const { data } = await api.get("/alerts", { params: { limit } });
  return data;
}

export async function getNetworkThreats(limit = 100) {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return { findings: s.network_threats.findings.slice(0, limit), count: s.network_threats.count };
  }
  const { data } = await api.get("/network-threats", { params: { limit } });
  return data;
}

export async function getClients() {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return s.clients;
  }
  const { data } = await api.get("/clients");
  return data;
}

export async function searchEvents(params = {}) {
  if (OFFLINE) {
    const s = await loadSnapshot();
    const { query = "", source_type = "", severity = "", category = "", client_id = "", threat_class = "", ts_from = "", ts_to = "", limit = 50, offset = 0 } = params;
    const filtered = offlineSearch(s.events, { query, source_type, severity, category, client_id, threat_class, ts_from, ts_to });
    return { total: filtered.length, limit, offset, events: filtered.slice(offset, offset + limit) };
  }
  const { data } = await api.get("/events/search", { params });
  return data;
}

// CSV export over the same filters /api/events/search honours. Returns a
// downloadable Blob; callers do the anchor click + revoke dance.
export async function exportCsv(params = {}) {
  if (OFFLINE) {
    const s = await loadSnapshot();
    const go = (s.events || []).filter((e) => {
      const f = e.fields || {};
      const tc = String(f?.threat_class || "").toLowerCase();
      return (!params.threat_class || tc.includes(params.threat_class.toLowerCase()))
        && (!params.client_id || e.client_id === params.client_id)
        && (!params.ts_from || !e.timestamp || e.timestamp >= params.ts_from)
        && (!params.ts_to || !e.timestamp || e.timestamp <= params.ts_to);
    });
    const rows = [["event_id", "timestamp", "source_type", "client_id", "client_ip", "category", "severity", "threat_class", "message", "trace_id"]];
    for (const e of go) rows.push([e.event_id, e.timestamp, e.source_type, e.client_id, e.client_ip || "", e.category, e.severity, e.fields?.threat_class || "", String(e.message).replace(/\n/g, " "), e.trace_id || ""]);
    return new Blob([rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n")], { type: "text/csv" });
  }
  const { data } = await api.get("/events/search", {
    params: { ...params, limit: 5000, offset: 0, format: "csv" },
    responseType: "blob",
  });
  return new Blob([data], { type: "text/csv" });
}

export async function getEvent(id) {
  if (OFFLINE) {
    const s = await loadSnapshot();
    const found = s.events.find((e) => e.event_id === id);
    if (!found) throw new Error(`event not found: ${id}`);
    return { ...found, raw: null, trace_events: [found] };
  }
  const { data } = await api.get(`/events/${encodeURIComponent(id)}`);
  return data;
}

export async function ingestLines(lines) {
  if (OFFLINE) {
    // Preview builds are read-only: acknowledge without mutating data.
    const s = await loadSnapshot();
    return { accepted: 0, failed: 0, duplicates: 0, ignored: 0, alerts: [], total: s.health.events_stored };
  }
  const { data } = await api.post("/ingest", { lines });
  return data;
}

// Export whether this build runs in preview mode (used for UI chrome).
export const isPreview = OFFLINE;

// ------------------------------------------------------------------
// auth
// ------------------------------------------------------------------

export async function loginUser(username, password) {
  const { data } = await api.post("/auth/login", { username, password });
  setToken(data.access_token);
  return data;
}

export async function authMe() {
  if (OFFLINE) return { username: "preview", role: "viewer" };
  const { data } = await api.get("/auth/me");
  return data;
}

export async function registerUser(username, password, role = "viewer") {
  if (OFFLINE) return { username, role };
  const { data } = await api.post("/auth/register", { username, password, role });
  return data;
}

export function logoutUser() {
  setToken(null);
}

export async function getUsers() {
  if (OFFLINE) return { users: [] };
  const { data } = await api.get("/auth/users");
  return data;
}

export async function deleteUser(username) {
  if (OFFLINE) return { deleted: true };
  const { data } = await api.delete(`/auth/users/${encodeURIComponent(username)}`);
  return data;
}

// ------------------------------------------------------------------
// live event stream (SSE)
// ------------------------------------------------------------------

export function streamEvents({ onEvent, onError, clientFilter } = {}) {
  // Preview builds serve the frozen snapshot — nothing to stream.
  if (OFFLINE) return () => {};
  const token = getToken();
  const url = `${BASE}/events/stream${token ? `?token=${encodeURIComponent(token)}` : ""}`;
  const es = new EventSource(url);
  es.onmessage = (ev) => {
    try {
      const parsed = JSON.parse(ev.data);
      if (clientFilter && parsed.client_id !== clientFilter) return;
      onEvent?.(parsed);
    } catch {
      /* ignore non-JSON sse lines */
    }
  };
  es.onerror = () => onError?.();
  return () => es.close();
}

// ------------------------------------------------------------------
// agents (per-machine tokens)
// ------------------------------------------------------------------

export async function getAgents() {
  const { data } = await api.get("/agents");
  return data;
}

export async function mintAgent(label = "", clientId = "") {
  const { data } = await api.post("/agents", { label, client_id: clientId });
  return data;
}

export async function revokeAgent(tokenId) {
  const { data } = await api.delete(`/agents/${encodeURIComponent(tokenId)}`);
  return data;
}

// ------------------------------------------------------------------
// settings & admin (Phase 2)
// ------------------------------------------------------------------

export async function changePassword(currentPassword, newPassword) {
  if (OFFLINE) return { ok: true }; // preview builds are read-only
  const { data } = await api.post("/auth/change-password", { current_password: currentPassword, new_password: newPassword });
  return data;
}

export async function getStorageStats() {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return {
      retention_days: 30, valid_values: [1, 7, 30, 90, 365, 0],
      events: s.health.events_stored || 0, raw_records: 0,
      event_db_bytes: 0, raw_store_bytes: 0,
      event_db_path: "", cutoff: null,
    };
  }
  const { data } = await api.get("/admin/storage");
  return data;
}

export async function setRetention(days, pruneNow = false) {
  if (OFFLINE) return { retention_days: days };
  const { data } = await api.put("/admin/retention", { days, prune_now: pruneNow });
  return data;
}

export async function getAudit(limit = 100) {
  if (OFFLINE) return { entries: [] };
  const { data } = await api.get("/admin/audit", { params: { limit } });
  return data;
}

export async function ingestBulkFile(file, { source = "", clientId = "" } = {}) {
  if (OFFLINE) {
    const s = await loadSnapshot();
    return { accepted: 0, failed: 0, duplicates: 0, raw_records: 0, total: s.health.events_stored, alerts: [] };
  }
  const fd = new FormData();
  fd.append("file", file);
  if (source) fd.append("source", source);
  if (clientId) fd.append("client_id", clientId);
  const { data } = await api.post("/ingest/bulk", fd);
  return data;
}

// ------------------------------------------------------------------
// analytics, collectors & fleet ops (Phase 4)
// ------------------------------------------------------------------

export async function getAnalytics(hours = 48) {
  if (OFFLINE) {
    const s = await loadSnapshot();
    const ev = s.events || [];
    return {
      generated_at: new Date().toISOString(), window_hours: hours, step_hours: 1,
      totals: { events_in_window: ev.length, events_total: ev.length, duplicates_total: 0,
        findings_total: s.network_threats.count || 0, alerts_total: s.alerts.sent || 0,
        analyzer_calls_total: 0, dedup_rate: 0 },
      time_series: [], by_source_type: groupCount(ev, "source_type"),
      by_severity: groupCount(ev, "severity"), by_category: groupCount(ev, "category"),
      by_client: groupCount(ev, "client_id"), detections: {},
    };
  }
  const { data } = await api.get("/analytics", { params: { hours } });
  return data;
}

function groupCount(list, key) {
  const out = {};
  for (const e of list) { const k = e[key] || "other"; out[k] = (out[k] || 0) + 1; }
  return out;
}

export async function downloadAnalyticsCsv(hours = 48) {
  if (OFFLINE) return null;
  const { data } = await api.get("/analytics", { params: { hours, format: "csv" }, responseType: "blob" });
  return new Blob([data], { type: "text/csv" });
}

export async function getCollectors() {
  if (OFFLINE) {
    return { config: { syslog: { enabled: false, port: 1514, client_id: "trinetra-core" },
        tailers: [], demo: { enabled: false, replay_delay_s: 300, client_id: "trinetra-core" } },
      running: { syslog_active: false, tailer_active: false, demo_active: false, syslog_port: 1514, tailers: [], demo_enabled: false } };
  }
  const { data } = await api.get("/admin/collectors");
  return data;
}

export async function setCollectors(patch) {
  const { data } = await api.put("/admin/collectors", patch);
  return data;
}

export function complianceReportUrl(assetId) {
  return `/report/${encodeURIComponent(assetId)}`;
}

// ------------------------------------------------------------------
// SOC policy: watchlist / blocklist / rules / cases / delivery (Phase 3)
// ------------------------------------------------------------------

export async function getWatchlist(list = "watchlist") {
  if (OFFLINE) return { list, entries: [] };
  const { data } = await api.get("/watchlist", { params: { list } });
  return data;
}

export async function addWatchEntry(list, kind, value, reason = "") {
  if (OFFLINE) return { entry: { kind, value, reason } };
  const { data } = await api.post("/watchlist", { list, kind, value, reason });
  return data;
}

export async function removeWatchEntry(list, kind, value) {
  if (OFFLINE) return { removed: true };
  const { data } = await api.delete(`/watchlist/${list}/${encodeURIComponent(kind)}`, {
    params: { value },
  });
  return data;
}

export async function toggleWatchEntry(list, kind, value, active) {
  if (OFFLINE) return { active };
  const { data } = await api.put(`/watchlist/${list}/${encodeURIComponent(kind)}/active`, null, {
    params: { value, active },
  });
  return data;
}

export async function getRules() {
  if (OFFLINE) return { rules: [] };
  const { data } = await api.get("/rules");
  return data;
}

export async function createRule(rule) {
  if (OFFLINE) return { rule: { ...rule, id: "preview" } };
  const { data } = await api.post("/rules", rule);
  return data;
}

export async function updateRule(id, rule) {
  if (OFFLINE) return { rule: { ...rule, id } };
  const { data } = await api.put(`/rules/${encodeURIComponent(id)}`, rule);
  return data;
}

export async function deleteRule(id) {
  if (OFFLINE) return { deleted: true };
  const { data } = await api.delete(`/rules/${encodeURIComponent(id)}`);
  return data;
}

export async function toggleRule(id, enabled) {
  if (OFFLINE) return { enabled };
  const { data } = await api.post(`/rules/${encodeURIComponent(id)}/toggle`, null, {
    params: { enabled },
  });
  return data;
}

export async function getCases(params = {}) {
  if (OFFLINE) {
    const s = await loadSnapshot();
    const alerts = (s.alerts.alerts || []).slice(0, params.limit || 100);
    const cases = alerts.map((a, i) => ({
      id: `preview-${i}`,
      threat_class: a.threat_class,
      severity: a.severity,
      source_kind: "flow",
      source_value: a.flows || "",
      message: a.threat_class,
      evidence: a.evidence || {},
      verdict: a.verdict,
      store_decision: a.store_decision,
      confidence: a.confidence,
      timestamp: a.timestamp,
      last_seen: a.timestamp,
      hits: 1,
      status: "open",
      assignee: "",
      notes: [],
      timeline: [],
      delivery: null,
    }));
    return { cases, count: cases.length, stats: { total: cases.length, by_status: { open: cases.length, acknowledged: 0, resolved: 0 }, by_severity: {}, unresolved_by_severity: {} } };
  }
  const { data } = await api.get("/cases", { params });
  return data;
}

export async function caseAction(id, { action, assignee = "", note = "" }) {
  if (OFFLINE) return { case: { id, status: "open" } };
  const { data } = await api.patch(`/cases/${encodeURIComponent(id)}`, { action, assignee, note });
  return data;
}

export async function getCaseStats() {
  if (OFFLINE) return { total: 0, by_status: {}, by_severity: {}, unresolved_by_severity: {} };
  const { data } = await api.get("/cases/stats");
  return data;
}

// ------------------------------------------------------------------
// notifications & digest delivery
// ------------------------------------------------------------------

export async function getNotifications() {
  if (OFFLINE) {
    return { enabled: true, severity_min: "warning",
      email: { host: "", port: 587, sender: "", recipient: "", username: "", password: "" },
      webhook: { url: "", secret: "" }, digest: { enabled: false, hour_utc: 8 } };
  }
  const { data } = await api.get("/admin/notifications");
  return data;
}

export async function saveNotifications(patch) {
  const { data } = await api.put("/admin/notifications", patch);
  return data;
}

export async function testNotifications() {
  const { data } = await api.post("/admin/notifications/test");
  return data;
}

export async function runDigest(force = false) {
  const { data } = await api.post("/admin/notifications/digest", null, { params: { force } });
  return data;
}