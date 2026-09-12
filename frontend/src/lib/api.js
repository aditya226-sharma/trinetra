import axios from "axios";
import { getToken, setToken } from "./auth";

// Requests go through the Vite dev proxy (/api -> FastAPI) so the browser
// needs no CORS config in local dev either. A build may point VITE_API_BASE
// at a deployed FastAPI origin; the default "/api" keeps everything
// same-origin for the Docker image.
const BASE = (import.meta.env.VITE_API_BASE || "/api").replace(/\/+$/, "");
api = axios.create({ baseURL: BASE, timeout: 30000 });

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

function offlineSearch(list, { query = "", source_type = "", severity = "", category = "", client_id = "" } = {}) {
  const q = query.trim().toLowerCase();
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
    const { query = "", source_type = "", severity = "", category = "", client_id = "", limit = 50, offset = 0 } = params;
    const filtered = offlineSearch(s.events, { query, source_type, severity, category, client_id });
    return { total: filtered.length, limit, offset, events: filtered.slice(offset, offset + limit) };
  }
  const { data } = await api.get("/events/search", { params });
  return data;
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