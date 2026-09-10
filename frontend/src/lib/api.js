import axios from "axios";

// Requests go through the Vite dev proxy (/api -> FastAPI) so the browser
// needs no CORS config in local dev either.
const api = axios.create({ baseURL: "/api", timeout: 30000 });

export async function bootstrapDemo(reset = true) {
  const { data } = await api.post("/demo/run", null, { params: { reset } });
  return data;
}

export async function getHealth() {
  const { data } = await api.get("/health");
  return data;
}

export async function getDashboard() {
  const { data } = await api.get("/dashboard");
  return data;
}

export async function getGraph() {
  const { data } = await api.get("/graph");
  return data;
}

export async function getAssets() {
  const { data } = await api.get("/assets");
  return data;
}

export async function getAssetRelations(ip) {
  const { data } = await api.get(`/assets/${encodeURIComponent(ip)}/relations`);
  return data;
}

export async function getCompliance(assetId) {
  const { data } = await api.get(`/compliance/${encodeURIComponent(assetId)}`);
  return data;
}

export async function getAlerts(limit = 100) {
  const { data } = await api.get("/alerts", { params: { limit } });
  return data;
}

export async function getNetworkThreats(limit = 100) {
  const { data } = await api.get("/network-threats", { params: { limit } });
  return data;
}

export async function getClients() {
  const { data } = await api.get("/clients");
  return data;
}

export async function searchEvents(params = {}) {
  const { data } = await api.get("/events/search", { params });
  return data;
}

export async function getEvent(id) {
  const { data } = await api.get(`/events/${encodeURIComponent(id)}`);
  return data;
}

export async function ingestLines(lines) {
  const { data } = await api.post("/ingest", { lines });
  return data;
}