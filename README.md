# TriNetra — Universal Log Pre-processing Framework (ULPF)

Containerized security **log pre-processing** and **correlation** framework for
Smart India Hackathon 2026. Ingest any structured/unstructured security log
(syslog, CEF, JSON netflow, CSV, Windows/EVT XML, vendor text), normalize it to
a single **Universal Event Schema (UES)**, deduplicate, batch, and run three
analysis modules (network threat detection, VPN/IPsec posture, entity-activity
graph) plus a pluggable LLM verdict layer — surfaced through a FastAPI backend
and a 5-page React dashboard.

```
                        ┌──────────────────────────────────────────────┐
  syslog ───────┐       │                     ()()()                    │
  CEF  ─────────┤       │   pipeline/          │ ULPF │                 │
  netflow ──────┼──▶ RAW│   raw_store ──▶ UES ─┴──────┴─▶ Modules ──▶ LLM
  JSON/CSV ─────┤  store│         │  dedup / batch / prefilter         │
  Windows EVT ──┘  (lossless)   │                                  verdict│
                        └───────┼──────────────┬───────────────────────┘
                                ▼              ▼
                     Modules (pure Python)   alerting/notifier
                     A net-threat            B vpn/ipsec            C graph
                                └──────────┬──────────┘
                                           ▼
                              FastAPI (backend/) + dashboard (frontend/)
```

## Features

- **Plug-and-play parser registry** — `@register_parser("syslog")` decorator;
  adding a format is a one-file change. Ships with syslog (RFC3164/5424), CEF,
  JSON, CSV, Tab/NetFlow, Windows/EVT parsers plus an *auto-detect* source type.
- **Lossless raw store** — every raw line is persisted with a deterministic
  `client::source::sha256` trace id; parsed events reference the raw line.
- **Dedup, batching, prefilter** — running dedup counter (`~2.5%` on demo data),
  time-window batch flush (200ms), and a severity gate to keep the analyzer bill
  low.
- **Module A — network threat detection** (pure Python, no sklearn required):
  port scan, DDoS, C2 beaconing, DGA DNS, data exfiltration. Deterministic
  thresholds + confidence scoring, documented-range IPs (192.0.2/24 etc.)
  treated as external attacker space.
- **Module B — VPN/IPsec posture assessment**: pure-Python PCAP parser for
  IKEv1/IKEv2 + ESP; SA proposal → `VpnProfile`; rubric-scored (0–100) with
  risk matrix and hardening recommendations. Demo fixtures: `ipsec_strong.pcap`
  → **95 / low**, `ipsec_weak.pcap` (IKEv1 + 3DES + MD5 + DH-2, 900s lifetime)
  → **0 / critical**.
- **Module C — entity-activity graph**: networkx `MultiDiGraph` of
  `ip / user / proc / domain / threat` nodes and `comm / dns / auth / exec /
  flagged / runs` edges; impacted-asset list, lateral-movement view.
- **Pluggable analyzer**: `heuristic` (offline, default), `anthropic`
  (`ANTHROPIC_API_KEY`), or `local` (any OpenAI-compatible endpoint,
  `TRINETRA_LOCAL_LLM_URL`) behind the `AnalyzerBackend` protocol; returns
  verdict + confidence + store_decision (review / quarantine / allow).
- **Compliance mapping** — every finding maps to **CIS Controls v8**,
  **NIST CSF**, and **MITRE ATT&CK** and produces a markdown analyst brief.
- **FastAPI backend + React dashboard** — events explorer with the raw
  trace-back, SVG entity graph, asset drill-down with compliance, network
  threats, and a one-button *Run demo*.

## Quickstart

```bash
# 0) (optional) create venv
python3 -m venv .venv && source .venv/bin/activate

pip install -r requirements.txt          # pure-Python; sklearn optional

# 1) Full offline demo — LAN collision story + VPN pcap assessment
python main.py --demo --json

# 2) API + dashboard (API doubles as static server when frontend/dist exists)
python -m uvicorn backend.app.main:app --port 8000
#   shell 2: cd frontend && npm install && npm run dev   (dev proxy /api → :8000)

# 3) Or everything in Docker
docker compose up --build          # http://localhost:8000
```

### Container deployment (GitHub Container Registry)

Every push to `main` publishes the self-contained image to GHCR — the API and
dashboard share one port, so a single `docker run` gives you the full product:

```bash
docker run --rm -d -p 8000:8000 \
  -e TRINETRA_STORE_PATH=/app/data/trinetra.db \
  -e TRINETRA_RAW_DIR=/app/data/raw \
  -e AGENT_TOKEN=change-me \
  -e ADMIN_USER=admin \
  -e ADMIN_PASSWORD=change-me \
  -e TRINETRA_RETENTION_DAYS=30 \
  --name trinetra \
  ghcr.io/aditya226-sharma/trinetra:latest

open http://localhost:8000        # log in with ADMIN_USER / ADMIN_PASSWORD,
                                  # then run the demo story from the UI (admin)
```

Or with compose against the published image:

```bash
docker pull ghcr.io/aditya226-sharma/trinetra:latest
docker run --rm -p 8000:8000 ghcr.io/aditya226-sharma/trinetra:latest
```

Images are multi-arch (`linux/amd64`, `linux/arm64`). Semver tags (`vX.Y.Z`)
are published whenever a `v*` tag is pushed. Bind-mount `/app/data` to keep
events across container restarts.

### Live preview (GitHub Pages) — near-live mirror

The full dashboard — dashboard, event triage + search, alerts, graph, assets
drill-downs and compliance — is published as an interactive preview to
**https://aditya226-sharma.github.io/trinetra/** on every `main` push. GitHub
Pages cannot run the Python API, so the preview build embeds a snapshot
(exported with `scripts/export_snapshot.py`, wired via `VITE_OFFLINE_DEMO=1`)
and serves it with identical response shapes — search and drill-downs behave
exactly like the live product (a small amber `PREVIEW DATA` badge indicates
bundled data).

The snapshot is refreshed manually from the local instance (auth needed for
authed endpoints), so the Pages URL is a stable, always-reachable **near-live
mirror**:

```bash
# refresh the snapshot against the running local API, then commit + push:
TRINETRA_TOKEN=<jwt> python3 scripts/export_snapshot.py http://127.0.0.1:8000/api
```

Run locally against fresh/ingested data:

### Central log forwarding (log-agent → dashboard)

Point the [log-agent](https://github.com/aditya226-sharma/log-agent) at a Trinetra
instance to turn it into a live, cross-machine log browser. Agents on any host
(LAN or internet) forward normalized events to `/api/ingest-events` and show up
as per-machine chips on the dashboard's Events page.

Authentication model:

- Dashboard access requires **login**; the first admin is seeded from the
  `ADMIN_USER` / `ADMIN_PASSWORD` env vars (default `admin`/`admin`). Admins can
  create additional users via the UI (Settings) or `POST /api/auth/register`.
- Agents authenticate with a shared **`X-Agent-Token`**, deliberately
  independent of dashboard sessions (machines log in with the token, humans with
  accounts). The SSE live tail accepts it via `?token=` because `EventSource`
  can't set headers.

```bash
# 1) VPS / container env (reverse-proxied at https://logs.example.com)
AGENT_TOKEN=<long-random-shared-secret>   # shared with every agent
ADMIN_USER=admin
ADMIN_PASSWORD=<strong-password>
TRINETRA_RETENTION_DAYS=30                # 1|7|30|90|365|0 (=forever)

# 2) docker-compose on the box:
#    docker compose up -d --build   → http://127.0.0.1:8000 behind a proxy

# 3) reverse proxy + TLS (Caddy):
#    logs.example.com {
#        reverse_proxy 127.0.0.1:8000
#    }
#    Nginx: proxy_pass http://127.0.0.1:8000; plus
#    proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";
#    for SSE. Keep TRINETRA_STORE_PATH / TRINETRA_RAW_DIR on a persistent volume.

# 4) agent config.yaml on each machine (see log-agent README):
#    output:
#      type: http
#      url: https://logs.example.com/api/ingest-events
#      auth_token: "<same AGENT_TOKEN>"
#    agent:
#      hostname_override: "mac-mini"   # optional dashboard client chip
```

Events arriving from agents keep their source/host/channel metadata, map to the
same UES schema as demo/file/syslog ingestion, and flow through dedup, modules,
the analyzer and the SSE live tail exactly like everything else.

### CLI

```
usage: main.py [--demo] [--json] [--pcap DIR] [--replay FILE] [--backend {heuristic,anthropic,local}]
               [--max-events N] [--delay SECONDS]
```

`--demo` runs a multi-scene intrusion story (recon → brute-force → DDoS → C2
beaconing → exfiltration → DGA → VPN gateway) plus the two VPN pcap profiles.
With `--json` the machine summary goes to stdout and the ALERT console output
moves to stderr.

## Demo output (reference)

| metric | value |
|---|---|
| raw lines | 238 |
| unique UES events | 232 (2.5% duplicate rate) |
| findings | 5 |
| threat classes | port_scan, ddos, c2_beaconing, dga_dns, data_exfiltration |
| graph | 37 nodes / 220 edges |
| impacted assets | `10.10.1.10`, `10.10.1.50`, `198.51.100.9`, `203.0.113.5` |
| VPN | `ipsec_strong.pcap` score 95 (low) · `ipsec_weak.pcap` score 0 (critical) |

Sample verdicts from the heuristic analyzer:

```
ALERT: [WARNING] port_scan conf=0.98 verdict=suspicious (review)
ALERT: [CRITICAL] c2_beaconing conf=0.95 verdict=malicious (quarantine)
ALERT: [CRITICAL] data_exfiltration conf=0.67 verdict=malicious (quarantine)
```

## REST API (FastAPI)

| route | purpose |
|---|---|
| `GET /api/health` | store count, configured analyzer backend |
| `POST /api/auth/login` · `GET /api/auth/me` | dashboard login + session check |
| `POST /api/auth/register` | create an admin/analyst/viewer account (admin-only) |
| `PUT /api/auth/change-password` | rotate your own password (authed) |
| `GET /api/auth/users` · `DELETE /api/auth/users/{username}` | admin user roster + account removal |
| `POST /api/demo/run?reset=` | bootstrap the demo story, returns full results (admin) |
| `GET /api/dashboard` | aggregated stats + graph + latest findings |
| `GET /api/graph` | full entity graph payload for the SVG view |
| `GET /api/assets` · `GET /api/assets/{ip}/relations` | impacted asset list + drill-down |
| `GET /api/compliance` · `GET /api/compliance/{asset_id}/report` | CIS/NIST/ATT&CK mapping + markdown brief + group PDF report |
| `GET /api/network-threats` | current Module A findings |
| `GET /api/analytics` | hourly/7-day series + top dimensions for the charts |
| `GET /api/alerts` · `PATCH /api/alerts/{id}` | case/alerts feed + ack/resolve/assign/annotate lifecycle |
| `GET /api/cases` · `GET /api/cases/stats` · `PATCH /api/cases/{case_id}` | SOC case queue, status counters, triage transitions (analyst+) |
| `GET /api/rules` · `GET /api/rules/{rule_id}` | custom detection rules (admin mutates) |
| `GET /api/watchlist` · `POST /api/watchlist` · `PATCH /api/watchlist/{entry_id}/toggle` | watch/block indicators (admin mutates) |
| `GET /api/agents` · `POST /api/agents` · `DELETE /api/agents/{token_id}` | fleet token registry (admin mints/revokes) |
| `POST /api/agent/heartbeat` | agent liveness ping (`X-Agent-Token`) |
| `GET /api/admin/storage` · `POST /api/admin/retention` | storage panel + retention policy (admin) |
| `GET /api/admin/audit` | privileged-action audit trail (admin) |
| `GET /api/admin/collectors` · `POST /api/admin/collectors` | live collector sources (admin) |
| `GET /api/admin/notifications` · `POST /api/admin/notifications` · tests/digest | alert delivery config + test/digest (admin) |
| `GET /api/clients` | distinct client ids (each agent host shows live here) |
| `GET /api/events/search?query=` · `GET /api/events/{id}` | event explorer with raw trace-back |
| `GET /api/events/stream?token=&client_id=` | SSE live tail for the dashboard |
| `POST /api/ingest-events` | agent/flocker intake (`X-Agent-Token`; array or `{events:[...]}`) |
| `POST /api/ingest` · `POST /api/ingest/bulk` | normalize + analyze arbitrary lines / up to 10k records (admin) |

All routes above the `POST /api/ingest` row require a valid bearer token
(dashboard pages send it automatically); `GET /api/health` is unauthenticated;
`POST /api/ingest`, `POST /api/ingest/bulk` and `POST /api/demo/run` require
the `admin` role; case triage (ack/resolve/assign/annotate) requires `admin`
or `analyst`; `POST /api/ingest-events` and `POST /api/agent/heartbeat` use the
shared `X-Agent-Token` instead of a dashboard bearer token.

## Configuration

`config/config.yaml`:

```yaml
client_id: trinetra-core
paths: { raw_store: ./data/raw, event_store: ./data/trinetra.db, pcaps: ./data/pcaps }
llm: { backend: heuristic }     # heuristic | anthropic | local
```

Environment variables:

| var | purpose |
|---|---|
| `ANTHROPIC_API_KEY` | enables the `anthropic` analyzer backend |
| `TRINETRA_LOCAL_LLM_URL` | OpenAI-compatible base URL for the `local` backend |
| `TRINETRA_LOCAL_LLM_MODEL` | model name for the `local` backend (default `qwen2.5-coder:7b`) |
| `TRINETRA_LLM_BACKEND` | overrides `llm.backend` (used in docker-compose) |
| `TRINETRA_STORE_PATH` / `TRINETRA_RAW_DIR` | containerized store locations |
| `TRINETRA_CLIENT_ID` | agent identity for this node (default `trinetra-core`) |
| `AGENT_TOKEN` | shared `X-Agent-Token` accepted by `/api/ingest-events` + `/api/events/stream`; no ingestion from agents until set |
| `ADMIN_USER` / `ADMIN_PASSWORD` | first admin account (seeded on start if none exists; defaults to `admin`/`admin` — change for any exposed deployment) |
| `TRINETRA_RETENTION_DAYS` | event retention (1/7/30/90/365/0); background pruning on start |
| `TRINETRA_JWT_SECRET` | override the persisted HMAC signing secret (omit to auto-generate) |
| `TRINETRA_SMTP_HOST/PORT/FROM/TO/USER/PASS` | SMTP credentials for email alert delivery + digest |
| `VITE_API_BASE` / `VITE_BASE` / `VITE_OFFLINE_DEMO` | frontend build-time: API origin, base path (e.g. `/trinetra/` on Pages), offline demo mode |

## Repository layout

```
trinetra/
├── config/config.yaml          runtime configuration
├── schema/                     UES: Event, finding, trace-id helpers
├── parsers/                    registry + syslog/cef/json/csv/netflow/windows
├── pipeline/                   raw_store, normalizer, batcher (dedup), prefilter, event_store (SQLite)
├── collectors/                 file tailer, syslog UDP, flow collector, demo_feed, pcapgen
├── modules/                    A network_threat · B vpn_assessment (+ipsec_ids) · C entity_graph
├── analyzer/                   backend protocol, heuristic/anthropic/local, LLMAnalyzer facade
├── alerting/notifier.py        console + email fan-out
├── orchestrator.py + main.py   pipeline runner + CLI
├── socpolicy.py                 SOC policy engine: watch/block lists, rules, case lifecycle, delivery + digest
├── backend/app/                FastAPI routes + auth/RBAC + compliance service (serves frontend/dist when present)
├── frontend/                   React + Tailwind v4 / Vite dashboard: dashboard, events, alerts, rules, watchlist, graph, assets, compliance, analytics, fleet, report, ingest, console, settings, clients/onboard/logs
├── tests/                      106 pytest cases (parsers, pipeline, modules A/B/C, analyzer, SOC policy, auth/RBAC, API)
├── Dockerfile (multi-stage) + docker-compose.yml
└── data/                       runtime artifacts (raw/, trinetra.db, generated pcaps)
```

## Testing

```bash
python -m pytest tests/ -q      # 106 passed
```

## Problem-statement coverage

| SIH 2026 requirement | where |
|---|---|
| Universal log ingestion + normalization (PS26156 core) | `parsers/` registry → UES |
| Lossless raw store / forensic trace-back | `pipeline/raw_store.py` + `GET /api/events/{id}` |
| Dedup, batching, alert pre-filtering | `pipeline/batcher.py`, `pipeline/prefilter.py` |
| Threat detection on flows (PS26189) | `modules/network_threat.py` (5 classes) |
| VPN / IPsec config hardening (PS26160) | `modules/vpn_assessment.py` |
| Entity / lateral-movement graph | `modules/entity_graph.py` |
| AI-assisted verdict + compliance (PS26145) | `analyzer/` + `backend/app/services/compliance.py` |
| Containerized deploy | `Dockerfile`, `docker-compose.yml` |