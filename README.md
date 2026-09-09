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

### CLI

```
usage: main.py [--demo] [--json] [--pcap DIR] [--replay FILE] [--backend {heuristic,anthropic,local}]
               [--max-events N] [--delay SECONDS]
```

`--demo` runs a 6-scene LAN story (recon → brute-force → DDoS → C2 beacon →
exfiltration → DGA) plus the two VPN pcap profiles. With `--json` the machine
summary goes to stdout and the ALERT console output moves to stderr.

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
| `POST /api/demo/run?reset=` | bootstrap the demo story, returns full results |
| `GET /api/dashboard` | aggregated stats + graph + latest findings |
| `GET /api/graph` | full entity graph payload for the SVG view |
| `GET /api/assets` · `GET /api/assets/{ip}/relations` | impacted asset list + drill-down |
| `GET /api/compliance` · `GET /api/compliance/{asset}` | CIS/NIST/ATT&CK mapping + markdown brief |
| `GET /api/network-threats` | current Module A findings |
| `GET /api/clients` | distinct client ids |
| `GET /api/events/search?query=` · `GET /api/events/{id}` | event explorer with raw trace-back |
| `POST /api/ingest` | normalize + analyze arbitrary lines (`{source, host, lines[]}`) |

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
| `TRINETRA_LLM_BACKEND` | overrides `llm.backend` (used in docker-compose) |
| `TRINETRA_STORE_PATH` / `TRINETRA_RAW_DIR` | containerized store locations |

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
├── backend/app/                FastAPI routes + compliance service (serves frontend/dist when present)
├── frontend/                   React + Tailwind v4 / Vite dashboard (5 pages)
├── tests/                      33 pytest cases (parsers, pipeline, modules A/B/C, analyzer, API)
├── Dockerfile (multi-stage) + docker-compose.yml
└── data/                       runtime artifacts (raw/, trinetra.db, generated pcaps)
```

## Testing

```bash
python -m pytest tests/ -q      # 33 passed
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