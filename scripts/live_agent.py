#!/usr/bin/env python3
"""Live log agent — forward events + heartbeats to a TriNetra server.

A dependency-free (stdlib ``urllib``) stand-in for a real fleet of log
collectors. It drives the same two agent endpoints the product exposes:

  * ``POST /api/ingest-events``  — pre-normalized LogEntry dicts
  * ``POST /api/agent/heartbeat`` — client presence/identity

Each configured client heartbeats on its own cadence (server marks a client
``online`` when last_seen is inside the grace window) and streams a small,
realistic mixed-severity batch of events per tick so the dashboard, ingest
telemetry graph and log console update live.

Auth is the shared ``AGENT_TOKEN`` (env or ``--token``); per-machine tokens
minted via ``POST /api/agents`` work too — pass one with ``--token``.

Examples
--------
    python3 scripts/live_agent.py --once
    python3 scripts/live_agent.py --interval 3 --clients edge-fw-01,web01
    python3 scripts/live_agent.py --duration 60          # run 60s then stop
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

DEFAULT_API = "http://127.0.0.1:8000"

# client_id -> (hostname, platform, agent_version, ip)
FLEET = {
    "edge-fw-01": ("edge-fw-01", "pfsense", "2.6.0", "203.0.113.10"),
    "web01": ("web01", "debian-12/nginx", "1.24.0", "10.10.1.22"),
    "db-primary": ("db-primary", "ubuntu-22/postgres16", "16.2", "10.10.1.30"),
    "app-srv-01": ("app-srv-01", "debian-12/docker", "27.1.1", "10.10.1.40"),
    "auth-srv": ("auth-srv", "rocky-9/keycloak", "24.0.5", "10.10.1.50"),
}

TEMPLATES = [
    ("syslog", "system", "info", "cron[{rng}] (root) CMD (run-parts /etc/cron.hourly)"),
    ("syslog", "system", "info", "sshd[{pid}]: Accepted publickey for deploy from 10.10.0.9 port {port} ssh2"),
    ("syslog", "system", "warning", "kernel: [{dev}] link down, carrier lost on interface {dev}"),
    ("nginx", "application", "info", '10.10.1.{h} - - [{ts}] "GET /api/v1/{path} HTTP/1.1" 200 {bytes}'),
    ("nginx", "application", "warning", '10.10.1.{h} - - [{ts}] "GET /admin.php HTTP/1.1" 404 153 "-" "Nmap Scripting Engine"'),
    ("nginx", "application", "error", '10.10.1.{h} - - [{ts}] "POST /login HTTP/1.1" 401 12 "-" "curl/8.4.0"'),
    ("auth", "auth", "info", "Accepted session for user svc-{n} from 10.10.0.{h}"),
    ("auth", "auth", "warning", "Failed password for invalid user admin from 203.0.113.{n} port {port} ssh2"),
    ("auth", "auth", "error", "authentication failure for user root from 203.0.113.{n}"),
    ("cef", "network", "info", "CEF:0|Trinetra|firewall|1.0|allow|{dev} allowed tcp 10.10.1.{h}->198.51.100.{n}:{port}"),
    ("cef", "network", "warning", "CEF:0|Trinetra|firewall|1.0|block|{dev} blocked tcp 203.0.113.{n}->10.10.1.{h}:{port}"),
    ("flow", "flow", "info", "proto=tcp src=10.10.1.{h} dst=198.51.100.{n} dport={port} bytes={bytes} pkts={pkts} flags=S"),
]

THREAT_TEMPLATES = [
    ("network", "critical", "port-scan: 18 SYNs from 203.0.113.{n} to 10.10.1.{h} in 3s"),
    ("auth", "critical", "brute-force: 12 failed SSH logins for root from 203.0.113.{n}"),
    ("flow", "error", "c2-beacon: periodic small flow 10.10.1.{h} -> 198.51.100.{n} every 60s"),
    ("network", "critical", "dga: high-entropy DNS query to 198.108.1.1 (.top)"),
]

_RUNNING = True


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _http(api: str, path: str, body, token: str, timeout: float = 8.0):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        api + path, data=data, method="POST",
        headers={"Content-Type": "application/json", "X-Agent-Token": token},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _fill(tpl: str) -> str:
    return tpl.format(
        rng=random.randint(1000, 9999), pid=random.randint(100, 9999),
        port=random.choice([22, 80, 443, 445, 3389, 8080]),
        dev=random.choice(["em0", "igb0", "ens192", "eth0"]),
        h=random.randint(2, 250), n=random.randint(2, 250),
        path=random.choice(["health", "items", "users", "orders"]),
        bytes=random.randint(120, 9000), pkts=random.randint(2, 200),
        ts=_now_iso(),
    )


def _event(client_id: str, threat_bias: float = 0.12) -> dict:
    if random.random() < threat_bias:
        cat, sev, msg = random.choice(THREAT_TEMPLATES)
        source = {"network": "cef", "auth": "auth", "flow": "flow"}[cat]
    else:
        source, cat, sev, msg = random.choice(TEMPLATES)
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "source": source,
        "level": sev,
        "category": cat,
        "message": _fill(msg),
        "raw": _fill(msg),
        "client_id": client_id,
        "metadata": {"host": client_id, "agent": "live_agent"},
    }


def _stop(*_a):
    global _RUNNING
    _RUNNING = False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="TriNetra live log agent")
    ap.add_argument("--api", default=os.environ.get("TRINETRA_API", DEFAULT_API))
    ap.add_argument("--token", default=os.environ.get("AGENT_TOKEN", ""))
    ap.add_argument("--interval", type=float, default=4.0, help="seconds between ticks")
    ap.add_argument("--batch", type=int, default=3, help="events per client per tick")
    ap.add_argument("--clients", default="", help="comma list; default = full FLEET")
    ap.add_argument("--duration", type=float, default=0.0, help="stop after N seconds (0 = forever)")
    ap.add_argument("--once", action="store_true", help="one tick then exit")
    args = ap.parse_args(argv)

    if not args.token:
        print("error: set AGENT_TOKEN or pass --token", file=sys.stderr)
        return 2

    clients = [c.strip() for c in args.clients.split(",") if c.strip()] or list(FLEET)
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    started = time.monotonic()
    total_sent = 0
    while _RUNNING:
        for cid in clients:
            host, platform, version, ip = FLEET.get(cid, (cid, "", "", ""))
            try:
                _http(args.api, "/api/agent/heartbeat", {
                    "client_id": cid, "hostname": host, "platform": platform,
                    "agent_version": version, "ip": ip,
                }, args.token)
                batch = [_event(cid) for _ in range(max(1, args.batch))]
                res = _http(args.api, "/api/ingest-events", {"events": batch}, args.token)
                total_sent += int(res.get("accepted", 0))
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", "replace")[:120]
                print(f"http {e.code} for {cid}: {detail}", file=sys.stderr)
                if e.code == 429:
                    time.sleep(max(args.interval, 5.0))
            except Exception as e:  # noqa: BLE001 — an agent must survive blips
                print(f"error for {cid}: {e}", file=sys.stderr)
                time.sleep(max(args.interval, 5.0))

        if args.once:
            print(f"sent ~{total_sent} events across {len(clients)} client(s)")
            return 0
        if args.duration and (time.monotonic() - started) >= args.duration:
            print(f"done: sent ~{total_sent} events in {time.monotonic() - started:.0f}s")
            return 0
        time.sleep(args.interval)

    print(f"stopped: sent ~{total_sent} events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
