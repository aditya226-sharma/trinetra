#!/usr/bin/env python3
"""Export a canonical demo-data snapshot from the live API for the GitHub
Pages build (GitHub Pages cannot run the Python backend).

Usage:
    python3 scripts/export_snapshot.py [base-url]
    # -> writes frontend/src/lib/demo-snapshot.json

The server must be bootstrapped (POST /api/demo/run?reset=true) first so the
snapshot reflects the canonical demo: 232 events / 5 findings / 37 nodes.
"""

import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/api"
OUT = "frontend/src/lib/demo-snapshot.json"


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=30) as r:
        return json.loads(r.read().decode())


def main() -> None:
    print("fetching snapshot from", BASE)
    data = {
        "meta": {
            "generated_by": "scripts/export_snapshot.py",
            "note": "Bundled demo data for the GitHub Pages preview build "
                    "(VITE_OFFLINE_DEMO=1). Regenerate against a bootstrapped "
                    "server if the demo corpus changes.",
        },
        "health": get("/health"),
        "dashboard": get("/dashboard"),
        "clients": get("/clients"),
        "alerts": get("/alerts?limit=100"),
        "network_threats": get("/network-threats?limit=100"),
        "graph": get("/graph"),
        "assets": get("/assets"),
        "compliance_mappings": get("/compliance"),
        "sample_events": get("/events/search?limit=300").get("events", []),
        "total_events": get("/events/search?limit=1").get("total", 0),
        "relations": {},
        "compliance_by_asset": {},
    }

    # Per-asset drill-downs (Asset drill-down panel + Compliance page).
    assets = data["assets"].get("assets", [])
    for a in assets:
        ip = a.get("id")
        if not ip:
            continue
        try:
            data["relations"][ip] = get(f"/assets/{ip}/relations")
        except Exception:
            data["relations"][ip] = {"asset": a, "edges": [], "findings": [],
                                     "compliance": {"controls": [],
                                                    "affected_findings": []}}
        try:
            data["compliance_by_asset"][ip] = get(f"/compliance/{ip}")
        except Exception:
            data["compliance_by_asset"][ip] = {
                "asset_id": ip, "affected_findings": [], "controls": []}

    with open(OUT, "w") as f:
        json.dump(data, f, indent=1)
    size = f"{len(json.dumps(data)) / 1024:.0f} KiB"
    print(f"wrote {OUT} ({size}), assets={len(assets)}, "
          f"sample_events={len(data['sample_events'])}")


if __name__ == "__main__":
    main()