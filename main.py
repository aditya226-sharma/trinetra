#!/usr/bin/env python3
"""TriNetra — universal log pre-processing framework with multi-domain AI
threat intelligence. CLI orchestrator (also importable by the FastAPI app).

Quickstart
----------
    python main.py --demo                # full offline storyline
    python main.py --demo --json         # machine-readable summary
    python main.py --pcap data/pcaps     # run Module B on PCAP captures
    python main.py --replay flows.jsonl  # replay NetFlow-ish JSONL dataset

Pipeline per raw line
---------------------
collector ─▶ raw_store (lossless, trace_id) ─▶ normalizer (UES)
         ─▶ batcher (fingerprint dedup) ─▶ modules A/B/C
         ─▶ analyzer (prefilter gate + backend) ─▶ notifier
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from typing import List, Optional

from config.settings import get_settings
from orchestrator import Orchestrator

log = logging.getLogger("trinetra")


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="trinetra", description="TriNetra ULPF orchestrator")
    parser.add_argument("--demo", action="store_true", help="run the offline demo storyline")
    parser.add_argument("--json", action="store_true", help="emit summary as JSON")
    parser.add_argument("--pcap", default=None, help="directory of .pcap files for Module B")
    parser.add_argument("--replay", default=None, help="JSONL flow dataset to replay")
    parser.add_argument("--backend", default=None,
                        help="analyzer backend: heuristic (default) | claude | local")
    parser.add_argument("--max-events", type=int, default=None, help="stop after N non-duplicate events")
    parser.add_argument("--delay", type=float, default=0.0, help="seconds between demo lines")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(level=logging.WARNING,
                        format="%(levelname)-7s %(name)s - %(message)s")
    settings = get_settings()
    orch = Orchestrator(settings, backend_name=args.backend)

    if args.pcap:
        summary = orch.run_vpn_module(args.pcap)
        _emit(summary if args.json else orch.summary(), args.json)
        return 0

    if args.demo:
        from collectors.demo_feed import DemoFeed

        # Generate PCR fixtures for Module B first.
        pcap_dir = str(settings.path("pcap"))
        paths = DemoFeed.generate_pcaps(pcap_dir)
        orch.run_vpn_module(pcap_dir)
        log.info("Module B assessed %d pcap fixture(s): %s", len(paths), paths)

        feed = DemoFeed()
        started = time.monotonic()
        for raw, source, client, host in feed.iterate(delay=args.delay):
            if args.max_events and orch.stats["events"] >= args.max_events:
                break
            orch.ingest(raw, source, client, host)
        for alert in orch.flush_batch():
            print("ALERT:", alert, file=sys.stderr if args.json else sys.stdout)
        elapsed = time.monotonic() - started
        orch.stats["run_seconds"] = round(elapsed, 2)
        _emit(orch.summary(), args.json)
        return 0

    if args.replay:
        from collectors.flow_collector import FlowCollector

        collector = FlowCollector(replay_path=args.replay)
        started = time.monotonic()
        for raw, source, client, host in collector.iterate():
            if args.max_events and orch.stats["events"] >= args.max_events:
                break
            orch.ingest(raw, source, client, host)
            for alert in orch.flush_batch():
                print("ALERT:", alert)
        orch.stats["run_seconds"] = round(time.monotonic() - started, 2)
        _emit(orch.summary(), args.json)
        return 0

    print("Nothing to do. Try: python main.py --demo", file=sys.stderr)
    return 2


def _emit(summary: Dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(summary, indent=2, default=str))
        return
    s = summary.get("stats", {})
    print(f"\nTriNetra run complete")
    print(f"  raw lines received : {s.get('raw_lines', 0)}")
    print(f"  unique events      : {s.get('events', 0)}  (dup rate "
          f"{summary.get('dedup_rate', 0) * 100:.1f}%)")
    print(f"  module findings    : {s.get('findings', 0)}  (alerts sent: {s.get('alerts_sent', 0)})")
    print(f"  threat classes     : {summary.get('threat_detections', {})}")
    graph = summary.get("graph", {})
    print(f"  graph nodes/edges  : {graph.get('nodes')}/{graph.get('edges')}  "
          f"impacted: {graph.get('threatened', [])}")
    vpn = summary.get("vpn", {})
    for profile in vpn.get("profiles", []):
        print(f"  VPN {profile.get('file', '?')}: ike={profile.get('ike_version')} "
              f"encr={profile.get('encryption')} integ={profile.get('integrity')} "
              f"dh={profile.get('dh_group')} pfs={profile.get('pfs')}")


if __name__ == "__main__":
    sys.exit(main())