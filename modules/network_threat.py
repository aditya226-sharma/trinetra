"""Module A — Network Threat Detection for unidirectional IP traffic (PS26145).

Passive, flow-level analysis — **never decrypts payload** (hard constraint):
TLS/QUIC and IPsec are analysed from metadata (sizes, timing, JA3
fingerprints, DNS query names) only.

Detection approach (simple, explainable, deterministic):
  * port_scan      — one source, high dst-address/port fan-out, tiny flows
  * ddos           — high volume toward one destination, many distinct sources
  * c2_beaconing   — periodic small flows, consistent inter-arrival times
  * dga            — high-entropy DNS query names (Shannon per-char)
  * exfiltration   — asymmetric outbound byte volume beyond norms

Every finding uses the PS26145 standardized alert schema:
``{timestamp, flow_id, threat_class, confidence, evidence}`` and is written
back into UES as ``module_findings.network_threat``.
"""

from __future__ import annotations

import datetime
import ipaddress
import math
import re
import statistics
import time
from collections import Counter
from typing import Any, Dict, List, Optional

from schema import Event


def _f(event: Event, key: str, default: Any = None) -> Any:
    value = event.fields.get(key)
    return value if value is not None else default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def shannon_entropy(text: str) -> float:
    """Per-character Shannon entropy of ``text`` (bits per symbol)."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length)
                for count in counts.values() if count)


_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]
# Documentation / benchmark ranges must be treated as EXTERNAL (attacker space):
_EXTERNAL_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("100.64.0.0/10"),
]


def is_private_ip(ip: str) -> bool:
    """True iff ``ip`` is on the internal/demo-protected network.

    Python >=3.13 marks RFC documentation ranges (192.0.2/24 etc.) as
    "private", which would silently reclassify attacker space as internal,
    so private-ness is decided by explicit prefix membership instead.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(addr in net for net in _EXTERNAL_NETS):
        return False
    return any(addr in net for net in _PRIVATE_NETS)


class ThreatDetector:
    """Incremental flow analyzer. Feed it UES events; it aggregates flows in a
    fixed window and surfaces findings plus per-source statistics."""

    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = window_seconds
        self._flows: List[Dict[str, Any]] = []
        self.detection_counts: Dict[str, int] = {}
        self.processed_flows = 0

    # -- ingestion -----------------------------------------------------------
    def add_event(self, event: Event) -> None:
        """Buffer one flow event (returns nothing — run :meth:`flush` on windows)."""
        flow = event.fields.copy()
        flow["event_id"] = event.event_id
        flow["timestamp"] = event.timestamp
        flow["client_id"] = event.client_id
        self._flows.append(flow)
        self.processed_flows += 1

    def flush(self) -> List[Dict[str, Any]]:
        """Analyze all buffered flows and return the resulting findings."""
        if not self._flows:
            return []
        flows, self._flows = self._flows, []
        return self.detect_batch(flows)

    # -- analysis ------------------------------------------------------------
    def detect_batch(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        src_groups: Dict[str, List[Dict]] = {}
        dst_groups: Dict[str, List[Dict]] = {}
        pairs: Dict[tuple, List[Dict]] = {}

        for flow in flows:
            src = str(flow.get("src_ip") or "")
            dst = str(flow.get("dst_ip") or "")
            src_groups.setdefault(src, []).append(flow)
            dst_groups.setdefault(dst, []).append(flow)
            if src and dst:
                pairs.setdefault((src, dst), []).append(flow)

        # 1. Port scan / reconnaissance — high fan-out, tiny flows
        for src, group in src_groups.items():
            if not src:
                continue
            dst_ports = {_to_int(f.get("dport")) for f in group if f.get("dport")}
            dst_hosts = {f.get("dst_ip") for f in group if f.get("dst_ip")}
            avg_pkts = statistics.fmean([_to_int(f.get("pkts")) for f in group]) if group else 0
            if (len(dst_hosts) >= 6 or len(dst_ports) >= 15) and avg_pkts <= 3:
                confidence = min(0.98, 0.45 + 0.03 * max(len(dst_ports), len(dst_hosts)))
                evidence = {
                    "src": src,
                    "distinct_dst_ports": sorted(dst_ports)[:50],
                    "distinct_dst_hosts": len(dst_hosts),
                    "flows": len(group),
                    "avg_packets_per_flow": round(avg_pkts, 2),
                }
                findings.append(self._alert(flows, "port_scan", round(confidence, 2),
                                            "reconnaissance", "warning", evidence))

        # 2. Volumetric / protocol DDoS — many sources converging on an internal target
        for dst, group in dst_groups.items():
            if not dst or not is_private_ip(dst):
                continue
            srcs = {f.get("src_ip") for f in group if f.get("src_ip")}
            total_pkts = sum(_to_int(f.get("pkts")) for f in group)
            syn = sum(1 for f in group if str(f.get("flags", "")).upper().startswith("S"))
            if (total_pkts >= 120 and len(srcs) >= 4) or (syn >= 40 and len(srcs) >= 2):
                confidence = min(0.97, 0.5 + min(total_pkts / 500, 0.47))
                evidence = {"dst": dst, "unique_sources": len(srcs), "total_packets": total_pkts,
                            "syn_packets": syn, "flows": len(group)}
                findings.append(self._alert(flows, "ddos", round(confidence, 2),
                                            "denial_of_service", "critical", evidence))

        # 3. Botnet C2 beaconing — periodic small flows toward ONE external dst
        for (src, dst), group in pairs.items():
            if len(group) < 5 or not is_private_ip(src) or is_private_ip(dst):
                continue
            proto = str(group[0].get("proto") or "").lower()
            if proto not in ("tcp", "sctp"):
                continue  # UDP/DNS lookalikes are excluded from beaconing
            total_bytes = sum(_to_int(f.get("bytes")) for f in group)
            intervals = _inter_arrivals(group)
            is_periodic = bool(intervals) and (statistics.stdev(intervals) <=
                                               0.5 * (statistics.fmean(intervals) + 1e-9))
            if is_periodic and total_bytes <= 20_000:
                confidence = min(0.95, 0.45 + 0.05 * min(len(group), 10))
                evidence = {"src": src, "dst": dst, "flows": len(group),
                            "total_bytes": total_bytes,
                            "inter_arrival_mean_s": round(statistics.fmean(intervals), 2) if intervals else 0,
                            "inter_arrival_stdev_s": round(statistics.stdev(intervals), 2) if intervals else 0,
                            "proto": group[0].get("proto")}
                findings.append(self._alert(flows, "c2_beaconing", round(confidence, 2),
                                            "command_and_control", "critical", evidence))

        # 4. DGA domains / DNS tunnelling — high-entropy query names
        dns_by_src: Dict[str, List[str]] = {}
        for flow in flows:
            query = str(flow.get("dns_query") or "").strip().lower()
            if not query:
                continue
            dns_by_src.setdefault(str(flow.get("src_ip") or "?"), []).append(query)
        for src, queries in dns_by_src.items():
            risky = [q for q in queries if _dga_score(q) >= 0.75]
            if len(risky) >= 3 and len(risky) / len(queries) >= 0.6:
                confidence = 0.7 + 0.03 * min(len(risky), 9)
                evidence = {"src": src, "suspicious_queries": risky[:10],
                            "total_queries": len(queries),
                            "max_entropy": round(max(shannon_entropy(q.rstrip(".top")) for q in risky), 2)}
                findings.append(self._alert(flows, "dga_dns", round(confidence, 2),
                                            "malware", "high", evidence))

        # 5. Data exfiltration — asymmetric outbound byte volume
        for src, group in src_groups.items():
            if not src or not is_private_ip(src):
                continue
            outbound = [(f, _to_int(f.get("bytes"))) for f in group
                        if f.get("dst_ip") and not is_private_ip(str(f.get("dst_ip")))]
            total_bytes = sum(b for _, b in outbound)
            if total_bytes >= 500_000:
                inbound_bytes = sum(_to_int(f.get("bytes")) for f in group
                                    if f.get("dst_ip") and is_private_ip(str(f.get("dst_ip"))))
                ratio = total_bytes / (inbound_bytes + 1)
                if ratio >= 5.0:
                    confidence = min(0.96, 0.5 + math.log10(total_bytes / 100_000) * 0.1)
                    evidence = {"src": src, "outbound_bytes": total_bytes,
                                "outbound_flows": len(outbound),
                                "dst_ips": sorted({f[0].get("dst_ip") for f in outbound})[:10],
                                "out_in_ratio": round(ratio, 1)}
                    findings.append(self._alert(flows, "data_exfiltration", round(confidence, 2),
                                                "data_exfiltration", "critical", evidence))

        for finding in findings:
            self.detection_counts[finding["threat_class"]] = \
                self.detection_counts.get(finding["threat_class"], 0) + 1
        return findings

    # -- alert schema (PS26145) ----------------------------------------------
    def _alert(self, flows: List[Dict], threat_class: str, confidence: float,
               threat_category: str, severity: str, evidence: Dict) -> Dict[str, Any]:
        timestamp = flows[0].get("timestamp") if flows else time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        first = flows[0] if flows else {}
        flow_id = first.get("event_id") or f"flow::{first.get('src_ip', '?')}->{first.get('dst_ip', '?')}"
        event_ids = sorted({str(f.get("event_id")) for f in flows if f.get("event_id")})
        return {
            "threat_class": threat_class,
            "threat_category": threat_category,
            "confidence": confidence,
            "severity": severity,
            "flow_id": flow_id,
            "event_ids": event_ids,
            "evidence": evidence,
            "alert": {
                "timestamp": timestamp,
                "flow_id": flow_id,
                "threat_class": threat_class,
                "threat_category": threat_category,
                "confidence": confidence,
                "severity": severity,
                "evidence": evidence,
            },
        }


# ---------------------------------------------------------------------- utils


def _inter_arrivals(flows: List[Dict[str, Any]]) -> List[float]:
    """Seconds between consecutive flows of a pair (using each flow's timestamp)."""
    stamps = []
    for flow in flows:
        parsed = _parse_ts(flow.get("timestamp"))
        if parsed is not None:
            stamps.append(parsed)
    stamps.sort()
    if len(stamps) < 3:
        return []
    return [b - a for a, b in zip(stamps, stamps[1:]) if b - a >= 0]


def _parse_ts(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    match = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", str(value))
    if not match:
        return None
    try:
        dt = datetime.datetime(*[int(g) for g in match.groups()])
        return dt.timestamp()
    except (TypeError, ValueError):
        return None


def _dga_score(query: str) -> float:
    """Heuristic DGA likelihood 0..1 from per-char entropy and length."""
    label = query
    for suffix in (".top", ".info", ".xyz", ".icu", ".club", ".site", ".com", ".net"):
        if label.endswith(suffix):
            label = label[: -len(suffix)]
            break
    if not label:
        return 0.0
    entropy = shannon_entropy(label)
    ratio = entropy / math.log2(min(len(label), 26) + 1)
    length_bonus = 0.2 if len(label) >= 12 else 0.0
    return min(1.0, ratio + length_bonus)