"""Module A tests — deterministic threat detections from metadata-only flows."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from schema import Event, new_uuid
from modules.network_threat import ThreatDetector, _dga_score


def flow(src, dst, sport, dport, pkts=1, bytes_=100, proto="tcp",
         flags="S", dns=None, ts="2026-09-10T12:00:00Z"):
    return Event(event_id=new_uuid(), client_id="trinetra-core",
                 source_type="netflow", category="flow", severity="info",
                 timestamp=ts, message="flow",
                 fields={"src_ip": src, "dst_ip": dst, "sport": sport,
                         "dport": dport, "pkts": pkts, "bytes": bytes_,
                         "flags": flags, "proto": proto, "dns_query": dns})


def test_port_scan_detected():
    td = ThreatDetector()
    for p in range(1, 20):
        td.add_event(flow("203.0.113.5", "10.10.1.10", p, 8080 + p,
                          ts=f"2026-09-10T12:00:0{p % 10}Z"))
    classes = {f["threat_class"] for f in td.flush()}
    assert "port_scan" in classes


def test_c2_beaconing_detected():
    td = ThreatDetector()
    for i in range(8):
        td.add_event(flow("10.10.1.50", "198.51.100.9", 4444, 443, bytes_=700,
                          flags="SA",
                          ts=f"2026-09-10T14:{(10 + i // 2):02d}:{i % 2 * 30 + 15:02d}Z"))
    classes = {f["threat_class"] for f in td.flush()}
    assert "c2_beaconing" in classes


def test_no_internal_beaconing_fp():
    """Internal-to-internal periodic pairs must NOT be beaconing."""
    td = ThreatDetector()
    for i in range(8):
        td.add_event(flow("10.10.1.21", "10.10.1.99", 4444, 443, bytes_=700,
                          flags="SA",
                          ts=f"2026-09-10T14:{(10 + i // 2):02d}:{i % 2 * 30 + 15:02d}Z"))
    assert all(f["threat_class"] != "c2_beaconing" for f in td.flush())


def test_dga_dns_detected_and_honest_domain_clean():
    td = ThreatDetector()
    for i in range(5):
        td.add_event(flow("10.10.1.50", "8.8.8.8", 53000, 53, proto="udp",
                          dns=f"x{i}kq{32 + i}w{30 + i * 3}ztu09{i}.top",
                          ts=f"2026-09-10T15:0{i}:30Z"))
    classes = {f["threat_class"] for f in td.flush()}
    assert "dga_dns" in classes
    assert _dga_score("google.com") < 0.75  # honest domain stays below threshold


def test_data_exfiltration_detected():
    td = ThreatDetector()
    for i in range(3):
        td.add_event(flow("10.10.1.50", "192.0.2.199", 50000 + i, 8080,
                          pkts=2000, bytes_=720000,
                          ts=f"2026-09-10T16:{10 + i * 10}:00Z"))
    classes = {f["threat_class"] for f in td.flush()}
    assert "data_exfiltration" in classes


def test_ddos_detected_on_internal_target():
    td = ThreatDetector()
    for j in range(6):
        for i in range(12):
            td.add_event(flow(f"10.10.1.{30 + j}", "10.10.1.10", 48000 + i, 80,
                              pkts=12, bytes_=1200,
                              ts=f"2026-09-10T13:0{j % 8}:{i % 50:02d}Z"))
    classes = {f["threat_class"] for f in td.flush()}
    assert "ddos" in classes


def test_alert_schema_has_required_keys():
    td = ThreatDetector()
    for p in range(1, 20):
        td.add_event(flow("203.0.113.5", "10.10.1.10", p, 8080 + p))
    findings = td.flush()
    assert findings
    alert = findings[0]["alert"]
    for key in ("timestamp", "flow_id", "threat_class", "confidence", "evidence"):
        assert key in alert


def test_is_private_ip_excludes_doc_ranges():
    from modules.network_threat import is_private_ip
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("192.168.1.1") is True
    # Documentation ranges must be treated as external (attacker space).
    assert is_private_ip("192.0.2.1") is False
    assert is_private_ip("198.51.100.7") is False
    assert is_private_ip("203.0.113.5") is False