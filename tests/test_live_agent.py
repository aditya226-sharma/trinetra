"""Regression tests for the live log agent (scripts/live_agent.py).

Two bugs these lock down:

1. Events that carried IPs only inside the message string produced an empty
   entity graph, because enrichment keys on ``fields`` (``src_ip``/``dst_ip``/
   ``dns_query``), not on the rendered text.
2. Isolated random events never tripped a network-threat rule: the detector
   only alerts on *correlated* traffic, and ``orchestrator`` only routes
   ``category == "flow"`` events into ``ThreatDetector`` at all.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from schema import Event  # noqa: E402
from modules.network_threat import ThreatDetector  # noqa: E402
import live_agent as la  # noqa: E402


def _as_event(d):
    return Event(event_id=d["event_id"], timestamp=d["timestamp"],
                 source_type=d["source"], client_id=d["client_id"],
                 category=d["category"], severity=d["level"],
                 message=d["message"], raw_event=d["raw"],
                 fields=d["metadata"])


@pytest.mark.parametrize("client_id", sorted(la.FLEET))
def test_events_carry_structured_ip_fields(client_id):
    """IPs must reach enrichment in metadata, not only in the message text."""
    for _ in range(40):
        fields = la._fields_for("flow", "flow", "info", client_id, False)
        assert fields.get("src_ip"), "flow events need fields.src_ip for graph edges"
        assert fields.get("dst_ip"), "flow events need fields.dst_ip for graph edges"
        assert fields["src_ip"] not in fields["host"]


def test_dns_and_auth_fields_present():
    net = la._fields_for("cef", "network", "critical", "edge-fw-01", True)
    assert net.get("dns_query"), "threat network events need dns_query for DGA"
    auth = la._fields_for("auth", "auth", "warning", "auth-srv", True)
    assert auth.get("user"), "auth events need fields.user for auth edges"
    assert auth.get("src_ip")


@pytest.mark.parametrize("kind", la.SCENARIOS)
def test_burst_is_routed_to_threat_detector(kind):
    """Every burst must use category='flow' or the orchestrator drops it."""
    burst = la._burst("edge-fw-01", kind)
    assert burst
    for d in burst:
        assert d["category"] == "flow", (
            "orchestrator only feeds category=='flow' into ThreatDetector")


@pytest.mark.parametrize("kind,expected", [
    ("port_scan", "port_scan"),
    ("ddos", "ddos"),
    ("c2_beacon", "c2_beaconing"),
    ("dga", "dga_dns"),
])
def test_scenario_trips_real_detector(kind, expected):
    td = ThreatDetector()
    for d in la._burst("edge-fw-01", kind):
        td.add_event(_as_event(d))
    classes = {f["threat_class"] for f in td.flush()}
    assert expected in classes


def test_c2_beacon_is_periodic():
    """Beacon flows must share a timestamp so inter-arrival variance is 0."""
    ts = {d["timestamp"] for d in la._burst("edge-fw-01", "c2_beacon")}
    assert len(ts) == 1
