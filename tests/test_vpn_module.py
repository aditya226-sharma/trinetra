"""Module B tests — IKE/ESP pcap assessment (round-trip with pcapgen)."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from collectors.demo_feed import DemoFeed
from modules.vpn_assessment import assess_vpn_directory


def _login_headers(client):
    """Seed admin + return bearer headers (startup seeds admin/admin)."""
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    d = tmp_path_factory.mktemp("pcaps")
    paths = DemoFeed.generate_pcaps(str(d))
    results = assess_vpn_directory(str(d))
    return d, paths, results


def test_generates_both_fixtures(generated):
    _, paths, _ = generated
    assert len(paths) == 2
    assert all(Path(p).exists() for p in paths)


def test_strong_profile_scores_high(generated):
    _, _, results = generated
    strong = next(r for r in results
                  if r["source_path"].endswith("ipsec_strong.pcap"))
    assert strong["security_score"] >= 80
    assert strong["risk_level"] == "low"
    profile = strong["profile"]
    assert profile["ike_version"] == 2
    assert profile["encryption"] in ("AES-GCM-16", "AES-GCM-256")
    assert profile["pfs"] == "yes"
    assert profile["mode"] == "tunnel"
    assert profile["sa_lifetime"] == 28800


def test_weak_profile_scores_low(generated):
    _, _, results = generated
    weak = next(r for r in results
                if r["source_path"].endswith("ipsec_weak.pcap"))
    assert weak["security_score"] <= 40
    assert weak["risk_level"] in ("critical", "high")
    profile = weak["profile"]
    assert profile["ike_version"] == 1
    assert profile["encryption"] == "3DES"
    assert profile["dh_group"] == "DH-2"
    assert profile["sa_lifetime"] == 900


def test_results_carry_recommendations(generated):
    """Weak profile must produce hardening advice; strong may have none."""
    _, _, results = generated
    for result in results:
        assert result["confidence"] > 0
        weak = next(r for r in results
                    if r["source_path"].endswith("ipsec_weak.pcap"))
        assert weak["recommendations"]

# ---------------------------------------------------------------------------
# Wiring: the module was correct but never re-run after a restart, so the
# dashboard's "VPN / IPsec gateway assessment" section was permanently empty
# even with the captures sitting on disk. These tests cover the plumbing the
# round-trip tests above cannot see.
# ---------------------------------------------------------------------------

def test_run_vpn_module_populates_orchestrator_profiles(generated):
    """run_vpn_module must expose the keys the dashboard/UI actually read."""
    from config.settings import Settings as TSettings
    from orchestrator import Orchestrator

    d, _, _ = generated
    orch = Orchestrator(TSettings())
    assert orch.vpn_profiles == []

    out = orch.run_vpn_module(str(d))
    assert out["profiles_count"] == 2
    assert len(orch.vpn_profiles) == 2
    assert orch.stats["vpn_profiles"] == 2

    for p in orch.vpn_profiles:
        # every field the DashboardPage VPN card dereferences
        for key in ("file", "ike_version", "encryption", "key_length",
                    "integrity", "prf", "dh_group", "pfs", "mode",
                    "sa_lifetime", "replay", "security_score", "risk_level",
                    "confidence", "recommendations"):
            assert key in p, f"profile missing {key!r} (UI reads it)"
        assert p["file"].endswith(".pcap")
        assert 0 <= p["security_score"] <= 100

    files = {p["file"] for p in orch.vpn_profiles}
    assert files == {"ipsec_strong.pcap", "ipsec_weak.pcap"}
    strong = next(p for p in orch.vpn_profiles if p["file"] == "ipsec_strong.pcap")
    weak = next(p for p in orch.vpn_profiles if p["file"] == "ipsec_weak.pcap")
    assert strong["security_score"] >= 80 and strong["risk_level"] == "low"
    assert weak["security_score"] <= 40 and weak["risk_level"] in ("critical", "high")
    assert weak["recommendations"], "weak gateway must surface hardening advice"


def test_dashboard_exposes_vpn_profiles_after_module_runs(generated):
    """GET /api/dashboard must carry a populated vpn.profiles list."""
    import backend.app.main as api_module
    from fastapi.testclient import TestClient

    d, _, _ = generated
    with TestClient(api_module.app) as client:          # boots -> _ORCH
        headers = _login_headers(client)
        api_module._ORCH.run_vpn_module(str(d))
        body = client.get("/api/dashboard", headers=headers)
        assert body.status_code == 200
        profiles = body.json()["vpn"]["profiles"]
        assert len(profiles) == 2
        assert {p["file"] for p in profiles} == {"ipsec_strong.pcap", "ipsec_weak.pcap"}
        api_module._ORCH.vpn_profiles = []
        api_module._ORCH.stats["vpn_profiles"] = 0


def test_boot_restores_vpn_profiles_from_disk(generated):
    """Regression: lifespan() must re-assess captures on boot.

    vpn_profiles lives only in memory and is derived from .pcap files rather
    than the event store, so without the boot-time re-assessment the section
    was empty after every restart.
    """
    from pathlib import Path as _Path
    import backend.app.main as api_module
    from fastapi.testclient import TestClient

    d, _, _ = generated
    settings = api_module._settings
    saved = settings._data.get("paths", {}).get("pcap")
    settings._data.setdefault("paths", {})["pcap"] = str(d)
    assert any(_Path(str(d)).glob("*.pcap")), "fixture captures should exist"
    try:
        api_module._ORCH = None      # force the boot path to run again
        with TestClient(api_module.app) as client:
            body = client.get("/api/dashboard", headers=_login_headers(client))
        profiles = body.json()["vpn"]["profiles"]
        assert len(profiles) == 2, "boot must re-assess captures into vpn.profiles"
        assert {p["file"] for p in profiles} == {"ipsec_strong.pcap", "ipsec_weak.pcap"}
    finally:
        api_module._ORCH.vpn_profiles = []
        api_module._ORCH.stats["vpn_profiles"] = 0
        if saved is None:
            settings._data.get("paths", {}).pop("pcap", None)
        else:
            settings._data["paths"]["pcap"] = saved


def test_no_pcap_dir_leaves_profiles_empty_without_raising(tmp_path):
    """A missing/empty capture dir must not raise during boot."""
    from config.settings import Settings as TSettings
    from orchestrator import Orchestrator

    orch = Orchestrator(TSettings())
    out = orch.run_vpn_module(str(tmp_path / "does-not-exist"))
    assert out["profiles_count"] == 0
    assert orch.vpn_profiles == []


def test_graph_edge_counter_stays_exact_at_cap():
    """Regression: the O(1) edge counter must match the real graph size.

    ``_bump_edge``/``_bump_comm``/``_add_edge`` used to call
    ``MultiDiGraph.number_of_edges()`` (an O(E) walk) once per event, making a
    65k-event store replay take ~27 min at boot. They now compare against a
    counter kept in ``_add_edge``, so it must never drift or the cap breaks.
    """
    from config.settings import Settings as TSettings
    from modules.entity_graph import EntityGraph
    from orchestrator import Orchestrator
    from schema import Event, new_uuid

    g = EntityGraph(max_nodes=5000, max_edges=40)
    orch = Orchestrator(TSettings())
    try:
        for i in range(400):
            e = Event(event_id=new_uuid(), client_id="c", source_type="netflow",
                      category="flow", severity="info",
                      timestamp="2026-09-10T12:00:00Z", message="m",
                      fields={"src_ip": f"10.0.{i // 250}.{i % 250}",
                              "dst_ip": f"198.51.100.{i % 200}", "proto": "tcp"})
            g.add_event(e)
            # counter must track the real graph at every step
            assert g._edge_total == g.graph.number_of_edges()
        # cap enforced, and we never exceeded it
        assert g.graph.number_of_edges() <= g.max_edges
        assert g._edge_total == g.graph.number_of_edges()
    finally:
        del orch
