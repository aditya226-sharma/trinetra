"""Module B tests — IKE/ESP pcap assessment (round-trip with pcapgen)."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from collectors.demo_feed import DemoFeed
from modules.vpn_assessment import assess_vpn_directory


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