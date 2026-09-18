"""Enricher: geo/ASN + threat-intel lookup, private-IP guard, cache + TTL.

The module is optional and fail-soft; with nothing configured every lookup must
return an empty dict and never touch the network. Private/RFC1918/whois-
reserved addresses must never be sent to any provider.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from modules.enricher import is_private_ip  # noqa: E402


def test_private_ip_detection():
    assert is_private_ip("10.1.2.3") is True
    assert is_private_ip("192.168.0.1") is True
    assert is_private_ip("172.16.9.9") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("169.254.1.1") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False
    assert is_private_ip("not-an-ip") is True  # un-parseable → never queried
    assert is_private_ip("") is True


def test_enricher_defaults_to_disabled():
    from modules.enricher import IpEnricher
    e = IpEnricher(None)
    assert e.enabled is False
    assert e.enrich("8.8.8.8") == {"geo": {}, "intel": {}}


def test_enricher_private_ips_never_lookup(monkeypatch):
    from modules.enricher import IpEnricher

    called = {"n": 0}

    def _boom(self, value):
        called["n"] += 1
        return {"geo": {"country": "X"}, "intel": {}}

    monkeypatch.setattr(IpEnricher, "_geo", _boom)
    monkeypatch.setattr(IpEnricher, "_intel", _boom)
    e = IpEnricher(None, intel_provider="abuseipdb", intel_api_key="k")
    assert e.enabled is True
    for addr in ("10.0.0.1", "192.168.1.1", "172.20.0.4", "127.0.0.1", "garbage"):
        assert e.enrich(addr) == {"geo": {}, "intel": {}}  # short-circuits
    assert called["n"] == 0


def test_enricher_cache_serves_repeat_hits(monkeypatch):
    from modules.enricher import IpEnricher

    n = {"count": 0}

    def _geo(self, value):
        n["count"] += 1
        return {"country": "US", "asn": 15169}

    monkeypatch.setattr(IpEnricher, "_geo", _geo)
    monkeypatch.setattr(IpEnricher, "_intel", lambda self, v: {})
    e = IpEnricher(None, intel_provider="abuseipdb", intel_api_key="k", ttl=3600)
    first = e.enrich("8.8.8.8")
    assert first["geo"]["asn"] == 15169
    e.enrich("8.8.8.8")
    e.enrich("8.8.8.8")
    assert n["count"] == 1  # cache absorbs the repeats


def test_enricher_ttl_expiry_refetches(monkeypatch):
    from modules.enricher import IpEnricher

    n = {"count": 0}

    def _geo(self, value):
        n["count"] += 1
        return {"country": "US"}

    monkeypatch.setattr(IpEnricher, "_geo", _geo)
    monkeypatch.setattr(IpEnricher, "_intel", lambda self, v: {})
    e = IpEnricher(None, intel_provider="abuseipdb", intel_api_key="k", ttl=0.01)
    e.enrich("1.2.3.4")
    import time
    time.sleep(0.02)
    e.enrich("1.2.3.4")
    assert n["count"] == 2


def test_unknown_intel_provider_disables(monkeypatch):
    from modules.enricher import IpEnricher
    e = IpEnricher(None, intel_provider="klextube", intel_api_key="k")
    assert e._intel_provider == ""