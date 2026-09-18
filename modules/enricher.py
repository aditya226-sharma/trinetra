"""Information enrichment — geo/ASN + external threat-intel on demand.

TriNetra calls the dataset it already has the "event store"; enrichment pulls
in *outside* context about an involved IP so an incident drawer can show where
a host lives and whether external intel flags it.

Both providers are opt-in and fail-soft:

  * Geo/ASN  — MaxMind GeoLite2-City.mmdb when ``paths.geo_db`` is configured
               (lookup only, never ships data out).
  * Threat intel — AbuseIPDB or VirusTotal when an API key is set; only the
               queried IP is sent, and only for public (non-RFC1918) addresses.

Everything is cached in-memory with a TTL so repeat lookups (the incident
drawer polls every few seconds) never re-hit a provider. Any error degrades to
an empty enrichment dict — enrichment must never break a page.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger("trinetra.enricher")

_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)

_DEFAULT_TTL = 3600
_DEFAULT_TIMEOUT = 4


def is_private_ip(value: str) -> bool:
    """True for RFC1918 / loopback / link-local addresses — never queried."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return True
    if not ip.is_global:
        return True
    return any(ip in net for net in _PRIVATE_NETS)


class IpEnricher:
    """Fetches and caches geo/ASN (local MMDB) + threat-intel (remote API)."""

    def __init__(self, settings, db_path: str = "",
                 intel_provider: str = "", intel_api_key: str = "",
                 ttl: int = _DEFAULT_TTL, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self._settings = settings
        self._ttl = float(ttl)
        self._timeout = float(timeout)
        self._geo_reader = None
        if db_path:
            try:
                from maxminddb import open_database  # type: ignore
                self._geo_reader = open_database(str(Path(db_path)))
                log.info("geo enrichment loaded from %s", db_path)
            except Exception as exc:  # noqa: BLE001 — optional feature
                log.warning("geo db not usable (%s); geo disabled", exc)
        self._intel_provider = str(intel_provider).lower()
        self._intel_api_key = str(intel_api_key or "")
        valid = {"", "abuseipdb", "virustotal"}
        if self._intel_provider not in valid:
            log.warning("unknown intel provider %r (use abuseipdb|virustotal)", self._intel_provider)
            self._intel_provider = ""
        self._lock = threading.Lock()
        self._cache: Dict[str, tuple] = {}  # ip -> (expires_at, payload)

    # -------------------------------------------------------------- lookup

    def enrich(self, value: str) -> Dict[str, Any]:
        """Return {'geo': {...}, 'intel': {...}} — always a dict, never raises."""
        value = str(value or "").strip()
        if is_private_ip(value):
            return {"geo": {}, "intel": {}}
        out: Dict[str, Any] = {"geo": {}, "intel": {}}
        with self._lock:
            hit = self._cache.get(value)
            if hit and hit[0] > time.time():
                geo, intel = hit[1]
            else:
                geo = self._geo(value)
                intel = self._intel(value)
                self._cache[value] = (time.time() + self._ttl, (geo, intel))
        out["geo"] = geo
        out["intel"] = intel
        return out

    @property
    def enabled(self) -> bool:
        return bool(self._geo_reader or (self._intel_api_key and self._intel_provider))

    # ---------------------------------------------------------------- geo

    def _geo(self, ip: str) -> Dict[str, Any]:
        if self._geo_reader is None:
            return {}
        try:
            rec = self._geo_reader.get(ip) or {}
            out: Dict[str, Any] = {}
            country = rec.get("country") or {}
            if country.get("iso_code"):
                out["country"] = str(country["iso_code"])
                out["country_name"] = str((country.get("names") or {}).get("en") or country["iso_code"])
            city = rec.get("city") or {}
            if city.get("names") and (city["names"].get("en")):
                out["city"] = str(city["names"]["en"])
            loc = rec.get("location") or {}
            for key, label in (("latitude", "lat"), ("longitude", "lon")):
                if loc.get(key) is not None:
                    out[label] = loc[key]
            asn = rec.get("autonomous_system_number")
            if asn is not None:
                out["asn"] = asn
                out["as_org"] = str((rec.get("autonomous_system_organization") or "") or "")
            return out
        except Exception as exc:  # noqa: BLE001
            log.warning("geo lookup failed for %s: %s", ip, exc)
            return {}

    # --------------------------------------------------------------- intel

    def _intel(self, ip: str) -> Dict[str, Any]:
        if not (self._intel_api_key and self._intel_provider):
            return {}
        try:
            if self._intel_provider == "abuseipdb":
                return self._abuseipdb(ip)
            if self._intel_provider == "virustotal":
                return self._virustotal(ip)
        except Exception as exc:  # noqa: BLE001
            log.warning("intel lookup failed for %s: %s", ip, exc)
        return {}

    def _get_json(self, url: str, headers: Optional[Dict[str, str]]) -> Optional[Dict[str, Any]]:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    def _abuseipdb(self, ip: str) -> Dict[str, Any]:
        url = ("https://api.abuseipdb.com/api/v2/check"
               + f"?ipAddress={ip}&maxAgeInDays=90")
        data = self._get_json(url, {"Key": self._intel_api_key,
                                    "Accept": "application/json"}) or {}
        rec = data.get("data") or {}
        score = int(rec.get("abuseConfidenceScore") or 0)
        verdict = "malicious" if score >= 75 else ("suspicious" if score >= 30 else "clean")
        return {
            "source": "abuseipdb",
            "verdict": verdict,
            "confidence": score,
            "abuse_confidence": rec.get("abuseConfidenceScore"),
            "total_reports": rec.get("totalReports"),
            "last_reported": rec.get("lastReportedAt"),
            "is_whitelisted": rec.get("isWhitelisted"),
            "usage_type": rec.get("usageType"),
            "is_flagged": bool(score >= 50),
        }

    def _virustotal(self, ip: str) -> Dict[str, Any]:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        data = self._get_json(url, {"x-apikey": self._intel_api_key}) or {}
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        verdicts = attrs.get("last_analysis_results") or {}
        malicious = int(stats.get("malicious") or 0)
        flagged = sum(1 for v in verdicts.values() if (v or {}).get("category", "").lower()
                      in ("malicious", "suspicious"))
        # Normalized contract the incident drawer renders: verdict + confidence
        # (0-100) + source, alongside the raw engine stats.
        total = int(stats.get("total") or 1)
        malicious_share = (malicious + flagged) / max(total, 1)
        verdict = ("malicious" if malicious_share >= 0.2
                   else "suspicious" if malicious_share > 0 else "clean")
        confidence = int(round(malicious_share * 100))
        return {
            "source": "virustotal",
            "verdict": verdict,
            "confidence": confidence,
            "malicious": malicious,
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total": total,
            "flagged_vendors": flagged,
            "is_flagged": bool(malicious + flagged > 0),
            "last_analysis": attrs.get("last_analysis_date"),
        }


def build_enricher(settings) -> IpEnricher:
    """Construct an enricher from settings/config (all optional)."""
    return IpEnricher(
        settings,
        db_path=str(settings.get("enrichment.geo.db_path") or ""),
        intel_provider=str(settings.get("enrichment.intel.provider") or ""),
        intel_api_key=str(settings.get("enrichment.intel.api_key") or ""),
        ttl=int(settings.get("enrichment.ttl", _DEFAULT_TTL)),
        timeout=int(settings.get("enrichment.timeout", _DEFAULT_TIMEOUT)),
    )