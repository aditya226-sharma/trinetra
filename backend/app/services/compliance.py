"""Compliance mapping — threat detections to control families (PS26189).

Every Module A/B/C finding maps to a control-family mapping used by the
compliance workflow:

  * NIST CSF function + subcategory (detect / respond)
  * CIS Controls v8 safeguard ids
  * MITRE ATT&CK technique ids for lateral-movement drill-down

The mapping endpoint returns, per asset, a structured list of
``{framework, control, description, status}`` entries plus a human-readable
markdown summary the analyst can paste into a report.
"""

from __future__ import annotations

from typing import Any, Dict, List

MAPPINGS: Dict[str, Dict[str, Any]] = {
    "port_scan": {
        "nist": "DE.CM-7 (Monitoring for unauthorized personnel, connections, devices, and software)",
        "cis": ["CIS v8 4.2", "CIS v8 4.7"],
        "attack": ["T1046 - Network Service Scanning"],
        "label": "Reconnaissance activity against the protected network.",
    },
    "ddos": {
        "nist": "PR.DS-5 (Data integrity) / DE.AE-2 (Event sequences)",
        "cis": ["CIS v8 12.4", "CIS v8 13.1", "CIS v8 13.2"],
        "attack": ["T1498 - Network Denial of Service"],
        "label": "Volumetric flood targeting an internal service.",
    },
    "c2_beaconing": {
        "nist": "DE.CM-1 (Network) / RS.RP-1 (Response plan)",
        "cis": ["CIS v8 13.1", "CIS v8 13.6", "CIS v8 16.1"],
        "attack": ["T1071.001 - Application Layer Protocol: Web Protocols"],
        "label": "Periodic encrypted call-homes from an internal host.",
    },
    "dga_dns": {
        "nist": "DE.AE-3 (Attack patterns) / DE.CM-4 (Malicious code)",
        "cis": ["CIS v8 13.3", "CIS v8 8.2"],
        "attack": ["T1568.002 - Domain Generation Algorithms"],
        "label": "High-entropy DNS query names indicative of DGA / tunnelling.",
    },
    "data_exfiltration": {
        "nist": "DE.CM-1 / DE.AE-2",
        "cis": ["CIS v8 13.10", "CIS v8 3.11"],
        "attack": ["T1048 - Exfiltration Over Alternative Protocol"],
        "label": "Asymmetric outbound volume from an internal host.",
    },
    "weak_ipsec_config": {
        "nist": "PR.AC-3 (Remote access) / DE.CM-1",
        "cis": ["CIS v8 4.4", "CIS v8 12.1"],
        "attack": ["T1021.004 - Remote Services: SSH", "T1552 - Unsecured Credentials (context)"],
        "label": "IPsec/IKE peer negotiated weak cryptography.",
    },
    "vpn_ok": {
        "nist": "PR.AC-3 (Remote access)",
        "cis": ["CIS v8 12.1"],
        "attack": [],
        "label": "VPN gateway configuration assessed healthy.",
    },
}

_DEFAULT = {
    "nist": "N/A",
    "cis": [],
    "attack": [],
    "label": "Observed anomaly; further correlation required.",
}


def mapping_for(threat_class: str) -> Dict[str, Any]:
    return MAPPINGS.get(threat_class, _DEFAULT)


def compliance_for_asset(asset_id: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the compliance payload for one asset from its findings list."""
    entries: List[Dict[str, Any]] = []
    affected_findings: List[Dict[str, Any]] = []
    for finding in findings:
        threat_class = finding.get("threat_class") or "unknown"
        if not _finding_touches(finding, asset_id):
            continue
        affected_findings.append(finding)
        control = mapping_for(threat_class)
        entries.append({
            "threat_class": threat_class,
            "severity": finding.get("severity", "high"),
            "confidence": finding.get("confidence", 0.5),
            "nist_csf": control["nist"],
            "cis_controls": control["cis"],
            "mitre_attack": control["attack"],
            "status": "action_required" if finding.get("severity") in ("high", "critical") else "monitor",
        })
    return {
        "asset_id": asset_id,
        "affected_findings": affected_findings,
        "controls": entries,
        "summary_markdown": _markdown(asset_id, entries),
    }


def _finding_touches(finding: Dict[str, Any], asset_id: str) -> bool:
    alert = finding.get("alert", finding)
    evidence = alert.get("evidence") or {}
    needle = asset_id
    if evidence.get("src") == needle or evidence.get("dst") == needle:
        return True
    if alert.get("src") == needle or alert.get("dst") == needle:
        return True
    return False


def _markdown(asset_id: str, entries: List[Dict[str, Any]]) -> str:
    if not entries:
        return f"### {asset_id}\n\nNo threat findings mapped to this asset."
    lines = [f"### Compliance mapping — {asset_id}"]
    for entry in entries:
        lines.append(f"\n- **{entry['threat_class']}** ({entry['severity']})")
        lines.append(f"  - NIST CSF: {entry['nist_csf']}")
        lines.append(f"  - CIS: {', '.join(entry['cis_controls']) or 'n/a'}")
        lines.append(f"  - MITRE ATT&CK: {', '.join(entry['mitre_attack']) or 'n/a'}")
        lines.append(f"  - Status: {entry['status']}")
    return "\n".join(lines)