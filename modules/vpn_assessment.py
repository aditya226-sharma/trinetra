"""Module B — VPN/IPsec Security Assessment (PS26160).

Passive analysis of packet captures containing IKE negotiation + ESP traffic.
Never decrypts payload — everything is protocol metadata (a hard requirement
of PS26145 that we reuse here as a privacy-preserving posture).

Pipeline:
  1. read a PCAP (pure-Python, no scapy dependency)
  2. parse IKEv1/IKEv2 SA proposal/transform substructures
  3. score the profile against a rule-based rubric (crypto strength, PFS,
     SA lifetime, replay protection, mode, protocol version)
  4. emit a structured finding that gets written back into UES
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.ipsec_ids import (
    CONVENTION_ATTR,
    IKEV1_ATTR,
    IKEV1_MODE,
    IKEV2_TTYPE,
    encr_lookup,
    group_str,
    hash_lookup,
)

# ------------------------------------------------------------------ pcap io


@dataclass
class Pkt:
    ts: float
    src_ip: str
    dst_ip: str
    proto: int
    sport: int = 0
    dport: int = 0
    payload: bytes = b""


def read_pcap(path: str | Path) -> List[Pkt]:
    """Parse a (possibly both-endian) pcap file into ``Pkt`` records."""
    packets: List[Pkt] = []
    with open(path, "rb") as fh:
        magic = fh.read(4)
        if len(magic) < 4:
            return packets
        le = False
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            le = True
            if magic == b"\x4d\x3c\xb2\xa1":
                le = False
        fmt = "<" if (magic in (b"\xd4\xc3\xb2\xa1",) or magic == b"\x4d\x3c\xb2\xa1") else ">"
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            pass
        else:
            return packets
        fh.seek(4)
        rest = fh.read(20)
        if len(rest) < 20:
            return packets
        _v_maj, _v_min, _this, _sig, _snap, _link = struct.unpack(fmt + "HHIIII", rest)
        while True:
            header = fh.read(16)
            if len(header) < 16:
                break
            ts_sec, ts_usec, incl_len, _orig = struct.unpack(fmt + "IIII", header)
            body = fh.read(incl_len)
            if len(body) < incl_len:
                break
            pkt = _parse_eth_ip(body)
            if pkt is not None:
                pkt.ts = ts_sec + ts_usec / 1_000_000
                packets.append(pkt)
    return packets


def _parse_eth_ip(body: bytes) -> Optional[Pkt]:
    if len(body) < 14:
        return None
    ethertype = body[12:14]
    ip = body[14:]
    if ethertype == b"\x08\x06":  # ARP
        return None
    if ethertype != b"\x08\x00" and ethertype != b"\x86\xdd":
        return None
    if ethertype == b"\x86\xdd":  # IPv6 — skip for the prototype
        return None
    return _parse_ipv4(ip)


def _parse_ipv4(ip: bytes) -> Optional[Pkt]:
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl:
        return None
    total_len = struct.unpack("!H", ip[2:4])[0]
    header = ip[:ihl]
    src = ".".join(str(b) for b in header[12:16])
    dst = ".".join(str(b) for b in header[16:20])
    proto = header[9]
    payload = ip[ihl:total_len] if total_len >= ihl else ip[ihl:]
    pkt = Pkt(ts=0.0, src_ip=src, dst_ip=dst, proto=proto, payload=payload)
    if proto == 17:  # UDP
        if len(payload) >= 8:
            sport, dport, _length, _csum = struct.unpack("!HHHH", payload[:8])
            pkt.sport, pkt.dport, pkt.payload = sport, dport, payload[8:]
        return pkt
    if proto == 50:  # ESP
        return pkt
    if proto == 6:  # TCP (metadata only)
        if len(payload) >= 20:
            sport, dport = struct.unpack("!HH", payload[0:4])
            pkt.sport, pkt.dport = sport, dport
    return pkt


# ------------------------------------------------------------------ IKE parse


@dataclass
class IkeMessage:
    initiator_spi: bytes
    responder_spi: bytes
    next_payload: int
    version_major: int
    version_minor: int
    exchange_type: int
    flags: int
    msg_id: int
    payload: bytes


def _parse_ike_header(raw: bytes) -> Optional[IkeMessage]:
    if len(raw) < 28:
        return None
    init, resp = raw[0:8], raw[8:16]
    body = raw[20:28]
    version = raw[17]
    return IkeMessage(
        initiator_spi=init,
        responder_spi=resp,
        next_payload=raw[16],
        version_major=version >> 4,
        version_minor=version & 0x0F,
        exchange_type=raw[18],
        flags=raw[19],
        msg_id=struct.unpack("!I", raw[16 + 4:16 + 8])[0],
        payload=raw[28:],
    )


def _iter_ikev1_attrs(data: bytes) -> Dict[int, Any]:
    attrs: Dict[int, Any] = {}
    offset = 0
    while offset + 4 <= len(data):
        word = struct.unpack("!H", data[offset:offset + 2])[0]
        is_tv = word >> 15
        attr_type = word & 0x3FFF
        if is_tv:
            value = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            attrs[attr_type] = value
            offset += 4
        else:
            length = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            raw_value = data[offset + 4:offset + 4 + length]
            attrs[attr_type] = raw_value
            offset += 4 + length
    return attrs


def _iter_ikev2_attrs(data: bytes) -> Dict[int, Any]:
    attrs: Dict[int, Any] = {}
    offset = 0
    while offset + 4 <= len(data):
        word = struct.unpack("!H", data[offset:offset + 2])[0]
        is_tv = word >> 15
        attr_type = word & 0x7FFF
        if is_tv:
            value = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            attrs[attr_type] = value
            offset += 4
        else:
            length = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            attrs[attr_type] = data[offset + 4:offset + 4 + length]
            offset += 4 + length
    return attrs


@dataclass
class VpnProfile:
    ike_version: int = 0
    encryption: str = ""
    key_length: int = 0
    integrity: str = ""
    prf: str = ""
    dh_group: str = ""
    pfs: str = "unknown"
    mode: str = "unknown"
    sa_lifetime: int = 0
    replay: str = "unknown"
    esp_seen: bool = False
    participants: List[str] = field(default_factory=list)
    raw_proposals: List[str] = field(default_factory=list)

    def observed_count(self) -> int:
        return sum(1 for v in (
            bool(self.ike_version), bool(self.encryption), bool(self.integrity),
            bool(self.dh_group), self.pfs != "unknown", self.sa_lifetime > 0,
            self.replay != "unknown", self.mode != "unknown"))


def extract_vpn_profiles(packets: List[Pkt]) -> List[VpnProfile]:
    """Group IKE messages by peer pair and merge the proposals observed."""
    by_peer: Dict[tuple, VpnProfile] = {}
    esp_pairs: set = set()

    for pkt in packets:
        if pkt.proto == 50:  # ESP
            esp_pairs.add((pkt.src_ip, pkt.dst_ip))
            continue
        if pkt.proto != 17 or pkt.dport not in (500, 4500):
            continue
        blob = pkt.payload
        if pkt.dport == 4500 and blob.startswith(b"\x00\x00\x00\x00"):
            blob = blob[4:]  # NAT-T non-ESP marker
        msg = _parse_ike_header(blob)
        if msg is None:
            continue
        peer = tuple(sorted((pkt.src_ip, pkt.dst_ip)))
        if peer not in by_peer:
            by_peer[peer] = VpnProfile(participants=[pkt.src_ip, pkt.dst_ip])
        profile = by_peer[peer]
        profile.ike_version = msg.version_major
        _absorb_sa_payload(profile, msg)

    for profile in by_peer.values():
        hits = [p for p in packets if p.proto == 50
                and (p.src_ip in profile.participants or p.dst_ip in profile.participants)]
        profile.esp_seen = bool(hits)
    return list(by_peer.values())


def _absorb_sa_payload(profile: VpnProfile, msg: IkeMessage) -> None:
    data = msg.payload
    offset = 0
    payload_type = msg.next_payload  # first payload type comes from the IKE header
    while payload_type != 0 and offset + 4 <= len(data):
        payload_length = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        if payload_length < 4 or offset + payload_length > len(data):
            break
        body = data[offset + 4:offset + payload_length]
        # SA payloads: IKEv1 type=1, IKEv2 type=33
        sa_type = 1 if msg.version_major < 2 else 33
        if payload_type == sa_type:
            _parse_proposals(profile, body, msg.version_major)
        payload_type = data[offset]  # advance via this payload's next field
        offset += payload_length


def _parse_proposals(profile: VpnProfile, sa_body: bytes, version: int) -> None:
    if version < 2:
        offset = 8  # IKEv1 SA body: DOI(4) + Situation(4) precede proposals
        while offset < len(sa_body):
            if offset + 8 > len(sa_body):
                break
            prop_len = struct.unpack("!H", sa_body[offset + 2:offset + 4])[0]
            if prop_len < 12 or offset + prop_len > len(sa_body):
                break
            proto_id = sa_body[offset + 5]
            transforms = sa_body[offset + 8:offset + prop_len]
            _absorb_transforms(profile, transforms, version, proto_id)
            offset += prop_len
        return

    # IKEv2: repeated proposal substructures without per-proposal lengths.
    offset = 0
    while offset < len(sa_body):
        if offset + 4 > len(sa_body):
            break
        proto_id = sa_body[offset + 1]
        spi_size = sa_body[offset + 2]
        num_transforms = sa_body[offset + 3]
        cursor = offset + 4
        if spi_size:
            cursor = min(cursor + spi_size, len(sa_body))
        for _ in range(num_transforms):
            transform = _next_v2_transform(sa_body, cursor)
            if transform is None:
                break
            ttype, tid, attrs, cursor = transform
            _apply_v2_transform(profile, proto_id, ttype, tid, attrs)
        offset = cursor


IKEV2_TRANSFORM_TYPES = (1, 2, 3, 4, 5, 6)


def _next_v2_transform(data: bytes, offset: int):
    """Parse one IKEv2 transform (type, id, attributes) at ``offset``.

    IKEv2 transforms carry no length field, so the attribute run has to be
    bounded heuristically: a new transform header is recognised when a byte in
    the IKEv2 transform-type range is followed by a zero byte. Returns
    ``(ttype, tid, attrs, next_offset)`` or ``None`` on garbage.
    """
    if offset + 4 > len(data):
        return None
    ttype = data[offset]
    if data[offset + 1] != 0 or ttype not in IKEV2_TRANSFORM_TYPES:
        return None
    tid = struct.unpack("!H", data[offset + 2:offset + 4])[0]
    cursor = offset + 4
    attrs: Dict[int, Any] = {}

    while cursor + 4 <= len(data):
        word = struct.unpack("!H", data[cursor:cursor + 2])[0]
        is_tv = word >> 15
        attr_type = word & 0x7FFF
        if is_tv:
            attrs[attr_type] = struct.unpack("!H", data[cursor + 2:cursor + 4])[0]
            cursor += 4
        elif attr_type == 0:
            length = struct.unpack("!H", data[cursor + 2:cursor + 4])[0]
            if 4 + length > len(data) - cursor:
                break
            attrs[attr_type] = data[cursor + 4:cursor + 4 + length]
            cursor += 4 + length
        else:
            break
        # A new transform header (type byte in range + zero) terminates this one.
        if cursor + 4 <= len(data) and data[cursor + 1] == 0 and data[cursor] in IKEV2_TRANSFORM_TYPES:
            break
    return ttype, tid, attrs, cursor


def _absorb_transforms(profile: VpnProfile, transforms: bytes, version: int,
                       protocol_id: int) -> None:
    offset = 0
    while offset + 4 <= len(transforms):
        tlen = struct.unpack("!H", transforms[offset + 2:offset + 4])[0]
        if tlen < 6 or offset + tlen > len(transforms):
            break
        attrs = _iter_ikev1_attrs(transforms[offset + 6:offset + tlen])
        for attr_type, attr_value in attrs.items():
            _apply_v1_attr(profile, protocol_id, attr_type, attr_value)
        offset += tlen


def _apply_v1_attr(profile: VpnProfile, protocol_id: int, attr_type: int, value: Any) -> None:
    if attr_type == IKEV1_ATTR["encryption"]:
        profile.encryption = encr_lookup(value)
    elif attr_type == IKEV1_ATTR["hash"]:
        profile.integrity = hash_lookup(value)
    elif attr_type == IKEV1_ATTR["group"]:
        if protocol_id == 3:
            profile.pfs = "yes"
        profile.dh_group = group_str(value)
    elif attr_type == IKEV1_ATTR["lifetime"]:
        profile.sa_lifetime = int(value)
    elif attr_type == IKEV1_ATTR["key_length"]:
        profile.key_length = int(value)
    elif attr_type == 6 and protocol_id == 3:  # encapsulation mode (Quick Mode)
        profile.mode = IKEV1_MODE.get(int(value), "unknown")


def _apply_v2_transform(profile: VpnProfile, protocol_id: int, ttype: int,
                        tid: int, attrs: Dict[int, Any]) -> None:
    if ttype == 6:  # analyst-convention transform
        if tid == CONVENTION_ATTR["mode"]:
            profile.mode = {1: "transport", 2: "tunnel"}.get(int(_first_attr_value(attrs) or 0), "unknown")
        elif tid == CONVENTION_ATTR["lifetime"]:
            profile.sa_lifetime = int(_first_attr_value(attrs) or 0)
        elif tid == CONVENTION_ATTR["replay"]:
            value = int(_first_attr_value(attrs) or 1)
            profile.replay = "enabled" if value else "disabled"
        return

    if ttype == IKEV2_TTYPE["ENCR"]:
        profile.encryption = encr_lookup(tid)
        if attrs.get(13):
            profile.key_length = int(attrs[13])
        elif "256" in profile.encryption:
            profile.key_length = 256
        elif "128" in profile.encryption:
            profile.key_length = 128
    elif ttype == IKEV2_TTYPE["PRF"]:
        profile.prf = hash_lookup(tid)
    elif ttype == IKEV2_TTYPE["INTEG"]:
        profile.integrity = hash_lookup(tid)
        if not profile.prf:
            profile.prf = profile.integrity
    elif ttype == IKEV2_TTYPE["DH"]:
        profile.dh_group = group_str(tid)
        if protocol_id == 3:
            profile.pfs = "yes"
    elif ttype == IKEV2_TTYPE["ESN"]:
        profile.replay = "enabled"  # ESN presence is not a replay-disable signal


def _first_attr_value(attrs: Dict[int, Any]) -> Any:
    for value in attrs.values():
        if isinstance(value, (int, bytes)):
            if isinstance(value, bytes):
                return int.from_bytes(value, "big")
            return value
    return None

# ------------------------------------------------------------------ scoring


@dataclass
class RubricCheck:
    name: str
    observed: str
    status: str  # pass | warn | fail | unknown
    points: int  # deduction from 100
    recommendation: str = ""


def _encryption_deduction(name: str, bits: int) -> tuple:
    upper = (name or "").upper()
    if "GCM-256" in upper:
        return 0, "pass", "Modern AEAD cipher (AES-256-GCM)."
    if "GCM" in upper or ("AES" in upper and bits >= 192):
        return 5, "pass", "Modern AEAD cipher."
    if "AES" in upper and bits >= 128:
        return 10, "warn", "Acceptable cipher — prefer AEAD (AES-GCM) where possible."
    if "3DES" in upper:
        return 40, "fail", "3DES is deprecated and cryptographically weak."
    return 50, "fail", "Legacy/weak cipher; migrate to AES-GCM."


def _integrity_deduction(name: str) -> tuple:
    upper = (name or "").upper()
    if "SHA2" in upper or "SHA-256" in upper or "SHA3" in upper:
        return 0, "pass", "Strong integrity algorithm."
    if "SHA1" in upper:
        return 10, "warn", "SHA-1 is deprecated for integrity protection."
    if "MD5" in upper:
        return 30, "fail", "MD5 is broken as a cryptographic primitive."
    return 5, "warn", "Unknown integrity algorithm."


def _dh_deduction(value: str) -> tuple:
    try:
        number = int(str(value).replace("DH-", ""))
    except (TypeError, ValueError):
        return 5, "warn", "Unknown DH group."
    if number >= 19 or number in (14, 15, 16):  # ECP >=256 or MODP >=2048
        return 0, "pass", "Strong key-exchange group."
    if number == 14:
        return 0, "pass", "2048-bit MODP group."
    if number in (2, 5):
        return 25, "fail", "1024-bit MODP is Logjam-vulnerable; use >= 2048 bits."
    return 40, "fail", "Sub-1024-bit DH group is critically weak."


def _lifetime_deduction(seconds: int) -> tuple:
    if not seconds:
        return 5, "warn", "SA lifetime not observed."
    if seconds >= 60 * 60 * 4:
        return 0, "pass", "Reasonable SA rekeying interval."
    if seconds >= 60 * 60:
        return 10, "warn", "Short SA lifetime increases key-exchange load."
    return 20, "fail", "Very short SA lifetime; review negotiated policy."


def score_profile(profile: VpnProfile) -> Dict[str, Any]:
    checks: List[RubricCheck] = []
    score = 100

    # Protocol version
    if profile.ike_version == 2:
        checks.append(RubricCheck("IKE version", "IKEv2", "pass", 0,
                                  "Modern IKEv2 protocol in use."))
    elif profile.ike_version == 1:
        score -= 10
        checks.append(RubricCheck("IKE version", "IKEv1", "warn", 10,
                                  "Prefer IKEv2 (RFC 7296) for improved security."))
    else:
        checks.append(RubricCheck("IKE version", "unknown", "unknown", 5,
                                  "IKE version not observed in capture."))

    # Encryption
    if profile.encryption:
        deduction, status, rec = _encryption_deduction(profile.encryption, profile.key_length)
        score -= deduction
        checks.append(RubricCheck("Encryption", profile.encryption, status, deduction, rec))
    else:
        score -= 5
        checks.append(RubricCheck("Encryption", "unknown", "unknown", 5,
                                  "No ESP/IKE cipher observed."))

    # Integrity / PRF
    integrity = profile.integrity or profile.prf or ""
    if integrity:
        deduction, status, rec = _integrity_deduction(integrity)
        score -= deduction
        checks.append(RubricCheck("Integrity / PRF", integrity, status, deduction, rec))
    else:
        score -= 5
        checks.append(RubricCheck("Integrity / PRF", "unknown", "unknown", 5,
                                  "No integrity algorithm observed."))

    # DH group
    if profile.dh_group:
        deduction, status, rec = _dh_deduction(profile.dh_group)
        score -= deduction
        checks.append(RubricCheck("DH group", profile.dh_group, status, deduction, rec))
    else:
        score -= 5
        checks.append(RubricCheck("DH group", "unknown", "unknown", 5,
                                  "No key-exchange group observed."))

    # PFS
    if profile.pfs == "yes":
        checks.append(RubricCheck("Perfect Forward Secrecy", "enabled", "pass", 0,
                                  "PFS enabled — session keys are independent."))
    elif profile.pfs == "no":
        score -= 20
        checks.append(RubricCheck("Perfect Forward Secrecy", "disabled", "fail", 20,
                                  "Enable PFS (an extra D-H exchange per rekey)."))
    else:
        score -= 5
        checks.append(RubricCheck("Perfect Forward Secrecy", "unknown", "unknown", 5,
                                  "PFS state not observable from capture."))

    # SA lifetime
    deduction, status, rec = _lifetime_deduction(profile.sa_lifetime)
    score -= deduction
    checks.append(RubricCheck("SA lifetime", f"{profile.sa_lifetime}s" if profile.sa_lifetime
                              else "not observed", status, deduction, rec))

    # Replay protection (best effort — receiver-window property)
    if profile.replay == "disabled":
        score -= 15
        checks.append(RubricCheck("Replay protection", "disabled", "fail", 15,
                                  "Enable anti-replay windows on the receiver."))
    else:
        checks.append(RubricCheck("Replay protection",
                                  profile.replay if profile.replay != "unknown" else "assumed enabled",
                                  "pass", 0, "Anti-replay assumed in the absence of a disable signal."))

    # Mode
    if profile.mode == "transport":
        score -= 5
        checks.append(RubricCheck("Encapsulation mode", "transport", "warn", 5,
                                  "Transport mode protects payloads only; use tunnel for site links."))
    else:
        checks.append(RubricCheck("Encapsulation mode",
                                  profile.mode if profile.mode != "unknown" else "assumed tunnel",
                                  "pass" if profile.mode == "tunnel" else "warn",
                                  0 if profile.mode == "tunnel" else 5,
                                  "Verify tunnel-mode encapsulation."))

    score = max(0, min(100, score))
    if score >= 80:
        risk_level = "low"
    elif score >= 60:
        risk_level = "medium"
    elif score >= 40:
        risk_level = "high"
    else:
        risk_level = "critical"

    confidence = profile.observed_count() / 8.0
    recommendations = [c.recommendation for c in checks
                       if c.status == "fail" and c.recommendation]
    proposed = len(profile.raw_proposals)

    return {
        "profile": _profile_to_dict(profile),
        "security_score": score,
        "risk_level": risk_level,
        "risk_matrix": [c.__dict__ for c in checks],
        "confidence": round(confidence, 2),
        "recommendations": recommendations,
        "proposals_observed": proposed,
    }


def _profile_to_dict(profile: VpnProfile) -> Dict[str, Any]:
    keep = {k: v for k, v in profile.__dict__.items() if k != "proposals_observed"}
    keep.pop("raw_proposals", None)
    return keep


def assess_vpn_pcap(path: str | Path, client_ip_hint: Optional[str] = None) -> Dict[str, Any]:
    """Full Module B entry point: profile + score for one pcap file."""
    packets = read_pcap(path)
    profiles = extract_vpn_profiles(packets)
    if not profiles:
        return {
            "status": "no_negotiation",
            "source_path": str(path),
            "security_score": None,
            "error": "No IKE negotiation found in capture.",
        }
    result = score_profile(profiles[0])
    result["status"] = "assessed"
    result["source_path"] = str(path)
    result["packets"] = len(packets)
    return result


def assess_vpn_directory(directory: str | Path) -> List[Dict[str, Any]]:
    """Assess every *.pcap under ``directory`` and return all findings."""
    findings = []
    for path in sorted(Path(directory).glob("*.pcap")):
        findings.append(assess_vpn_pcap(path))
    return findings
