"""Minimal, deterministic PCAP writer for IKEv1/IKEv2 + ESP captures.

Crafts byte-valid Ethernet/IP/UDP packets carrying IKE negotiation (SA
proposal/transform substructures) so the demo and the test suite have real
binary captures to analyse — no external capture tooling required. The
structure follows RFC 7296 (IKEv2) / RFC 2409 (IKEv1) well enough that the
analyzer in modules/vpn_assessment.py parses the same bytes back out.
"""

from __future__ import annotations

import struct
import time
from typing import Dict

from modules.ipsec_ids import (
    CONVENTION_ATTR,
    IKEV1_ATTR,
    IKEV1_ENC,
    IKEV1_GROUP,
    IKEV1_HASH,
    IKEV2_DH,
    IKEV2_ENCR,
    IKEV2_INTEG,
    IKEV2_PRFR,
    IKEV2_TTYPE,
)

PCAP_MAGIC = 0xA1B2C3D4


def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# ------------------------------------------------------------------ ether/IP
def _pack_ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 1) -> bytes:
    src_bytes = bytes(int(octet) for octet in src.split("."))
    dst_bytes = bytes(int(octet) for octet in dst.split("."))
    total_len = 20 + len(payload)
    header_no_csum = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0x4000, 64, proto, 0, src_bytes, dst_bytes
    )
    checksum = ip_checksum(header_no_csum)
    return struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0x4000, 64, proto, checksum, src_bytes, dst_bytes
    ) + payload


def _pack_udp(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def _pack_eth(proto_field: bytes) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb")
    return eth[0:6] + eth[6:12] + proto_field  # dst, src, ethertype


def ip_packet(src: str, dst: str, proto: int, ip_payload: bytes, ident: int = 1) -> bytes:
    ip = _pack_ipv4(src, dst, proto, ip_payload, ident)
    return _pack_eth(b"\x08\x00") + ip


# -------------------------------------------------------------------- IKE
def ike_header(init_spi: bytes, resp_spi: bytes, next_payload: int, version_major: int,
               version_minor: int, exchange_type: int, flags: int = 0,
               msg_id: int = 0) -> bytes:
    version = (version_major << 4) | version_minor
    body = init_spi + resp_spi + struct.pack(
        "!BBBBII", next_payload, version, exchange_type, flags, msg_id, 0
    )
    return body + struct.pack("!I", len(body))


def _ikev1_attr(type_: int, value: int) -> bytes:
    """IKEv1 attribute: bit15=TV format, 15-bit type, 2-byte value."""
    return struct.pack("!HH", 0x8000 | type_, value)


def _ikev2_tlv(wire_type: int, transform_id: int, value: int) -> bytes:
    """IKEv2 attribute inside a transform: 2-byte type (TV: high bit) + value."""
    return struct.pack("!HH", 0x8000 | wire_type, value)


def _ikev2_transform(tt: int, tid: int, attributes: bytes = b"") -> bytes:
    length = 4 + len(attributes)
    return struct.pack("!BBH", tt, 0, tid) + attributes


def _ikev1_transform(tnum: int, tid: int, attributes: bytes) -> bytes:
    length = 6 + len(attributes)
    return struct.pack("!BBHBB", 0, 0, length, tnum, tid) + attributes


def _sa_payload_ikev1(cfg: Dict) -> bytes:
    """SA payload ('next'=0) containing one ISAKMP proposal + transforms."""
    encryption = IKEV1_ENC[cfg["encr"]]
    hashing = IKEV1_HASH[cfg["auth"]]
    group = IKEV1_GROUP[cfg["dh"]]
    key_bits = {"AES-GCM-256": 256, "AES-GCM-128": 128, "3DES": 112, "3DES-CBC": 112,
                "AES-CBC": 256}.get(cfg["encr"], 256)

    attrs = b"".join([
        _ikev1_attr(IKEV1_ATTR["encryption"], encryption),
        _ikev1_attr(IKEV1_ATTR["hash"], hashing),
        _ikev1_attr(IKEV1_ATTR["group"], group),
        _ikev1_attr(IKEV1_ATTR["lifetime_type"], 1),
        _ikev1_attr(IKEV1_ATTR["lifetime"], cfg["sa_lifetime"]),
        _ikev1_attr(IKEV1_ATTR["key_length"], key_bits),
    ])
    transform = _ikev1_transform(1, 1, attrs)
    proposal_total_len = 8 + len(transform)
    proposal = struct.pack("!BBHBBBB", 0, 0, proposal_total_len, 1, 1, 0, 1) + transform
    payload_total_len = 12 + len(proposal)
    return struct.pack("!BBHI", 0, 0, payload_total_len, 1) + struct.pack("!I", 1) + proposal


def _sa_payload_ikev2(cfg: Dict) -> bytes:
    """IKEv2 SA payload (next=0) with IKE proposal transforms + analyst-convention
    attributes (mode / lifetime / replay) in a trailing child-proposal block.

    The proposal section mirrors RFC 7296; PFS shows up as a D-H transform in
    the child proposal.
    """
    encr_id = IKEV2_ENCR[cfg["encr"]]
    prf_id = IKEV2_PRFR[cfg["auth"]]
    integ_id = IKEV2_INTEG[cfg["auth"]]
    dh_id = IKEV2_DH[cfg["dh"]]
    key_bits = 256 if "256" in cfg["encr"] else 128

    transforms = b"".join([
        _ikev2_transform(IKEV2_TTYPE["ENCR"], encr_id, _ikev2_tlv(13, encr_id, key_bits)),
        _ikev2_transform(IKEV2_TTYPE["PRF"], prf_id),
        _ikev2_transform(IKEV2_TTYPE["INTEG"], integ_id),
        _ikev2_transform(IKEV2_TTYPE["DH"], dh_id),
    ])
    proposal = struct.pack("!BBBB", 1, 1, 0, 4) + transforms
    sa_len = 4 + len(proposal)
    # first byte (next payload) = 33: the SA payload chains onto the CHILD SA
    # (the child proposal carries PFS / lifetime / mode / replay conventions).
    main_sa = struct.pack("!BBH", 33, 0, sa_len) + proposal

    # Child proposal carrying mode / lifetime / ESN / PFS (analyst conventions).
    child_transforms = [
        _ikev2_transform(IKEV2_TTYPE["ENCR"], encr_id, _ikev2_tlv(13, encr_id, key_bits)),
        _ikev2_transform(IKEV2_TTYPE["INTEG"], integ_id),
    ]
    if cfg.get("pfs") == "yes":
        child_transforms.append(_ikev2_transform(IKEV2_TTYPE["DH"], dh_id))
    mode = 2 if cfg.get("mode") == "tunnel" else 1
    child_transforms.append(_convention_transform(CONVENTION_ATTR["mode"], mode, 2))
    child_transforms.append(_convention_transform(CONVENTION_ATTR["lifetime"], cfg["sa_lifetime"], 4))
    child_transforms.append(_convention_transform(
        CONVENTION_ATTR["replay"], 1 if cfg.get("replay_protection") else 0, 2))
    child_proposal_len = 4 + sum(len(t) for t in child_transforms)
    child_proposal = struct.pack("!BBBB", 2, 3, 0, len(child_transforms)) + b"".join(child_transforms)
    child_sa_len = 4 + len(child_proposal)
    child_sa = struct.pack("!BBH", 0, 0, child_sa_len) + child_proposal
    return main_sa + child_sa


def _convention_transform(attr_type: int, value: int, value_bytes: int) -> bytes:
    """Convention transform: type=6 (unassigned), id = attr_type, then a proper
    IKEv2 attribute (TV for 2-byte values, TLV otherwise) carrying the value."""
    header = struct.pack("!BBH", 6, 0, attr_type)
    if value_bytes == 2:
        attr = struct.pack("!HH", 0x8000, value)
    else:
        attr = struct.pack("!HH", 0, value_bytes) + value.to_bytes(value_bytes, "big")
    return header + attr


def _ikev2_convention_transform(attr_type: int, value: int, value_bits: int) -> bytes:
    """Convention transform: type=6 (unassigned), id = attr_type, then a TV value."""
    return struct.pack("!BBH", 6, 0, attr_type) + struct.pack("!%dH" % (value_bits // 2), value)


# ----------------------------------------------------------------------- ESP
def _esp_packet(src: str, dst: str, spi: int, seq: int, encrypted: bytes) -> bytes:
    esp = struct.pack("!II", spi, seq) + encrypted
    return ip_packet(src, dst, 50, esp)


# ------------------------------------------------------------------- pcap
def write_pcap(path: str, packets: list[bytes]) -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1))
        base = int(time.time())
        for index, pkt in enumerate(packets):
            ts = base + index
            fh.write(struct.pack("<IIII", ts, index * 100, len(pkt), len(pkt)))
            fh.write(pkt)


def write_ike_pcap(path: str, cfg: Dict, ike_src: str, ike_dst: str,
                   esp_src: str, esp_dst: str) -> None:
    """Write a capture with an IKE negotiation + a few ESP packets.

    ``cfg`` keys: ike_version ('1'/'2'), mode, encr, auth, dh, pfs, sa_lifetime,
    replay_protection.
    """
    init_spi = bytes.fromhex("0102030405060708")
    resp_spi = bytes.fromhex("0807060504030201")
    packets: list[bytes] = []

    if cfg["ike_version"] == "2":
        sa = _sa_payload_ikev2(cfg)
        sa_init = ike_header(init_spi, resp_spi, 33, 2, 0, 34, 0x08)  # exch IKE_SA_INIT
    else:
        sa = _sa_payload_ikev1(cfg)
        sa_init = ike_header(init_spi, resp_spi, 1, 1, 0, 2, 0x08)

    sa_init_hdr = _replace_length(sa_init, len(sa_init) - 4 + len(sa))
    req = ip_packet(ike_src, ike_dst, 17, _pack_udp(500, 500, sa_init_hdr + sa))
    resp = ip_packet(ike_dst, ike_src, 17, _pack_udp(500, 500, sa_init_hdr + sa))
    packets.extend([req, resp])

    # A couple of ESP-protected data packets complete the picture.
    packets.append(_esp_packet(esp_src, esp_dst, 0x10203040, 1, bytes(range(16))))
    packets.append(_esp_packet(esp_src, esp_dst, 0x10203040, 2, bytes(range(32, 48))))

    write_pcap(path, packets)


def _replace_length(header: bytes, new_len: int) -> bytes:
    """Rewrite the IKE header Length field once the SA payload is appended."""
    return header[:24] + struct.pack("!I", new_len)