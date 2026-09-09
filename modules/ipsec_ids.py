"""IPsec / IKE identifier tables shared by the PCAP generator, the analyzer
(Module B) and the tests.

IKEv1 attribute types and IKEv2 transform types follow the IANA registries;
the *analyst convention* attribute types (mode, lifetime, replay) are
TriNetra-defined so the demo captures carry full posture metadata that a
real capture would only partially expose (documented in docs/architecture.md).
"""

from __future__ import annotations

# ---- IKEv1 attribute types (inside transform payloads) --------------------
IKEV1_ATTR = {
    "encryption": 1,
    "hash": 2,
    "auth_method": 3,
    "group": 4,
    "lifetime_type": 7,
    "lifetime": 8,
    "key_length": 10,
}
IKEV1_ENC = {"DES": 1, "DES-CBC": 1, "3DES": 3, "3DES-CBC": 3, "RC4": 5, "BLOWFISH": 6,
             "CAST": 7, "AES-CBC": 12}
IKEV1_HASH = {"MD5": 1, "SHA1": 2, "Tiger": 3, "SHA2-256": 5, "SHA2-384": 6, "SHA2-512": 7}
IKEV1_GROUP = {"DH-1": 1, "DH-2": 2, "DH-5": 5, "DH-14": 14, "DH-15": 15,
               "DH-16": 16, "DH-19": 19, "DH-20": 20}
IKEV1_MODE = {1: "transport", 2: "tunnel"}

# ---- IKEv2 transform types & IDs (IANA) -----------------------------------
IKEV2_TTYPE = {"ENCR": 1, "PRF": 2, "INTEG": 3, "DH": 4, "ESN": 5}
IKEV2_ENCR = {"DES": 2, "3DES": 3, "3DES-CBC": 3, "AES-CBC": 12, "AES-GCM-12": 21,
              "AES-GCM-14": 22, "AES-GCM-16": 20, "AES-GCM-256": 20, "AES-GCM-128": 20}
IKEV2_PRFR = {"MD5": 1, "SHA1": 2, "SHA2-256": 5, "SHA2-384": 6, "SHA2-512": 7}
IKEV2_INTEG = {"MD5": 1, "SHA1": 2, "SHA2-256": 6, "SHA2-384": 7, "SHA2-512": 8}
IKEV2_DH = {"DH-1": 1, "DH-2": 2, "DH-5": 5, "DH-14": 14, "DH-15": 15,
            "DH-16": 16, "DH-19": 19, "DH-20": 20}
IKEV2_ESN = {0: "no-esn", 1: "esn"}

# ---- analyst-convention attribute types (TriNetra extension) --------------
CONVENTION_ATTR = {
    "mode": 0x3000,       # TV: 1=transport, 2=tunnel
    "lifetime": 0x4000,   # TV/TLV: seconds
    "replay": 0x5000,     # TV: 1=enabled, 0=disabled
}

# ---- friendly-name lookups ------------------------------------------------
ENCR_BY_ID = {}
for _kind in (IKEV1_ENC, IKEV2_ENCR):
    for _name, _id in _kind.items():
        ENCR_BY_ID.setdefault(_id, _name)
DH_BY_ID = {**IKEV1_GROUP, **IKEV2_DH}
HASH_BY_ID = {}
for _kind in (IKEV2_INTEG, IKEV2_PRFR, IKEV1_HASH):  # INTEG first: id 6 is SHA2-256
    for _name, _id in _kind.items():
        HASH_BY_ID.setdefault(_id, _name)


def encr_lookup(value) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value)
    return ENCR_BY_ID.get(number, f"encr-{number}")


def hash_lookup(value) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value)
    return HASH_BY_ID.get(number, f"hash-{number}")


def group_str(value) -> str:
    try:
        return f"DH-{int(value)}"
    except (TypeError, ValueError):
        return str(value)


def encr_str(value) -> str:
    if isinstance(value, int) and value in ENCR_BY_ID:
        return ENCR_BY_ID[value]
    if isinstance(value, str):
        return value
    return f"UNKNOWN({value})"