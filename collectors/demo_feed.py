"""Demo feed — a self-contained, offline dataset generator.

Produces a believable multi-step intrusion storyline across every source
type TriNetra supports, so ``python main.py --demo`` demonstrates the whole
stack with zero external dependencies or network access:

  1. Recon — nmap-style port scan ``203.0.113.5`` -> internal hosts (flows + nginx 404s + UFW)
  2. Brute force — sshd failed passwords from the same IP (auth, cross-module link)
  3. C2 beaconing — periodic small flows ``10.10.1.50`` -> ``198.51.100.9``
  4. Data exfiltration — asymmetric large outbound flow from the same host
  5. DGA DNS — high-entropy query names to a .top resolver
  6. VPN gateway story — strongswan logs + generated PCAP captures (Module B)
  7. Normal background noise — healthy web + auth traffic

Returns ``(raw, source_type, client_id, host_hint)`` tuples.
"""

from __future__ import annotations

import json
import logging
from typing import Iterator, Optional, Tuple

from collectors.pcapgen import write_ike_pcap

Line = Tuple[str, str, str, str]

ATK = "203.0.113.5"
HOST_SRC = "10.10.1.50"
C2 = "198.51.100.9"
WAN = "192.0.2.199"
DGA_RESOLVER = "198.108.1.1"

log = logging.getLogger("trinetra.demo")


def _syslog(client: str, tag: str, pri: int, month_ts: str, msg: str) -> str:
    return f"<{pri}>{month_ts} {client} {tag}: {msg}"


def _flow(ts: str, src: str, dst: str, proto: str, sport: int, dport: int,
          pkts: int, bytes_: int, flags: str = "", dns_query: str = "",
          tls_ja3: str = "") -> str:
    rec: dict = {
        "ts": ts, "src": src, "dst": dst, "proto": proto,
        "sport": sport, "dport": dport, "pkts": pkts, "bytes": bytes_, "flags": flags,
    }
    if dns_query:
        rec["dns_query"] = dns_query
    if tls_ja3:
        rec["tls_ja3"] = tls_ja3
    return json.dumps(rec)


def _json_log(ts: str, category: str, severity: str, message: str, **extra) -> str:
    rec = {"timestamp": ts, "category": category, "severity": severity,
           "message": message, **extra}
    return json.dumps(rec)


def _dga_name(i: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    seed = (i * 2654435761) % (36 ** 12)
    out = []
    for _ in range(18):
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(alphabet[seed % 36])
    return "".join(out) + ".top"


class DemoFeed:
    """Deterministic storyline generator. No RNG — output is reproducible."""

    def iterate(self, start_index: int = 0, max_items: Optional[int] = None,
                delay: float = 0.0) -> Iterator[Line]:
        lines = self._build_offline()
        count = 0
        for raw, source, client, host in lines:
            if count < start_index:
                count += 1
                continue
            if max_items is not None and (count - start_index) >= max_items:
                return
            count += 1
            yield raw, source, client, host
            if delay:
                import time

                time.sleep(delay)

    # -- the two PCAP fixtures Module B needs -----------------------------
    @staticmethod
    def generate_pcaps(target_dir: str) -> list[str]:
        """Write strong + weak IKEv2/ESP captures; returns their paths."""
        from pathlib import Path

        directory = Path(target_dir)
        directory.mkdir(parents=True, exist_ok=True)
        strong = directory / "ipsec_strong.pcap"
        weak = directory / "ipsec_weak.pcap"
        write_ike_pcap(
            str(strong),
            cfg={"ike_version": "2", "mode": "tunnel", "encr": "AES-GCM-256",
                 "auth": "SHA2-256", "dh": "DH-19", "pfs": "yes",
                 "sa_lifetime": 28800, "replay_protection": True},
            ike_src=ATK, ike_dst="10.10.0.1", esp_src="10.10.0.1", esp_dst="10.10.1.10",
        )
        write_ike_pcap(
            str(weak),
            cfg={"ike_version": "1", "mode": "tunnel", "encr": "3DES-CBC",
                 "auth": "MD5", "dh": "DH-2", "pfs": "no",
                 "sa_lifetime": 900, "replay_protection": False},
            ike_src="10.10.0.1", ike_dst="198.51.100.77", esp_src="198.51.100.77",
            esp_dst="10.10.0.1",
        )
        return [str(strong), str(weak)]

    # -- full storyline ----------------------------------------------------
    def _build_offline(self) -> list[Line]:
        t = 0
        out: list[Line] = []

        def ts(step: int = 1) -> str:
            nonlocal t
            t += step
            hour = 14 + t // 3600
            minute = (t % 3600) // 60
            second = t % 60
            return f"Sep  8 {hour % 24:02d}:{minute:02d}:{second:02d}"

        # ============ 1. RECON — port scan 203.0.113.5 -> 10.10.1.10 ======
        for i in range(18):
            out.append((_flow(ts(1), ATK, "10.10.1.10", "tcp", 40000 + i, 1024 + i * 137,
                              1, 60, "S"), "netflow", "flow-sensor-1", ""))
        for i in range(5):
            out.append((_syslog("web01", "nginx", 150, ts(2),
                                f'10.10.1.10 - - [08/Sep/2026:14:0{i}] "GET /admin.php HTTP/1.1" '
                                f'404 153 "-" "Nmap Scripting Engine"'),
                        "syslog", "web01", "web01"))
        for _ in range(4):
            out.append((_syslog("edge-fw-01", "ufw", 134, ts(1),
                                f"BLOCK src={ATK} dpt=22 proto=tcp"),
                        "syslog", "edge-fw-01", "edge-fw-01"))

        # ============ 2. BRUTE FORCE — sshd on web01 from the same IP =====
        for i in range(12):
            user = ["admin", "root", "ubuntu", "oracle", "test"][i % 5]
            out.append((_syslog("web01", "sshd", 120, ts(1),
                                f"Failed password for invalid user {user} from {ATK} "
                                f"port {50000 + i} ssh2"),
                        "syslog", "web01", "web01"))
        out.append((_syslog("web01", "sshd", 113, ts(5),
                            f"Disconnected from invalid user admin {ATK} port 50012"),
                    "syslog", "web01", "web01"))
        out.append((_syslog("edge-fw-01", "ufw", 134, ts(2),
                            f"BLOCK src={ATK} dpt=22 proto=tcp"),
                    "syslog", "edge-fw-01", "edge-fw-01"))

        # ============ 2b. DDoS — 6 internal hosts flood web01 (10.10.1.10) ===
        for j in range(6):
            for _ in range(25):
                out.append((_flow(ts(1), f"10.10.1.{30 + j}", "10.10.1.10", "tcp",
                                  48000 + _, 80, 12, 1_200, "S"), "netflow",
                            "flow-sensor-1", ""))

        # ============ 3. C2 BEACONING — periodic TLS from 10.10.1.50 =======
        for i in range(10):
            out.append((_flow(ts(7), HOST_SRC, C2, "tcp", 49152 + i, 443,
                              4, 640, "SA", tls_ja3="aa12f34bb90192c1f98a1f2c4d8f8c6a"),
                        "netflow", "flow-sensor-1", ""))

        # ============ 4. EXFILTRATION — asymmetric outbound bytes ==========
        for _ in range(3):
            out.append((_flow(ts(3), HOST_SRC, WAN, "tcp", 40220, 8080,
                              220, 4_500_000, "PA"), "netflow", "flow-sensor-1", ""))

        # ============ 5. DGA DNS queries ====================================
        for i in range(9):
            out.append((_flow(ts(1), HOST_SRC, DGA_RESOLVER, "udp", 53000 + i, 53,
                              1, 76, "-", dns_query=_dga_name(i)),
                        "netflow", "flow-sensor-1", ""))

        # ============ 6. VPN GATEWAY story (Module B PCAPs handled separately)
        out.append((_syslog("vpn-gw-01", "strongswan", 134, ts(3),
                            'charon: 05[NET] received packet: from 198.51.100.77[4500] to 10.10.0.1[4500] (400 bytes)'),
                    "syslog", "vpn-gw-01", "vpn-gw-01"))
        out.append((_syslog("vpn-gw-02", "charon", 150, ts(4),
                            'charon: 12[CFG] received stroke: add connection "office-net" [AES_GCM_16_256, SHA2_256, DH_GROUP_19]'),
                    "syslog", "vpn-gw-02", "vpn-gw-02"))
        out.append((_json_log(ts(2), "vpn", "warning",
                              "IPsec tunnel peer 198.51.100.77 proposes weak proposal",
                              gateway="vpn-gw-01", peer_ip="198.51.100.77"),
                    "json", "vpn-gw-01", "vpn-gw-01"))

        # ============ 7. NOISE — normal traffic =============================
        for _ in range(14):
            server = ("142.250.1.1", "151.101.1.1", "104.16.1.1")[_ % 3]
            out.append((_flow(ts(2), "10.10.1." + str(20 + _ % 5), server, "tcp",
                              40000 + _, 443, 30 + _ % 5, 5_000 + _, "SA"),
                        "netflow", "flow-sensor-1", ""))
        out.append((_syslog("web01", "sshd", 190, ts(2),
                            "Accepted publickey for admin from 10.10.1.21 port 40210 ssh2"),
                    "syslog", "web01", "web01"))
        out.append((_syslog("web01", "nginx", 122, ts(2),
                            '10.10.1.21 - - [08/Sep/2026:14:09] "GET / HTTP/1.1" 200 728 "-" "Mozilla/5.0"'),
                    "syslog", "web01", "web01"))
        out.append((_syslog("apache02", "httpd", 122, ts(3),
                            '10.10.1.22 - - [08/Sep/2026:14:10] "POST /api/v1/order HTTP/1.1" 200 214 "-" "curl/8.4"'),
                    "syslog", "apache02", "apache02"))

        # ============ CEF appliance logs ===================================
        for i in range(3):
            out.append((f"CEF:0|Fortinet|FortiGate|v7.4.0|0001|{['PolicyViolation', 'IPS:ET RULE', 'Anomaly'][i]}|5|src={ATK}"
                        f" dst=10.10.1.10 spt=50000 dpt={442 + i * 7} proto=tcp act=detect",
                        "cef", "edge-fw-01", "edge-fw-01"))

        # ============ cloud audit JSON ======================================
        out.append((_json_log(ts(5), "application", "critical",
                              "S3 bucket finance-reports set to public-read",
                              resource="arn:aws:s3:::finance-reports", action="PutBucketAcl",
                              actor="svc-exporter", event_type="iam"),
                    "json", "cloud-audit", "cloud-audit"))
        out.append((_json_log(ts(8), "auth", "error",
                              "Root account sign-in from unusual location",
                              actor="root", source_ip=ATK, event_type="authentication"),
                    "json", "cloud-audit", "cloud-audit"))

        return out