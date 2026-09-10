"""Parser registry tests — every source type parses to usable UES fields."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import parsers  # noqa: F401, E402  (registers all parsers)
from parsers.registry import PARSERS, parse, guess_source_type


def test_all_parsers_registered():
    assert {"syslog", "cef", "json", "csv", "netflow", "windows"} <= set(PARSERS)


def test_syslog_sshd_failed_password():
    raw = ("<134>Sep  8 14:00:01 web01 sshd: Failed password for invalid user "
           "root from 203.0.113.5 port 50000 ssh2")
    parsed = parse(raw, "syslog", "client", "web01")
    assert parsed is not None
    assert parsed["category"] == "auth"
    assert parsed["severity"] == "error"  # PRI 134 -> daemon.auth / error
    assert parsed["client_ip"] == "203.0.113.5"
    assert parsed["fields"]["process"] == "sshd"
    assert parsed["fields"]["src_ip"] == "203.0.113.5"
    assert parsed["client_ip"] == "203.0.113.5"


def test_syslog_ufw_block():
    raw = "<134>Sep  8 14:00:02 edge-fw-01 ufw: BLOCK src=203.0.113.5 dpt=22 proto=tcp"
    parsed = parse(raw, "syslog", "client", "edge-fw-01")
    assert parsed is not None
    assert parsed["category"] == "network"
    assert parsed["fields"]["src_ip"] == "203.0.113.5"


def test_cef_parser():
    raw = ("CEF:0|Fortinet|FortiGate|v7.4.0|0001|IPS:ET RULE|5|src=203.0.113.5 "
           "dst=10.10.1.10 spt=50000 dpt=449 proto=tcp act=detect")
    parsed = parse(raw, "cef", "client", "edge-fw-01")
    assert parsed is not None
    assert parsed["severity"] == "error"
    assert parsed["fields"]["src_ip"] == "203.0.113.5"
    assert parsed["fields"]["dst_ip"] == "10.10.1.10"
    assert parsed["fields"]["dport"] == "449"

def test_cef_extension_keys_mapped():
    raw = ("CEF:0|Fortinet|FortiGate|v7.4.0|0001|IPS:ET RULE|5|src=203.0.113.5 "
           "dst=10.10.1.10 spt=50000 dpt=449 proto=tcp act=detect")
    parsed = parse(raw, "cef", "client", "edge-fw-01")
    assert parsed["client_ip"] == "203.0.113.5"
    assert parsed["fields"]["sport"] == "50000"
    assert parsed["fields"]["action"] == "detect"


def test_netflow_json():
    raw = ('{"ts": "Sep  8 14:00:01", "src": "203.0.113.5", "dst": "10.10.1.10", '
           '"proto": "tcp", "sport": 40000, "dport": 1024, "pkts": 1, "bytes": 60, '
           '"flags": "S"}')
    parsed = parse(raw, "netflow", "client", "")
    assert parsed is not None
    assert parsed["category"] == "flow"
    assert parsed["fields"]["src_ip"] == "203.0.113.5"
    assert parsed["fields"]["dport"] == 1024


def test_netflow_tab_separated():
    raw = ("Sep  8 14:00:01\t203.0.113.5\t10.10.1.10\ttcp\t40000\t1024\t1\t60\tS")
    parsed = parse(raw, "netflow", "client", "")
    assert parsed is not None
    assert parsed["fields"]["src_ip"] == "203.0.113.5"


def test_windows_parser():
    raw = ("Level=3 Provider=Microsoft-Windows-Security-Auditing EventID=4625 "
           "Computer=WIN-FW1 Account Name=admin")
    parsed = parse(raw, "windows", "client", "win-fw1")
    assert parsed is not None
    assert parsed["category"] == "auth"
    assert parsed["fields"]["event_id"] == "4625"


def test_guess_source_type():
    assert guess_source_type('{"a":1}') == "json"
    assert guess_source_type("<134>Sep  8 nginx: x") == "syslog"
    assert guess_source_type("CEF:0|x|y") == "cef"


def test_parse_none_on_garbage_source():
    assert parse("garbage", "not-a-parser", "c", "") is None


def test_json_parser_structured_event():
    raw = ('{"ts": "Sep 10 09:00:01", "src": "10.10.1.20", '
           '"dst": "198.51.100.9", "proto": "tcp", "sport": 47777, '
           '"dport": 443, "pkts": 3, "bytes": 2100, "flags": "SA", '
           '"severity": "error", "category": "flow"}')
    parsed = parse(raw, "json", "client", "")
    assert parsed is not None
    assert parsed["category"] == "flow"
    assert parsed["severity"] == "error"
    assert parsed["fields"]["src"] == "10.10.1.20"
    assert parsed["client_ip"] == "10.10.1.20"


def test_csv_header_then_data_rows():
    header = "timestamp,src_ip,dst_ip,proto,sport,dport,pkts,bytes,flags"
    row = "Sep 12 09:00:00,198.51.100.77,10.10.1.40,tcp,44000,445,2,900,S"
    # Header row is consumed, not materialised into a fake event.
    assert parse(header, "csv", "client", "") == {"_skip": True}
    parsed = parse(row, "csv", "client", "")
    assert parsed is not None
    assert parsed["client_ip"] == "198.51.100.77"
    assert parsed["fields"]["dst_ip"] == "10.10.1.40"
    assert parsed["fields"]["dport"] == "445"


def test_csv_headerless_positional_mapping():
    row = "Sep 12 09:00:00,198.51.100.77,10.10.1.40,tcp,44000,445,2,900,S"
    parsed = parse(row, "csv", "client", "")
    assert parsed is not None
    assert parsed["fields"]["src_ip"] == "198.51.100.77"
    assert parsed["fields"]["dport"] == "445"
    # Deterministic output -> same input yields the same fingerprint.
    assert parse(row, "csv", "client", "")["fields"] == parsed["fields"]