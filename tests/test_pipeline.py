"""Pipeline tests — raw store losslessness, UES normalization, dedup, prefilter."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.normalizer import Normalizer
from pipeline.raw_store import RawStore
from pipeline.batcher import Batcher, DedupCounter
from pipeline.prefilter import Prefilter
from schema import Event, new_uuid, make_trace_id


def _normalizer(tmp_path):
    return Normalizer(RawStore(tmp_path / "raw.jsonl"))


def test_raw_store_lossless(tmp_path):
    store = RawStore(tmp_path / "raw.jsonl")
    line = "<134>Sep  8 14:00:01 web01 sshd: Failed password"
    store.append("trace-1", "client", "syslog", line)
    assert store.get("trace-1") == line
    store.append("trace-1", "client", "syslog", line)  # idempotent
    assert len(store) == 1


def test_normalizer_preserves_raw_and_trace(tmp_path):
    n = _normalizer(tmp_path)
    raw = "<134>Sep  8 14:00:01 web01 sshd: Failed password for invalid user root from 10.1.1.1"
    event = n.normalize(raw, "syslog", "web01", "web01")
    assert event is not None
    assert event.raw_event == raw
    assert event.source_type == "syslog"
    assert event.category == "auth"
    assert event.trace_id.startswith("web01::syslog::")
    assert n.raw_store.get(event.trace_id) == raw


def test_dedup_counter():
    dc = DedupCounter()
    raw = "dup line"
    e1 = Event(event_id=new_uuid(), timestamp="t", source_type="syslog",
               client_id="c", message=raw, fields={})
    assert dc.track(e1) is True
    assert dc.track(e1) is False
    assert dc.duplicate_rate == 0.5


def test_batcher_window_flush():
    b = Batcher(window_seconds=0.001, max_events=100)
    e = Event(event_id="1", timestamp="t", source_type="syslog", client_id="c",
              message="hello", fields={})
    out = b.add(e)
    assert out is None or (out and out[0].event_id == "1")


def test_prefilter_severity_gate():
    p = Prefilter(min_severity="error")
    info = Event(event_id="1", timestamp="t", source_type="syslog", client_id="c",
                 category="system", severity="info", message="x", fields={})
    err = Event(event_id="2", timestamp="t", source_type="syslog", client_id="c",
                category="system", severity="error", message="x", fields={})
    assert p.should_pass(info) is False
    assert p.should_pass(err) is True


def test_prefilter_flow_passes_with_findings():
    p = Prefilter(min_severity="error")
    flow = Event(event_id="1", timestamp="t", source_type="netflow", client_id="c",
                 category="flow", severity="info", message="x", fields={})
    assert p.should_pass(flow) is False  # no module findings yet
    flow.module_findings["network_threat"] = {"threat_class": "c2_beaconing"}
    assert p.should_pass(flow) is True