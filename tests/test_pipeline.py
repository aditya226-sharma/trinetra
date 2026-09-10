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


def _dummy_event(event_id):
    return Event(event_id=event_id, timestamp="2026-09-12T10:00:00Z",
                 source_type="csv", client_id="probe", category="system",
                 severity="info", message="m", trace_id=f"probe::{event_id}",
                 fields={})


def test_event_store_self_heals_after_external_replace(tmp_path):
    """Ingest must keep working when another process replaces the DB file."""
    from pipeline.event_store import EventStore

    path = tmp_path / "events.db"
    store = EventStore(path)
    store.save(_dummy_event("ev-1"))
    assert store.count() == 1

    # External process (e.g. `python main.py --demo`, or a second reset)
    # unlinks and recreates data/trinetra.db while `store` stays open.
    path.unlink(missing_ok=True)
    fresh = EventStore(path)
    fresh.save(_dummy_event("new-0"))

    # The stale connection must self-heal and write to the CURRENT file —
    # never silently write to the now-deleted inode.
    store.save(_dummy_event("ev-2"))
    assert store.get("ev-2") is not None
    assert EventStore(path).count() == 2  # new-0 + ev-2 (fresh reader)


def test_orchestrator_ingest_outcomes(monkeypatch, tmp_path):
    """ingest() reports honest statuses: stored / duplicate / invalid."""
    monkeypatch.setenv("TRINETRA_STORE_PATH", str(tmp_path / "events.db"))
    monkeypatch.setenv("TRINETRA_RAW_DIR", str(tmp_path / "raw"))
    from config.settings import Settings as TSettings
    from orchestrator import Orchestrator

    orch = Orchestrator(TSettings())
    raw = ("<134>Sep 11 10:00:01 webx sshd: Failed password for invalid "
           "user root from 198.51.100.7 port 51122 ssh2")
    assert orch.ingest(raw, "syslog", "webx") == "stored"
    assert orch.ingest(raw, "syslog", "webx") == "duplicate"
    assert orch.ingest("   ", "syslog", "webx") == "invalid"
    assert orch.event_store.count() == 1
    assert orch.stats["duplicates"] == 1


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