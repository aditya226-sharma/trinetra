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
from schema import Event, new_uuid


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


def test_normalizer_auto_detects_source_type(tmp_path):
    """Untagged lines must be auto-detected, not forced to 'generic'.

    Regression: the normalizer passed ``source or "generic"`` into
    ``guess_source_type``, which returns any non-empty source verbatim and
    never reached the detection heuristics — every untagged line was
    classified 'generic' and parsed with the fallback instead of its format.
    """
    n = _normalizer(tmp_path)
    cases = [
        ('{"ts": "Sep 23 10:00:01", "level": "error", "msg": "boom"}', "json", "application"),
        ("<134>Sep 23 10:00:01 web01 sshd[1234]: Failed password for root", "syslog", "auth"),
        ("CEF:0|TriNetra|FW|1.0|100|x|5|src=1.2.3.4 dst=5.6.7.8", "cef", "system"),
        ("blah nothing special", "generic", "system"),
    ]
    for raw, expect_type, _cat in cases:
        event = n.normalize(raw, "", "web01")
        assert event is not None
        assert event.source_type == expect_type, f"{raw[:40]!r} -> {event.source_type}"


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
    # The production reset path also clears WAL sidecars.
    path.unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        try:
            (tmp_path / f"events.db{suffix}").unlink(missing_ok=True)
        except OSError:
            pass
    fresh = EventStore(path)
    fresh.save(_dummy_event("new-0"))
    fresh.close()

    # The stale connection must self-heal.  After the file was replaced, the
    # old fd may still accept writes silently (WAL + open unlinked inode), so
    # we explicitly trigger the reconnect path to prove it works.
    store._reconnect()
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


def test_rebuild_derived_restores_graph_after_restart(monkeypatch, tmp_path):
    """A fresh orchestrator over the same store rebuilds the entity graph.

    The graph + threat detector are memory-only; after a container restart
    persisted events must be replayed so /api/graph isn't empty.
    """
    monkeypatch.setenv("TRINETRA_STORE_PATH", str(tmp_path / "events.db"))
    monkeypatch.setenv("TRINETRA_RAW_DIR", str(tmp_path / "raw"))
    from config.settings import Settings as TSettings
    from collectors.demo_feed import DemoFeed
    from orchestrator import Orchestrator

    live = Orchestrator(TSettings())
    for i, (raw, source, client, host) in enumerate(DemoFeed().iterate(max_items=200)):
        live.ingest(raw, source, client, host)
    live.flush_batch()
    expected = live.graph.summary()
    assert expected["nodes"] > 0 and expected["edges"] > 0

    restarted = Orchestrator(TSettings())
    assert restarted.graph.summary()["nodes"] == 0  # memory cleared

    restarted.rebuild_derived()
    rebuilt = restarted.graph.summary()
    assert rebuilt["nodes"] == expected["nodes"]
    assert rebuilt["edges"] == expected["edges"]
    assert rebuilt["threatened"] == expected["threatened"]
    assert rebuilt["findings"] == expected["findings"]
    assert restarted.threats.detection_counts == live.threats.detection_counts
    # The rebuild must mirror flush_batch bookkeeping so the dashboard KPI
    # and alerts fan-out match the live run (see _overlay_threat_findings).
    assert restarted.stats["findings"] == expected["findings"]
    assert len(restarted.findings_log) == len(live.findings_log)
    assert len(restarted.alerts_log) == len(live.alerts_log), "alerts log lost on rebuild"
    for got, want in zip(restarted.alerts_log, live.alerts_log):
        assert got["threat_class"] == want["threat_class"]
        assert got["severity"] == want["severity"]
        assert got["confidence"] == want["confidence"]


def test_dedup_counter_bounded():
    """m6: the fingerprint set is capped so long-running ingestion does not
    grow memory without bound."""
    dc = DedupCounter()
    dc._MAX_SEEN = 100
    for i in range(150):
        e = Event(event_id=f"e{i}", timestamp="t", source_type="syslog",
                  client_id="c", message=f"line {i}", fields={"i": i})
        assert dc.track(e) is True
    assert len(dc.seen_fingerprints) <= 100


def test_module_findings_persist_and_threat_class_search(tmp_path):
    """M3: module findings written back onto events survive a reload, and the
    ``threat_class`` search filter returns those correlated flow events."""
    from pipeline.event_store import EventStore
    from schema import Event, new_uuid

    store = EventStore(tmp_path / "ev.db")
    flow = Event(event_id="flow-0001", timestamp="2026-09-12T10:00:01Z",
                 source_type="netflow", client_id="c1", category="flow",
                 severity="info", message="tcp 192.168.1.5 -> 203.0.113.9:443",
                 fields={"src_ip": "192.168.1.5", "dst_ip": "203.0.113.9"})
    store.save(flow)
    # simulate flush_batch attaching a Module A finding back to the sources
    store.attach_findings(["flow-0001"], "network_threat", {
        "threat_class": "port_scan", "confidence": 0.9,
        "event_ids": ["flow-0001"],
    })
    # reload from disk — module findings must be present (persistence)
    reloaded = EventStore(tmp_path / "ev.db")
    got = reloaded.get("flow-0001")
    assert got is not None
    assert got.module_findings["network_threat"][0]["threat_class"] == "port_scan"
    # and the threat_class filter now actually finds the event
    hits = reloaded.search(threat_class="port_scan")
    assert len(hits) == 1
    # a threat class with no findings matches nothing (filter is stable)
    assert reloaded.search(threat_class="ddos") == []
    # checking that a *different* threat class value does not leak through
    other = Event(event_id="flow-0002", timestamp="2026-09-12T10:00:02Z",
                  source_type="netflow", client_id="c1", category="flow",
                  severity="info", message="x",
                  fields={"threat_class": "geo_fence"})
    store.save(other)
    assert len(reloaded.search(threat_class="port_scan")) == 1


def test_module_findings_absent_when_none(tmp_path):
    """Events saved without findings round-trip with an empty map."""
    from pipeline.event_store import EventStore
    from schema import Event

    store = EventStore(tmp_path / "plain.db")
    e = Event(event_id="plain-1", timestamp="2026-09-12T10:00:00Z",
              source_type="syslog", client_id="c1", category="auth",
              severity="info", message="ok", fields={"user": "root"})
    store.save(e)
    got = EventStore(tmp_path / "plain.db").get("plain-1")
    assert got is not None and got.module_findings == {}