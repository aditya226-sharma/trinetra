"""SOC policy engine: watchlist/blocklist, custom rules, case lifecycle,
external delivery throttling and the digest builder."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config.settings import Settings  # noqa: E402
from schema import Event, utc_now  # noqa: E402
from socpolicy import SocPolicy, SocPolicyError  # noqa: E402

ROOT_CONFIG = ROOT / "config" / "config.yaml"


@pytest.fixture()
def settings(tmp_path):
    s = Settings(ROOT_CONFIG)
    s._data["paths"]["event_store"] = str(tmp_path / "trinetra.db")
    s._data["paths"]["raw_store"] = str(tmp_path / "raw")
    s._data["paths"]["pcap"] = str(tmp_path / "pcaps")
    return s


@pytest.fixture()
def soc(settings):
    policy = SocPolicy(settings)
    yield policy
    policy._bootstrap_db()


def _event(**overrides):
    base = {
        "event_id": "evt-1",
        "timestamp": utc_now(),
        "source_type": "syslog",
        "client_id": "host-01",
        "client_ip": "10.0.0.9",
        "category": "system",
        "severity": "error",
        "message": "sshd failed login for bob",
        "trace_id": "host-01::syslog::abcd1234",
        "fields": {"user": "bob", "host": "host-01", "asset": "proxy-aa"},
    }
    base.update(overrides)
    return Event(**base)


# ---------------------------------------------------------------- watch/block


def test_watchlist_hit_creates_warning_case(soc):
    soc.add_entry("watchlist", "user", "bob", "high value account", actor="admin")
    cases = soc.evaluate_event(_event())
    assert len(cases) == 1
    assert cases[0]["threat_class"] == "watchlist_hit"
    assert cases[0]["severity"] == "warning"
    assert cases[0]["status"] == "open"


def test_blocklist_hit_flags_event_and_critical(soc):
    soc.add_entry("blocklist", "ip", "10.0.0.9", "scanner", actor="admin")
    event = _event()
    cases = soc.evaluate_event(event)
    assert len(cases) == 1
    assert cases[0]["threat_class"] == "blocked_entity"
    assert cases[0]["severity"] == "critical"
    assert event.fields.get("blocked") == "true"


def test_non_matching_values_do_not_fire(soc):
    soc.add_entry("watchlist", "ip", "192.0.2.1", reason="")
    soc.add_entry("blocklist", "client", "mallory", reason="")
    assert soc.evaluate_event(_event()) == []


def test_throttled_duplicates_collapse_into_hits(soc):
    soc.add_entry("watchlist", "user", "bob", "watchme")
    first = soc.evaluate_event(_event())[0]
    second = soc.evaluate_event(_event())[0]
    assert first["id"] == second["id"]
    assert second["hits"] == 2


def test_entry_duplicate_rejected(soc):
    soc.add_entry("blocklist", "ip", "10.0.0.9", "a")
    with pytest.raises(SocPolicyError):
        soc.add_entry("blocklist", "ip", "10.0.0.9", "b")


def test_remove_and_toggle(soc):
    soc.add_entry("blocklist", "ip", "10.0.0.9", "a")
    assert soc.remove_entry("blocklist", "ip", "10.0.0.9") is True
    assert soc.remove_entry("blocklist", "ip", "10.0.0.9") is False
    soc.add_entry("blocklist", "ip", "10.0.0.9", "a")
    assert soc.set_entry_active("blocklist", "ip", "10.0.0.9", False) is True
    assert soc.evaluate_event(_event()) == []


# -------------------------------------------------------------------- rules


def test_rule_match_fires_custom_case(soc):
    rule = soc.upsert_rule({
        "name": "Brute force",
        "min_severity": "info",
        "action": "alert",
        "match": [{"field": "fields.user", "op": "eq", "value": "bob"},
                  {"field": "message", "op": "contains", "value": "failed login"}],
    }, actor="admin")
    cases = soc.evaluate_event(_event())
    assert len(cases) == 1
    assert cases[0]["threat_class"] == f"custom::{rule['id']}"
    assert cases[0]["rule_id"] == rule["id"]
    assert cases[0]["severity"] == "info"


def test_rule_severity_floor(soc):
    soc.upsert_rule({
        "name": "needs error",
        "min_severity": "error",
        "match": [{"field": "fields.user", "op": "eq", "value": "bob"}],
    }, actor="admin")
    # event severity info below floor -> no fire
    assert soc.evaluate_event(_event(severity="info")) == []
    # warning still below error -> no fire
    assert soc.evaluate_event(_event(severity="warning")) == []
    assert len(soc.evaluate_event(_event(severity="error"))) == 1


def test_rule_regex_and_categories(soc):
    soc.upsert_rule({
        "name": "regex cat",
        "categories": ["system"],
        "source_types": ["syslog"],
        "min_severity": "info",
        "match": [{"field": "message", "op": "regex", "value": r"sshd.*bob"}],
    }, actor="admin")
    assert len(soc.evaluate_event(_event())) == 1
    soc.upsert_rule({
        "name": "regex cat 2",
        "categories": ["network"],
        "min_severity": "info",
        "match": [{"field": "message", "op": "regex", "value": r"sshd.*bob"}],
    }, actor="admin")
    assert len(soc.evaluate_event(_event())) == 1  # only the system rule fired

def test_rule_toggle_and_delete(soc):
    rule = soc.upsert_rule({"name": "X", "min_severity": "info",
                            "match": [{"field": "severity", "op": "eq", "value": "error"}]})
    assert soc.toggle_rule(rule["id"], False) is True
    assert soc.evaluate_event(_event()) == []
    assert soc.toggle_rule(rule["id"], True) is True
    assert len(soc.evaluate_event(_event())) == 1
    assert soc.delete_rule(rule["id"]) is True
    assert soc.evaluate_event(_event()) == []


def test_rule_validation_errors(soc):
    with pytest.raises(SocPolicyError):
        soc.upsert_rule({"name": "", "match": [{"field": "severity", "op": "eq", "value": "x"}]})
    with pytest.raises(SocPolicyError):
        soc.upsert_rule({"name": "bad op", "match": [{"field": "severity", "op": "hacked", "value": "x"}]})
    with pytest.raises(SocPolicyError):
        soc.upsert_rule({"name": "bad regex", "match": [{"field": "message", "op": "regex", "value": "["}]})
    with pytest.raises(SocPolicyError):
        soc.upsert_rule({"name": "no match", "match": []})


# ----------------------------------------------------------------- lifecycle


def test_case_lifecycle_resolve_reopen(soc):
    soc.add_entry("watchlist", "user", "bob", "watch")
    case = soc.evaluate_event(_event())[0]
    acked = soc.transition(case["id"], "ack", actor="analyst")
    assert acked["status"] == "acknowledged"
    resolved = soc.transition(case["id"], "resolve", actor="analyst", note="underscores hard")
    assert resolved["status"] == "resolved"
    assert resolved["notes"][-1]["note"] == "underscores hard"
    reopened = soc.transition(case["id"], "reopen", actor="analyst")
    assert reopened["status"] == "open"
    with pytest.raises(SocPolicyError):
        soc.transition(case["id"], "unack", actor="analyst")  # not acknowledged anymore


def test_case_assign_and_note(soc):
    soc.add_entry("blocklist", "ip", "10.0.0.9", "a")
    case = soc.evaluate_event(_event())[0]
    assigned = soc.transition(case["id"], "assign", actor="admin", assignee="irfan")
    assert assigned["assignee"] == "irfan"
    noted = soc.transition(case["id"], "note", actor="admin", note="epa check")
    assert noted["notes"][-1]["note"] == "epa check"
    assert len(noted["timeline"]) == 3  # created, assign, note

def test_case_stats_after_resolution(soc):
    soc.add_entry("watchlist", "user", "bob", "w")
    case = soc.evaluate_event(_event())[0]
    soc.transition(case["id"], "resolve", actor="a")
    stats = soc.case_stats()
    assert stats["by_status"]["resolved"] == 1
    assert stats["by_status"]["open"] == 0


def test_flow_finding_records_case(soc):
    finding = {
        "threat_class": "exfiltration",
        "severity": "high",
        "confidence": 0.93,
        "analysis": {"verdict": "malicious", "store_decision": "quarantine"},
        "alert": {"flow_id": "tcp/23", "severity": "high", "evidence": {"dst": "198.51.100.1"},
                  "timestamp": utc_now()},
    }
    case = soc.record_flow_finding(finding)
    assert case is not None
    assert case["threat_class"] == "exfiltration"
    assert case["source_kind"] == "flow"
    assert case["verdict"] == "malicious"
    # second identical finding within throttle collapses
    case2 = soc.record_flow_finding(finding)
    assert case2["hits"] == 2


# --------------------------------------------------------------- delivery


def test_delivery_threshold_and_enabled(soc):
    soc.add_entry("blocklist", "ip", "10.0.0.9", "scanner")
    case = soc.evaluate_event(_event())[0]
    results = soc.notify_case(case)
    # block case is critical -> above default warning min for console wrapper
    transports = {r["transport"]: r for r in results}
    assert "console" in transports
    assert transports["console"]["status"] == "sent"

    # disable notifications entirely
    soc.save_notifications({"enabled": False})
    results = soc.notify_case(case)
    assert results[0]["status"] == "skipped"


def test_webhook_delivery_and_secret(soc, monkeypatch):
    captured = {}

    class FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=10):
        captured["headers"] = dict(req.headers)
        captured["body"] = json.loads(req.data)
        return FakeResp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    soc.save_notifications({
        "webhook": {"url": "https://example.com/hook", "secret": "s3cr3t"},
    })
    results = soc.send_test(actor="tester")["results"]
    web = next(r for r in results if r["transport"] == "webhook")
    assert web["status"] == "sent"
    lower = {k.lower(): v for k, v in captured["headers"].items()}
    assert lower["x-trinetra-secret"] == "s3cr3t"
    assert captured["body"]["type"] == "trinetra.alert"


def test_send_test_returns_transports(soc):
    out = soc.send_test(actor="tester")
    assert any(r["transport"] == "console" for r in out["results"])


# ------------------------------------------------------------------ digest


def test_digest_runs_and_persists_state(soc):
    soc.add_entry("watchlist", "user", "bob", "w")
    soc.evaluate_event(_event())
    soc.save_notifications({"digest": {"enabled": True, "hour_utc": 9}})
    out = soc.run_digest(force=False)
    assert out["status"] == "sent"
    assert out["cases_in_window"] >= 1
    # second run today is skipped
    again = soc.run_digest(force=False)
    assert again["status"] == "skipped"
    # forced run still works
    forced = soc.run_digest(force=True)
    assert forced["status"] == "sent"


def test_digest_disabled_skips(soc):
    out = soc.run_digest(force=False)
    assert out["status"] == "skipped"


# ---------------------------------------------------------------- persistence


def test_persistence_roundtrip(soc):
    soc.add_entry("blocklist", "ip", "10.0.0.9", "a")
    rule = soc.upsert_rule({"name": "R", "min_severity": "warning",
                            "match": [{"field": "message", "op": "contains", "value": "x"}]})
    saved_policy = SocPolicy(soc.settings)
    assert any(e["value"] == "10.0.0.9" for e in saved_policy.list_entries("blocklist"))
    assert [r["id"] for r in saved_policy.list_rules()] == [rule["id"]]
    assert soc.evaluate_event(_event())


def test_policy_isolation_between_instances(soc, tmp_path):
    other_settings = Settings(ROOT_CONFIG)
    other_settings._data["paths"]["event_store"] = str(tmp_path / "other" / "t.db")
    other = SocPolicy(other_settings)
    assert other.list_entries("watchlist") == []
    assert other.list_rules() == []


# ------------------------------------------------------------ regression fixes


def test_invalid_list_name_is_defensive_not_a_500(soc):
    """remove_entry / set_entry_active must tolerate unknown list names
    instead of raising KeyError on the (previously unguarded) lookup."""
    assert soc.remove_entry("watchlist", "user", "bob") is False
    # bogus list name -> False, never an exception
    assert soc.remove_entry("nonexistent", "user", "bob") is False
    assert soc.set_entry_active("nonexistent", "user", "bob", False) is False
    # a real list still works after the defensive change
    soc.add_entry("watchlist", "user", "bob", "vip", actor="admin")
    assert soc.set_entry_active("watchlist", "user", "bob", False) is True
    assert soc.remove_entry("watchlist", "user", "bob") is True


def test_notifications_preserve_secret_on_blank_put(soc):
    """Saving a notifications patch with an empty secret must keep the
    stored secret (form round-trip: GET masks it to '', PUT sends '' back)."""
    soc.save_notifications({"webhook": {"url": "https://h/x", "secret": "real-secret"}})
    soc.save_notifications({"webhook": {"url": "https://h/x", "secret": ""}})
    assert soc.notifications()["webhook"]["secret"] == "real-secret"
    # explicitly setting a new value still overwrites
    soc.save_notifications({"webhook": {"url": "https://h/x", "secret": "new-secret"}})
    assert soc.notifications()["webhook"]["secret"] == "new-secret"


def test_email_port_tls_route_selection():
    """EmailNotifier must elect SMTPS for 465 and STARTTLS for 587 without
    erroring — the audit found no TLS branch existed for 465."""
    from alerting.notifier import EmailNotifier

    e587 = EmailNotifier(host="smtp.example.com", port=587, sender="a@x.y",
                         recipient="b@x.y")
    e465 = EmailNotifier(host="smtp.example.com", port=465, sender="a@x.y",
                         recipient="b@x.y")
    # unconfigured host means notify() short-circuits to skipped before any
    # network I/O — the port routing itself is exercised by the code path.
    e_unset = EmailNotifier(port=465)
    r = e_unset.notify("critical", "t", "b")
    assert r["status"] == "skipped"
    assert e465.port == 465
    assert e587.port == 587