"""Dashboard auth tests: login, bearer guard, roles, admin-only routes."""

import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

import backend.app.main as api_module


@pytest.fixture(scope="module")
def client():
    with TestClient(api_module.app) as c:
        yield c


def _login(c, username="admin", password="admin"):
    resp = c.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def test_health_is_public(client):
    assert client.get("/api/health").status_code == 200


def test_protected_route_requires_token(client):
    assert client.get("/api/clients").status_code == 401
    assert client.get("/api/events/search").status_code == 401


def test_login_wrong_password_401(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_me_round_trip(client):
    headers = _login(client)
    me = client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["username"] == "admin"
    assert me.json()["role"] == "admin"


def test_admin_can_access_dashboard_data(client):
    headers = _login(client)
    # 428 means "authenticated but boostrap first" — proves auth passed.
    assert client.get("/api/dashboard", headers=headers).status_code in (200, 428)
    assert client.get("/api/clients", headers=headers).status_code in (200, 428)


def test_register_and_viewer_role(client):
    who = f"viewer-{uuid.uuid4().hex[:8]}"
    admin_headers = _login(client)
    reg = client.post("/api/auth/register", headers=admin_headers,
                      json={"username": who, "password": "viewer-pass", "role": "viewer"})
    assert reg.status_code == 200, reg.text

    vh = _login(client, username=who, password="viewer-pass")
    assert vh["Authorization"].startswith("Bearer ")
    # viewer can read dashboard data
    assert client.get("/api/clients", headers=vh).status_code in (200, 428)
    # viewer cannot run destructive bootstrap
    assert client.post("/api/demo/run", headers=vh).status_code == 403
    # viewer cannot create users
    reg2 = client.post("/api/auth/register", headers=vh,
                       json={"username": "nope", "password": "nope-nope", "role": "viewer"})
    assert reg2.status_code == 403


def test_register_requires_admin(client):
    assert client.post("/api/auth/register",
                       json={"username": "x", "password": "y-123456"}).status_code == 401


def test_demo_run_requires_admin(client):
    headers = _login(client)
    assert client.post("/api/demo/run", headers=headers).status_code == 200


def test_tampered_token_rejected(client):
    headers = _login(client)
    token = headers["Authorization"].split("Bearer ")[1]
    tampered = token[:-2] + ("!!" if not token.endswith("==") else "AA")
    resp = client.get("/api/clients", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401


# ---------------------------------------------------------------- analyst role


def test_register_accepts_analyst_role(client):
    who = f"analyst-{uuid.uuid4().hex[:8]}"
    admin_headers = _login(client)
    reg = client.post("/api/auth/register", headers=admin_headers,
                      json={"username": who, "password": "analyst-pass", "role": "analyst"})
    assert reg.status_code == 200, reg.text
    assert reg.json()["role"] == "analyst"
    ah = _login(client, username=who, password="analyst-pass")
    assert client.get("/api/auth/me", headers=ah).json()["role"] == "analyst"
    # analysts read the queue + policy lists
    assert client.get("/api/cases/stats", headers=ah).status_code == 200
    assert client.get("/api/rules", headers=ah).status_code == 200
    assert client.get("/api/watchlist", headers=ah).status_code == 200
    # but cannot mutate policy or create users
    assert client.post("/api/watchlist", headers=ah,
                       json={"list": "watchlist", "kind": "ip",
                             "value": "203.0.113.9", "reason": "analyst?"}).status_code == 403
    assert client.post("/api/rules", headers=ah,
                       json={"name": "nope", "min_severity": "warning",
                             "action": "alert", "match": []}).status_code == 403
    assert client.post("/api/auth/register", headers=ah,
                       json={"username": "x2", "password": "x2-x2-x2-x2",
                             "role": "analyst"}).status_code == 403


def test_role_validation_on_register(client):
    admin_headers = _login(client)
    for bad in ("root", "superadmin", ""):
        resp = client.post("/api/auth/register", headers=admin_headers,
                           json={"username": f"u-{uuid.uuid4().hex[:6]}",
                                 "password": "pass-12345", "role": bad})
        assert resp.status_code == 400, resp.text


def _seed_case(seed):
    case = api_module._SOC.record_flow_finding({
        "severity": "high",
        "threat_class": f"flow-{seed}",
        "flow_id": f"flow-{seed}",
        "timestamp": "2026-09-15T00:00:00Z",
        "evidence": {"src": seed},
    })
    assert case is not None, "failed to seed a triage case"
    return case["id"]


def test_case_triage_role_gate(client):
    cid = _seed_case("rbac")
    who = f"analyst-{uuid.uuid4().hex[:8]}"
    who_v = f"viewer-{uuid.uuid4().hex[:8]}"
    admin = _login(client)
    client.post("/api/auth/register", headers=admin,
                json={"username": who, "password": "analyst-pass", "role": "analyst"})
    client.post("/api/auth/register", headers=admin,
                json={"username": who_v, "password": "viewer-pass", "role": "viewer"})
    ah = _login(client, username=who, password="analyst-pass")
    vh = _login(client, username=who_v, password="viewer-pass")

    # analyst can ack a case
    assert client.patch(f"/api/cases/{cid}", headers=ah,
                        json={"action": "ack"}).status_code == 200
    # viewer is read-only: PATCH is refused before it reaches the policy
    assert client.patch(f"/api/cases/{cid}", headers=vh,
                        json={"action": "unack"}).status_code == 403
    # analysts can also resolve / assign / annotate
    assert client.patch(f"/api/cases/{cid}", headers=ah,
                        json={"action": "assign", "assignee": "irfan"}).status_code == 200
    assert client.patch(f"/api/cases/{cid}", headers=ah,
                        json={"action": "resolve", "note": "closed out"}).status_code == 200
    # admin can reopen
    assert client.patch(f"/api/cases/{cid}", headers=admin,
                        json={"action": "reopen"}).status_code == 200


def test_users_admin_only(client):
    admin = _login(client)
    who = f"analyst-{uuid.uuid4().hex[:8]}"
    client.post("/api/auth/register", headers=admin,
                json={"username": who, "password": "analyst-pass", "role": "analyst"})
    # analysts and strangers cannot list users
    assert client.get("/api/auth/users").status_code == 401
    ah = _login(client, username=who, password="analyst-pass")
    assert client.get("/api/auth/users", headers=ah).status_code == 403
    # admin can, and the roster includes the seeds + new analyst
    roster = client.get("/api/auth/users", headers=admin)
    assert roster.status_code == 200
    usernames = [u["username"] for u in roster.json()["users"]]
    assert "admin" in usernames and who in usernames
    assert "password_hash" not in roster.json()["users"][0]


def test_delete_user_rules(client):
    admin = _login(client)
    who = f"analyst-{uuid.uuid4().hex[:8]}"
    client.post("/api/auth/register", headers=admin,
                json={"username": who, "password": "analyst-pass", "role": "analyst"})
    # cannot delete yourself
    assert client.delete("/api/auth/users/admin", headers=admin).status_code == 400
    # a second admin can be removed by the first (two admins exist at that point)
    other = f"admin2-{uuid.uuid4().hex[:8]}"
    client.post("/api/auth/register", headers=admin,
                json={"username": other, "password": "admin-pass-2", "role": "admin"})
    assert client.delete(f"/api/auth/users/{other}", headers=admin).status_code == 200
    assert client.post("/api/auth/login",
                       json={"username": other, "password": "admin-pass-2"}).status_code == 401
    # delete the analyst — gone afterwards
    assert client.delete(f"/api/auth/users/{who}", headers=admin).status_code == 200
    assert client.post("/api/auth/login",
                       json={"username": who, "password": "analyst-pass"}).status_code == 401
    # analysts cannot delete anyone (require_admin fires first)
    again = f"analyst-{uuid.uuid4().hex[:8]}"
    client.post("/api/auth/register", headers=admin,
                json={"username": again, "password": "analyst-pass", "role": "analyst"})
    ah = _login(client, username=again, password="analyst-pass")
    assert client.delete(f"/api/auth/users/{again}", headers=ah).status_code == 403
    # missing user
    assert client.delete("/api/auth/users/ghost-404", headers=admin).status_code == 404


def test_deleted_user_token_is_revoked(client):
    """M1: a JWT minted before account deletion stops working immediately."""
    admin = _login(client)
    who = f"revoke-{uuid.uuid4().hex[:8]}"
    client.post("/api/auth/register", headers=admin,
                json={"username": who, "password": "revoke-pass", "role": "viewer"})
    headers = _login(client, username=who, password="revoke-pass")
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    assert client.delete(f"/api/auth/users/{who}", headers=admin).status_code == 200
    # the old (still cryptographically valid, unexpired) token is now rejected
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_password_change_revokes_old_token(client):
    """M1: password rotation bumps token_version, killing old sessions."""
    admin = _login(client)
    who = f"pwrot-{uuid.uuid4().hex[:8]}"
    client.post("/api/auth/register", headers=admin,
                json={"username": who, "password": "rot-pass-1", "role": "viewer"})
    old = _login(client, username=who, password="rot-pass-1")
    assert client.get("/api/auth/me", headers=old).status_code == 200
    resp = client.post("/api/auth/change-password", headers=old,
                       json={"current_password": "rot-pass-1", "new_password": "rot-pass-2"})
    assert resp.status_code == 200, resp.text
    # the pre-rotation token is revoked
    assert client.get("/api/auth/me", headers=old).status_code == 401
    # logging in with the new password works and returns a fresh token
    new = _login(client, username=who, password="rot-pass-2")
    assert client.get("/api/auth/me", headers=new).status_code == 200
    assert client.post("/api/auth/login",
                       json={"username": who, "password": "rot-pass-1"}).status_code == 401


def test_bruteforce_lockout_returns_429(client):
    """M2: repeated failed logins for a user+IP are throttled with 429."""
    admin = _login(client)
    who = f"locked-{uuid.uuid4().hex[:8]}"
    client.post("/api/auth/register", headers=admin,
                json={"username": who, "password": "lock-pass", "role": "viewer"})
    payload = {"username": who, "password": "wrong-pass"}
    for _ in range(4):
        assert client.post("/api/auth/login", json=payload).status_code == 401
    # the 5th failure tips over the threshold
    assert client.post("/api/auth/login", json=payload).status_code == 401
    # subsequent attempts are locked out even with the correct password
    locked = client.post("/api/auth/login",
                         json={"username": who, "password": "lock-pass"})
    assert locked.status_code == 429
    assert "Retry-After" in locked.headers


def test_lockout_keyed_by_username(client):
    """M2: locking one user does not lock out users with different names."""
    admin = _login(client)
    hit = f"hit-{uuid.uuid4().hex[:8]}"
    miss = f"miss-{uuid.uuid4().hex[:8]}"
    client.post("/api/auth/register", headers=admin,
                json={"username": hit, "password": "hit-pass", "role": "viewer"})
    client.post("/api/auth/register", headers=admin,
                json={"username": miss, "password": "miss-pass", "role": "viewer"})
    payload = {"username": hit, "password": "wrong"}
    for _ in range(5):
        client.post("/api/auth/login", json=payload)
    assert client.post("/api/auth/login", json=payload).status_code == 429
    # unrelated user can still log in
    assert client.post("/api/auth/login",
                       json={"username": miss, "password": "miss-pass"}).status_code == 200
