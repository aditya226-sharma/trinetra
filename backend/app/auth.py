"""TriNetra dashboard authentication.

Dependency-free auth for the live dashboard: pbkdf2 password hashing and
HS256-signed bearer tokens, both stdlib. Users live in a small SQLite
``users`` table (``trinetra_users.db``) next to the event store.

    POST /api/auth/login     username + password -> {access_token, role, ...}
    GET  /api/auth/me        current user (requires bearer token)
    POST /api/auth/register  create a user (admin only)

Roles:
    admin   everything, including demo/ingest reset + user management
    viewer  read-only dashboard access

The agent ingest path (``POST /api/ingest-events``) is authenticated
separately with a shared ``X-Agent-Token`` — never with dashboard logins.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from config.settings import Settings, get_settings
from backend.app.services.audit import audit_log

log = logging.getLogger("trinetra.auth")

_PBKDF2_ITERATIONS = 200_000
_ALG = "sha256"

# --- M2: brute-force lockout state (per (ip, username) -> [timestamps]) ---
_login_failures: Dict[tuple, list] = {}
_LOCKOUT_MAX_FAILURES = 5
_LOCKOUT_WINDOW_S = 900  # 15 minutes
_LOCKOUT_BACKOFF_S = 900  # 15 min after 5 failures
_MAX_LOGIN_FAILURE_ENTRIES = 512


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=128)
    role: str = "viewer"


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=6, max_length=128)


router = APIRouter(prefix="/api/auth", tags=["auth"])


# ------------------------------------------------------------------- password


def _hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(_ALG, password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"{_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        iterations, salt_hex, hash_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac(_ALG, password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


# ------------------------------------------------------------------- storage


def _users_path(settings: Settings) -> Path:
    return Path(settings.path("event_store")).parent / "trinetra_users.db"


def _connect(settings: Settings) -> sqlite3.Connection:
    path = _users_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        " username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,"
        " role TEXT NOT NULL, created_at TEXT NOT NULL,"
        " token_version INTEGER NOT NULL DEFAULT 0)")
    # Migrate existing databases that lack the token_version column.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "token_version" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0")
    conn.commit()
    return conn


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_admin(settings: Settings) -> None:
    """Seed the first admin account from ADMIN_USER/ADMIN_PASSWORD (or the
    documented demo default admin/admin). No-op once any user exists."""
    conn = _connect(settings)
    try:
        row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        if int(row["c"]) > 0:
            return
        username = str(settings.get("auth.admin_user") or os.environ.get("ADMIN_USER", "")) or "admin"
        password = str(settings.get("auth.admin_password") or os.environ.get("ADMIN_PASSWORD", "")) or "admin"
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at, token_version)"
            " VALUES (?, ?, ?, ?, ?)",
            (username, _hash_password(password), "admin", _iso_now(), secrets.randbelow(1 << 32)))
        conn.commit()
        if password == "admin":
            log.warning("Seeded default admin user (admin/admin) — set ADMIN_PASSWORD in production.")
    finally:
        conn.close()


def create_user(settings: Settings, username: str, password: str, role: str) -> None:
    conn = _connect(settings)
    try:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            raise HTTPException(status_code=409, detail="user already exists")
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at, token_version)"
            " VALUES (?, ?, ?, ?, ?)",
            (username, _hash_password(password), role, _iso_now(), secrets.randbelow(1 << 32)))
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------- JWT (HS256)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _jwt_secret(settings: Settings) -> str:
    configured = (str(settings.get("auth.jwt_secret") or "")
                  or os.environ.get("TRINETRA_JWT_SECRET", "")).strip()
    if configured:
        return configured
    # Persist a generated secret so sessions survive restarts.
    path = _users_path(settings).with_name(".trinetra_jwt_secret")
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = secrets.token_hex(32)
    path.write_text(value, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return value


def make_token(settings: Settings, username: str, role: str, version: int = 0) -> str:
    now = int(time.time())
    expiry = now + int(settings.get("auth.jwt_expiry_hours", 12)) * 3600
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": username, "role": role, "iat": now, "exp": expiry, "ver": int(version)}
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        + "." + _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    )
    sig = hmac.new(_jwt_secret(settings).encode("utf-8"),
                   signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + _b64url(sig)


def decode_token(settings: Settings, token: str) -> Optional[Dict[str, Any]]:
    try:
        signing_input, sig_b64 = token.rsplit(".", 1)
        expected = hmac.new(_jwt_secret(settings).encode("utf-8"),
                            signing_input.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(sig_b64, _b64url(expected)):
            return None
        payload = json.loads(_b64url_decode(signing_input.split(".")[1]))
        if int(payload.get("exp", 0)) < time.time():
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


# ------------------------------------------------------------------ M2 (login lockout)


def _record_login_failure(key: tuple) -> None:
    now = time.time()
    _login_failures.setdefault(key, []).append(now)
    # Prune expired timestamps and bound the dict (m6: no unbounded growth).
    _login_failures[key] = [t for t in _login_failures[key]
                            if now - t <= _LOCKOUT_WINDOW_S]
    if len(_login_failures) > _MAX_LOGIN_FAILURE_ENTRIES:
        for stale_key in [k for k, vs in _login_failures.items()
                          if not vs or now - vs[-1] > _LOCKOUT_WINDOW_S]:
            _login_failures.pop(stale_key, None)
        if len(_login_failures) > _MAX_LOGIN_FAILURE_ENTRIES:
            # Still over budget — drop oldest entries.
            ordered = sorted(_login_failures, key=lambda k: _login_failures[k][-1])
            for stale_key in ordered[:len(_login_failures) - _MAX_LOGIN_FAILURE_ENTRIES]:
                _login_failures.pop(stale_key, None)


def _login_locked(key: tuple) -> Optional[int]:
    """Return remaining lockout seconds if ``key`` is locked, else None."""
    stamps = [t for t in _login_failures.get(key, [])
              if time.time() - t <= _LOCKOUT_WINDOW_S]
    _login_failures[key] = stamps
    if len(stamps) >= _LOCKOUT_MAX_FAILURES:
        return max(1, int(_LOCKOUT_BACKOFF_S - (time.time() - stamps[0])))
    return None


def _clear_login_failures(key: tuple) -> None:
    _login_failures.pop(key, None)


# ------------------------------------------------------------------- dependencies

_bearer = HTTPBearer(auto_error=False)


def _user_version(settings: Settings, username: str) -> Optional[int]:
    """Current token_version for a user, or None if the account is gone."""
    try:
        conn = _connect(settings)
        try:
            row = conn.execute("SELECT token_version FROM users WHERE username = ?",
                               (username,)).fetchone()
            return int(row["token_version"]) if row else None
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001
        log.warning("could not resolve user version %s: %s", username, exc)
        return None


def _check_token_current(settings: Settings, payload: Dict[str, Any]) -> bool:
    """Reject tokens for deleted accounts and tokens minted before a password
    change or account re-creation (token_version rotation)."""
    username = str(payload.get("sub", ""))
    current = _user_version(settings, username)
    if current is None:
        return False
    return payload.get("ver") == current


def require_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
                 settings: Settings = Depends(get_settings)) -> Dict[str, Any]:
    """Require a valid bearer token; returns its decoded payload."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated",
                            headers={"WWW-Authenticate": "Bearer"})
    payload = decode_token(settings, credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})
    if not _check_token_current(settings, payload):
        raise HTTPException(status_code=401, detail="Token has been revoked",
                            headers={"WWW-Authenticate": "Bearer"})
    return payload


def require_admin(payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return payload


def require_analyst(payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    """Admins and SOC analysts may triage cases; pure viewers stay read-only."""
    if payload.get("role") not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Analyst privileges required")
    return payload


async def require_token_query(request: Request,
                              settings: Settings = Depends(get_settings)) -> Dict[str, Any]:
    """SSE (EventSource) can't set an Authorization header, so accept the
    bearer token from ``?token=`` as well."""
    credentials = await _bearer(request)
    token = credentials.credentials if credentials else (request.query_params.get("token") or "")
    payload = decode_token(settings, token) if token else None
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if not _check_token_current(settings, payload):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    return payload


# ------------------------------------------------------------------- endpoints


@router.post("/login", response_model=dict)
def login(body: LoginRequest, request: Request,
          settings: Settings = Depends(get_settings)) -> Dict[str, Any]:
    ensure_admin(settings)
    ip = request.client.host if request.client else ""
    key = (body.username, ip)
    locked = _login_locked(key)
    if locked:
        raise HTTPException(status_code=429,
                            detail=f"Too many failed attempts — retry in {locked}s",
                            headers={"Retry-After": str(locked)})
    conn = _connect(settings)
    try:
        row = conn.execute(
            "SELECT password_hash, role, token_version FROM users WHERE username = ?",
            (body.username,)).fetchone()
    finally:
        conn.close()
    if row is None or not _verify_password(body.password, str(row["password_hash"])):
        _record_login_failure(key)
        audit_log(settings, body.username, "auth.login_failed", "bad credentials")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    _clear_login_failures(key)
    token = make_token(settings, body.username, str(row["role"]),
                       version=int(row["token_version"]))
    audit_log(settings, body.username, "auth.login", f"role={row['role']}")
    return {"access_token": token, "token_type": "bearer",
            "username": body.username, "role": str(row["role"])}


@router.get("/me", response_model=dict)
def me(payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, str]:
    return {"username": str(payload.get("sub")), "role": str(payload.get("role"))}


@router.post("/register", response_model=dict,
             dependencies=[Depends(require_admin)])
def register(body: RegisterRequest,
             payload: Dict[str, Any] = Depends(require_admin),
             settings: Settings = Depends(get_settings)) -> Dict[str, str]:
    if body.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400,
                            detail="role must be 'admin', 'analyst' or 'viewer'")
    create_user(settings, body.username, body.password, body.role)
    audit_log(settings, str(payload.get("sub", "admin")), "auth.register",
              f"created user {body.username} (role={body.role})")
    return {"username": body.username, "role": body.role}


@router.get("/users", response_model=dict, dependencies=[Depends(require_admin)])
def users_list(settings: Settings = Depends(get_settings)) -> Dict[str, Any]:
    """Admin view of the dashboard accounts (no password material)."""
    conn = _connect(settings)
    try:
        rows = conn.execute(
            "SELECT username, role, created_at FROM users ORDER BY created_at").fetchall()
    finally:
        conn.close()
    return {"users": [dict(r) for r in rows]}


@router.delete("/users/{username}", response_model=dict,
               dependencies=[Depends(require_admin)])
def users_delete(username: str,
                 payload: Dict[str, Any] = Depends(require_admin),
                 settings: Settings = Depends(get_settings)) -> Dict[str, bool]:
    """Remove an account; you cannot delete yourself or the last admin."""
    if username == str(payload.get("sub", "")):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    conn = _connect(settings)
    try:
        target = conn.execute("SELECT role FROM users WHERE username = ?",
                              (username,)).fetchone()
        if target is None:
            raise HTTPException(status_code=404, detail="user not found")
        if str(target["role"]) == "admin":
            admins = conn.execute(
                "SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").fetchone()
            if int(admins["c"]) <= 1:
                raise HTTPException(status_code=400,
                                    detail="Cannot delete the last admin account")
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
    finally:
        conn.close()
    audit_log(settings, str(payload.get("sub", "admin")), "auth.delete_user",
              f"deleted user {username}")
    return {"deleted": True}


@router.post("/change-password", response_model=dict)
def change_password(body: ChangePasswordRequest,
                    payload: Dict[str, Any] = Depends(require_auth),
                    settings: Settings = Depends(get_settings)) -> Dict[str, bool]:
    """Rotate your own password after proving the current one.
    """
    username = str(payload.get("sub"))
    conn = _connect(settings)
    try:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)).fetchone()
        if row is None or not _verify_password(body.current_password,
                                               str(row["password_hash"])):
            audit_log(settings, username, "auth.change_password_failed",
                      "wrong current password")
            raise HTTPException(status_code=401, detail="Current password is incorrect")
        conn.execute("UPDATE users SET password_hash = ?, token_version = token_version + 1"
                     " WHERE username = ?",
                     (_hash_password(body.new_password), username))
        conn.commit()
    finally:
        conn.close()
    audit_log(settings, username, "auth.change_password", "rotated password")
    return {"ok": True}
