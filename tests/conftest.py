"""Test isolation: run the API suite against throwaway stores.

The API tests share one imported ``backend.app.main`` module whose :class:`Settings`
snapshots environment variables at import time, so these are set here (pytest imports
this file before any test module) and the tests never touch the real
``data/`` store, the live ``trinetra_users.db`` or the production admin account.
"""

import os
import tempfile
from pathlib import Path

_PVT = Path(tempfile.mkdtemp(prefix="trinetra-test-"))
_STORE = _PVT / "trinetra.db"
_RAW = _PVT / "raw"

os.environ.setdefault("TRINETRA_STORE_PATH", str(_STORE))
os.environ.setdefault("TRINETRA_RAW_DIR", str(_RAW))
os.environ.setdefault("TRINETRA_RETENTION_DAYS", "30")
os.environ.setdefault("ADMIN_USER", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "admin")
os.environ.setdefault("TRINETRA_JWT_SECRET", "testonly-jwt-secret")

# AGENT_TOKEN is deliberately left to each test module so the
# "endpoint disabled without a token" behaviour stays testable.