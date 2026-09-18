"""TriNetra — configuration loading.

Resolves config/config.yaml (defaults) overlaid with environment variables.
Kept intentionally small: every knob used by the orchestrator lives here.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config" / "config.yaml"


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Settings:
    def __init__(self, path: Path = CONFIG_PATH) -> None:
        with open(path, "r", encoding="utf-8") as fh:
            raw: Dict[str, Any] = yaml.safe_load(fh) or {}
        raw["paths"]["root"] = str(ROOT)
        for key, value in raw.get("paths", {}).items():
            if isinstance(value, str) and value.startswith("."):
                raw["paths"][key] = str((ROOT / value).resolve())
        self._data = raw
        self._env_overrides()

    def _env_overrides(self) -> None:
        mapping = {
            "TRINETRA_LLM_BACKEND": ("llm", "backend"),
            "ANTHROPIC_API_KEY": ("llm", "anthropic_api_key"),
            "TRINETRA_RAW_DIR": ("paths", "raw_store"),
            "TRINETRA_STORE_PATH": ("paths", "event_store"),
            "TRINETRA_CLIENT_ID": ("agent", "client_id"),
            "AGENT_TOKEN": ("auth", "agent_token"),
            "TRINETRA_RETENTION_DAYS": ("events", "retention_days"),
            "ADMIN_USER": ("auth", "admin_user"),
            "ADMIN_PASSWORD": ("auth", "admin_password"),
            "TRINETRA_JWT_SECRET": ("auth", "jwt_secret"),
            "TRINETRA_GEO_DB_PATH": ("enrichment", "geo", "db_path"),
            "TRINETRA_INTEL_PROVIDER": ("enrichment", "intel", "provider"),
            "ABUSEIPDB_API_KEY": ("enrichment", "intel", "api_key"),
            "VIRUSTOTAL_API_KEY": ("enrichment", "intel", "api_key"),
            "TRINETRA_CORS_ORIGINS": ("web", "cors_origins"),
        }
        for env, path in mapping.items():
            value = os.environ.get(env)
            if value:
                node = self._data
                for part in path[:-1]:
                    node = node.setdefault(part, {})
                node[path[-1]] = value

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def as_dict(self) -> Dict[str, Any]:
        return self._data

    def path(self, key: str) -> Path:
        value = self.get(f"paths.{key}")
        return Path(value)


_DEFAULT: Settings | None = None


def get_settings() -> Settings:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Settings()
    return _DEFAULT