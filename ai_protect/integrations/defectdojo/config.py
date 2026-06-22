"""DefectDojo connection config — resolved from explicit args, env, then UI settings.

Precedence (first non-empty wins):
    1. explicit args (CLI --url/--token)
    2. environment (DEFECTDOJO_URL / DEFECTDOJO_API_TOKEN / DEFECTDOJO_VERIFY_SSL)
    3. UI settings (config.json: defectdojo_url / defectdojo_token / defectdojo_verify_ssl)

Env first means CI injects creds from Vault / Key Vault without touching the
on-disk settings; the UI settings path is the convenience route for a local
operator.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


class DefectDojoConfigError(RuntimeError):
    """Raised when URL/token aren't configured anywhere."""


def _settings_get(key: str, default: str = "") -> str:
    # Imported lazily so the integration has no hard import-time dep on the UI.
    try:
        from ...core import settings
        val = settings.get(key, default)
        return "" if val is None else str(val)
    except Exception:
        return default


@dataclass
class DefectDojoConfig:
    url: str
    token: str
    verify_ssl: bool = True

    @classmethod
    def resolve(cls, url: str | None = None, token: str | None = None) -> "DefectDojoConfig | None":
        """Return a config if fully specified, else None (caller decides if that's an error)."""
        url = (url or os.environ.get("DEFECTDOJO_URL") or _settings_get("defectdojo_url")).rstrip("/")
        token = token or os.environ.get("DEFECTDOJO_API_TOKEN") or _settings_get("defectdojo_token")
        verify = _resolve_verify_ssl()
        if not url or not token:
            return None
        return cls(url=url, token=token, verify_ssl=verify)

    @classmethod
    def from_env(cls, url: str | None = None, token: str | None = None) -> "DefectDojoConfig":
        """Like resolve() but raises DefectDojoConfigError when unconfigured."""
        cfg = cls.resolve(url=url, token=token)
        if cfg is None:
            raise DefectDojoConfigError(
                "DefectDojo is not configured: set DEFECTDOJO_URL and DEFECTDOJO_API_TOKEN "
                "(or pass --url/--token, or configure it under /settings).")
        return cfg


def _resolve_verify_ssl() -> bool:
    env = os.environ.get("DEFECTDOJO_VERIFY_SSL")
    if env is not None:
        return env.lower() not in ("0", "false", "no")
    setting = _settings_get("defectdojo_verify_ssl", "1")
    return str(setting).lower() not in ("0", "false", "no", "off")
