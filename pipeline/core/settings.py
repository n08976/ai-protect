"""User-configurable settings — persisted to ~/.ai-protect/config.json.

Single shared instance: there's one operator (DEFAULT_ACTOR) and one site.
If multi-tenant ever lands, this becomes per-account.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, available_timezones

from ..remediate.state import REMEDIATE_HOME

CONFIG_PATH = REMEDIATE_HOME / "config.json"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S %Z"
DEFAULT_TIMEZONE = "UTC"


def load() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text())
    except Exception:
        return {}


def save(cfg: dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2, sort_keys=True))


def get_timezone() -> str:
    return load().get("timezone") or DEFAULT_TIMEZONE


def get_date_format() -> str:
    return load().get("date_format") or DEFAULT_DATE_FORMAT


def set_timezone(tz: str) -> None:
    """Persist a TZ. Raises ValueError if not a real IANA zone."""
    if tz not in available_timezones():
        raise ValueError(f"unknown timezone '{tz}' — pick an IANA name like 'America/New_York'")
    cfg = load()
    cfg["timezone"] = tz
    save(cfg)


def set_date_format(fmt: str) -> None:
    cfg = load()
    cfg["date_format"] = fmt
    save(cfg)


def format_epoch(ts: float | None, fmt: str | None = None, tz: str | None = None) -> str:
    """Render an epoch as a human string in the configured (or supplied) zone.

    Returns '—' for None / 0 / negative — handlers always expect a string,
    so the template can interpolate without conditionals.
    """
    if not ts or ts <= 0:
        return "—"
    use_tz = tz or get_timezone()
    use_fmt = fmt or get_date_format()
    try:
        dt = datetime.fromtimestamp(float(ts), tz=ZoneInfo(use_tz))
    except Exception:
        # Fallback to UTC if the saved tz is somehow invalid.
        dt = datetime.fromtimestamp(float(ts), tz=ZoneInfo("UTC"))
    return dt.strftime(use_fmt)


# Curated dropdown — common zones for the settings form. Operator can also
# type any IANA name in the free-text fallback.
COMMON_TIMEZONES = [
    "UTC",
    "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
    "America/Phoenix", "America/Anchorage", "America/Halifax", "America/Sao_Paulo",
    "Europe/London", "Europe/Dublin", "Europe/Paris", "Europe/Berlin", "Europe/Madrid",
    "Europe/Amsterdam", "Europe/Athens", "Europe/Moscow",
    "Asia/Dubai", "Asia/Kolkata", "Asia/Singapore", "Asia/Shanghai",
    "Asia/Tokyo", "Asia/Seoul", "Asia/Hong_Kong",
    "Australia/Sydney", "Australia/Melbourne", "Pacific/Auckland",
]
