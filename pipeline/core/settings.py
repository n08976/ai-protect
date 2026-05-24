"""User-configurable settings — schema-driven, persisted to ~/.ai-protect/config.json.

Design goals (per the May 2026 'highly configurable' directive):
- One declarative schema (SCHEMA below) generates the /settings form, the
  /docs page anchors, and the typed get/set helpers. Adding a new setting
  means appending one Field — no template edits.
- Progressive disclosure via Field.reveal_when so the form only shows the
  fields that apply to the operator's choices (e.g. select GitHub → reveal
  the GitHub auth fields; choose PAT → reveal the PAT input; choose
  GitHub App → reveal app_id + private_key_path + installation_id).
- Every Field carries inline help text AND a help_anchor pointing at /docs
  so the operator can jump to step-by-step setup ("where do I get a PAT?").
- Backwards-compatible: the timezone / date_format API the rest of the
  codebase already uses continues to work unchanged.
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, available_timezones

from ..remediate.state import REMEDIATE_HOME

CONFIG_PATH = REMEDIATE_HOME / "config.json"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S %Z"
DEFAULT_TIMEZONE = "UTC"


# -------------------------------------------------------------------- schema

@dataclass
class Field:
    key: str
    label: str
    kind: str                                 # text | password | select | number | checkbox | textarea | path
    default: Any = ""
    options: list[str] = field(default_factory=list)
    help: str = ""
    help_anchor: str = ""                     # /docs#anchor — step-by-step setup
    reveal_when: dict[str, list[str]] = field(default_factory=dict)
    free_text_override: bool = False          # allow custom value alongside the select dropdown
    placeholder: str = ""
    secret: bool = False                      # mask in UI; do not log


@dataclass
class Section:
    key: str
    title: str
    description: str
    fields: list[Field]


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


SCHEMA: list[Section] = [
    Section(
        key="locale",
        title="Locale & time",
        description="How dates and times are displayed across the dashboard.",
        fields=[
            Field(
                key="timezone", label="Timezone", kind="select",
                default=DEFAULT_TIMEZONE, options=COMMON_TIMEZONES,
                free_text_override=True,
                help="Any IANA timezone name. The dropdown lists 28 common zones; free-text accepts any of the 600+ IANA names.",
                help_anchor="locale-timezone",
            ),
            Field(
                key="date_format", label="Date format", kind="text",
                default=DEFAULT_DATE_FORMAT,
                help="Python strftime tokens. Default %Y-%m-%d %H:%M:%S %Z. Examples in the docs.",
                help_anchor="locale-date-format",
            ),
        ],
    ),
    Section(
        key="paths",
        title="Paths & storage",
        description="Where ai-protect keeps its persistent data. All paths must be outside /tmp (which is wiped on reboot).",
        fields=[
            Field(
                key="findings_path", label="Findings file",
                kind="path", default=str(REMEDIATE_HOME / "findings.jsonl"),
                help="Append-only JSONL of every finding from every scan. The UI's --findings flag overrides this at launch.",
                help_anchor="paths-findings",
            ),
            Field(
                key="manifests_dir", label="Manifests directory",
                kind="path", default="",
                help="Directory holding app manifests (*.yml). Leave blank to use pipeline/manifests/ relative to the install.",
                help_anchor="paths-manifests",
            ),
            Field(
                key="source_cache_dir", label="Source cache directory",
                kind="path", default=str(REMEDIATE_HOME / "src-cache"),
                help="Persistent clone cache for repos fetched from GitHub/etc. Used when 'Clone strategy' is set to cached.",
                help_anchor="paths-cache",
            ),
        ],
    ),
    Section(
        key="source_providers",
        title="Source providers",
        description="Where ai-protect pulls code from to scan. Each manifest can override this — these are the defaults used when a manifest doesn't specify its own provider.",
        fields=[
            Field(
                key="default_provider", label="Default provider",
                kind="select", default="local", options=["local", "github"],
                reveal_when={"github": [
                    "github_base_url", "github_visibility", "github_auth_method",
                    "github_pat", "github_app_id", "github_app_private_key_path",
                    "github_app_installation_id", "github_clone_strategy",
                    "github_default_ref", "github_clone_depth",
                ]},
                help="local = read manifest.source_paths from the filesystem. github = clone the repo declared on the manifest before each scan.",
                help_anchor="source-default-provider",
            ),
            Field(
                key="github_base_url", label="GitHub base URL",
                kind="text", default="https://github.com",
                placeholder="https://github.com or https://ghes.example.com",
                help="Use https://github.com for the public service or your GHES URL for GitHub Enterprise Server.",
                help_anchor="source-github-base-url",
            ),
            Field(
                key="github_visibility", label="Repo visibility",
                kind="select", default="public", options=["public", "private"],
                reveal_when={"private": ["github_auth_method", "github_pat",
                                          "github_app_id", "github_app_private_key_path",
                                          "github_app_installation_id"]},
                help="Public repos require no auth. Private repos need a PAT or a GitHub App installed on the repo's owner.",
                help_anchor="source-github-visibility",
            ),
            Field(
                key="github_auth_method", label="Authentication method",
                kind="select", default="pat", options=["pat", "github_app", "none"],
                reveal_when={
                    "pat": ["github_pat"],
                    "github_app": ["github_app_id", "github_app_private_key_path", "github_app_installation_id"],
                },
                help="PAT = simple personal access token (good for single-operator setups). GitHub App = installable on an org, fine-grained per-repo permissions, no human token to rotate (recommended for organizations).",
                help_anchor="source-github-auth-method",
            ),
            Field(
                key="github_pat", label="Personal access token",
                kind="password", default="", secret=True,
                placeholder="github_pat_…",
                help="Fine-grained PAT with 'Contents: Read' scope on the repos to scan. See docs for step-by-step creation. Stored in ~/.ai-protect/config.json; ensure chmod 600.",
                help_anchor="source-github-pat",
            ),
            Field(
                key="github_app_id", label="GitHub App ID",
                kind="text", default="",
                placeholder="123456",
                help="Numeric App ID shown on the App's settings page after creation.",
                help_anchor="source-github-app-id",
            ),
            Field(
                key="github_app_private_key_path", label="App private key file",
                kind="path", default="",
                placeholder="/home/user/.ai-protect/github-app.pem",
                help="Absolute path to the PEM private key file downloaded when the App was created. File should be chmod 600.",
                help_anchor="source-github-app-private-key",
            ),
            Field(
                key="github_app_installation_id", label="App installation ID",
                kind="text", default="",
                placeholder="78901234",
                help="The numeric installation id, visible at https://github.com/organizations/<org>/settings/installations after installing the App.",
                help_anchor="source-github-app-installation-id",
            ),
            Field(
                key="github_clone_strategy", label="Clone strategy",
                kind="select", default="per_scan", options=["per_scan", "cached"],
                help="per_scan = shallow clone to a temp dir each time, delete after. cached = clone once into the source cache dir and refresh via 'git fetch' on subsequent scans (faster on the 2nd+ scan).",
                help_anchor="source-github-clone-strategy",
            ),
            Field(
                key="github_default_ref", label="Default ref",
                kind="text", default="main",
                placeholder="main, develop, refs/heads/release-1.2, or a SHA",
                help="Branch, tag, or commit SHA to scan when the manifest doesn't specify one. Most repos: 'main'.",
                help_anchor="source-github-default-ref",
            ),
            Field(
                key="github_clone_depth", label="Clone depth",
                kind="number", default="1",
                help="Number of recent commits to fetch. 1 = shallow (fastest, ideal for SAST). Set 0 to fetch full history (slower; needed only if an adapter needs git blame).",
                help_anchor="source-github-clone-depth",
            ),
        ],
    ),
    Section(
        key="intel",
        title="Intel feeds defaults",
        description="Defaults applied to newly-added intel feeds. Per-feed overrides live on /feeds.",
        fields=[
            Field(
                key="default_poll_seconds", label="Default polling interval (s)",
                kind="number", default="3600",
                help="How often the background poller refetches each feed. Minimum 60s. 3600 (1h) is reasonable for CVE feeds.",
                help_anchor="intel-poll-seconds",
            ),
            Field(
                key="intel_match_min_severity", label="intel_match emission floor",
                kind="select", default="high",
                options=["info", "low", "medium", "high", "critical"],
                help="Below this severity, intel_match drops the finding. KEV-listed matches always emit regardless.",
                help_anchor="intel-match-min-severity",
            ),
            Field(
                key="intel_match_disable_kev_ratchet", label="Disable KEV ratchet",
                kind="checkbox", default="",
                help="If checked, CISA KEV-listed CVEs do NOT bump scanner findings to critical via the enrichment hook. Default: unchecked (ratchet on).",
                help_anchor="intel-kev-ratchet",
            ),
        ],
    ),
]


# -------------------------------------------------------------------- I/O

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
    # Best-effort chmod 600 — the file may carry GitHub PATs / App keys.
    try:
        os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def get(key: str, default: Any = None) -> Any:
    """Look up a key. Falls back to the schema default, then to `default`."""
    cfg = load()
    if key in cfg and cfg[key] != "":
        return cfg[key]
    for section in SCHEMA:
        for fld in section.fields:
            if fld.key == key:
                return fld.default if fld.default not in (None, "") else default
    return default


def set_many(updates: dict[str, Any]) -> dict[str, str]:
    """Apply a batch of {key: value} updates. Returns per-key error map (empty = all ok)."""
    cfg = load()
    errors: dict[str, str] = {}
    # Validate before persisting so a single bad field doesn't half-write.
    for key, raw in updates.items():
        try:
            value = _validate(key, raw)
        except ValueError as e:
            errors[key] = str(e)
            continue
        cfg[key] = value
    if not errors:
        save(cfg)
    return errors


def _validate(key: str, raw: Any) -> Any:
    """Type-check + range-check a single field. Returns the canonical value."""
    fld = _field(key)
    if fld is None:
        # Unknown key — store as-is. Lets us evolve the schema without
        # losing user data on the next migration.
        return raw
    val = str(raw).strip() if isinstance(raw, str) else raw
    if fld.kind == "select" and val and not fld.free_text_override:
        if val not in fld.options:
            raise ValueError(f"must be one of: {', '.join(fld.options)}")
    if fld.kind == "number" and val != "":
        try:
            float(val)
        except (TypeError, ValueError):
            raise ValueError("must be a number")
    if key == "timezone" and val:
        if val not in available_timezones():
            raise ValueError(f"unknown IANA timezone '{val}'")
    if fld.kind == "checkbox":
        val = "on" if val in (True, "on", "true", "1", 1) else ""
    return val


def _field(key: str) -> Field | None:
    for section in SCHEMA:
        for fld in section.fields:
            if fld.key == key:
                return fld
    return None


# ---------------------------------------------------------- backward-compat
# These wrap the schema-driven `get()` so the rest of the codebase
# (server.py, intel_enrichment, fetcher, etc.) keeps working unchanged.

def get_timezone() -> str:
    return get("timezone", DEFAULT_TIMEZONE) or DEFAULT_TIMEZONE


def get_date_format() -> str:
    return get("date_format", DEFAULT_DATE_FORMAT) or DEFAULT_DATE_FORMAT


def set_timezone(tz: str) -> None:
    errs = set_many({"timezone": tz})
    if errs:
        raise ValueError(errs.get("timezone", "invalid timezone"))


def set_date_format(fmt: str) -> None:
    set_many({"date_format": fmt})


def format_epoch(ts: float | None, fmt: str | None = None, tz: str | None = None) -> str:
    """Render an epoch as a human string in the configured zone. '—' for falsy."""
    if not ts or float(ts) <= 0:
        return "—"
    use_tz = tz or get_timezone()
    use_fmt = fmt or get_date_format()
    try:
        dt = datetime.fromtimestamp(float(ts), tz=ZoneInfo(use_tz))
    except Exception:
        dt = datetime.fromtimestamp(float(ts), tz=ZoneInfo("UTC"))
    return dt.strftime(use_fmt)
