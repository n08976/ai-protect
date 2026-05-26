"""Helpers for the UI manifest CRUD: load, validate, serialize.

Kept separate from server.py so it's easy to test in isolation and so the
serialization rules (YAML key order, header comment, etc.) have one home.
"""
from __future__ import annotations

import os
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

from ..core.manifest import Manifest
from ..core.tiering import classify


# Manifest names allow mixed case ([A-Za-z]) — operators reasonably want to
# write "Example-Commercial" instead of "example-commercial". The
# case-fold uniqueness check in validate_for_save() prevents file-system
# collisions on case-insensitive filesystems (macOS HFS+ / Windows NTFS).
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,63}$")

# Sandbox for /api/browse — anything outside these roots is invisible.
# Aligned with the user's stated scan targets (ExampleAdsApp, /opt/app)
# plus standard project areas. Adding a path here makes it browseable.
BROWSE_ROOTS = [
    os.path.expanduser("~"),
    "/opt/app",
    "/opt/mcp",
    "/opt/example",
    "/home/user/ai-protect",
]


# Allow-listed enum values — match pipeline/core/manifest.py + tiering.py.
# "all" is a meta-option: the app has multiple of these characteristics; tier
# conservatively at the most-restrictive value (handled in pipeline/core/tiering.py).
# Useful when an app handles both PHI and PII, or takes both irreversible and
# automated actions, etc. The most-restrictive value wins for classification
# anyway; "all" just lets the operator state that explicitly on the manifest.
DATA_SENSITIVITY_OPTIONS = ["all", "phi", "pii", "financial", "confidential", "public"]
DECISION_IMPACT_OPTIONS = ["all", "irreversible", "clinical_influence", "automated_action", "advisory"]
INTEGRATION_OPTIONS = ["all", "external_action", "agent_tool_use", "write_back", "read_only"]
USER_POPULATION_OPTIONS = ["all", "external", "enterprise", "team", "single_user"]
SIDE_EFFECTS_OPTIONS = ["read_only", "mutating", "irreversible"]


def manifests_dir() -> Path:
    """Resolved at call time so tests can override via env."""
    return Path(os.environ.get("AI_PROTECT_MANIFESTS_DIR",
                               "/home/user/ai-protect/pipeline/manifests"))


def path_for(name: str) -> Path:
    """Resolved path for a manifest by name. Refuses path traversal."""
    if not NAME_RE.match(name):
        raise ValueError(f"invalid manifest name {name!r} (must match {NAME_RE.pattern})")
    p = manifests_dir() / f"{name}.yml"
    # Defense in depth — resolve and confirm still inside the manifests dir.
    resolved = p.resolve()
    if manifests_dir().resolve() not in resolved.parents:
        raise ValueError(f"path traversal attempt: {p}")
    return p


def list_existing_names() -> list[str]:
    md = manifests_dir()
    if not md.is_dir():
        return []
    return sorted(p.stem for p in md.glob("*.yml"))


def load_raw(name: str) -> dict:
    """Read the raw YAML dict (for the edit form). Does NOT instantiate
    the Manifest dataclass — we want to preserve unknown keys verbatim.

    Tries `name.yml` directly first. If that misses, falls back to scanning
    the manifests dir for a file whose internal `name:` field matches —
    handles the case where the manifest's YAML `name` uses dashes
    (e.g. example-commercial) but the filename uses underscores
    (example_commercial.yml). Without the fallback, /manifests' edit links
    404 because they're built from the YAML name.
    """
    p = path_for(name)
    if p.is_file():
        with p.open() as f:
            return yaml.safe_load(f) or {}
    # Fallback — scan for a file whose `name:` field equals the requested name.
    md = manifests_dir()
    if md.is_dir():
        for cand in md.glob("*.yml"):
            try:
                with cand.open() as f:
                    data = yaml.safe_load(f) or {}
            except Exception:
                continue
            if isinstance(data, dict) and data.get("name") == name:
                return data
    raise FileNotFoundError(f"manifest {name!r} not found at {p}")


def save(name: str, data: dict, *, overwrite: bool = True) -> Path:
    """Serialize `data` to YAML at the manifest path. Validates first.

    Underscore-prefixed keys (e.g. _original_name, used by the case-fold
    uniqueness check in validate_for_save to skip self-collisions on
    edit-in-place) are private — they reach the validator but are stripped
    before YAML serialization."""
    p = path_for(name)
    if p.exists() and not overwrite:
        raise FileExistsError(f"manifest {name!r} already exists at {p}")

    errors = validate_for_save(data)
    if errors:
        raise ValueError("validation errors:\n  " + "\n  ".join(errors))

    p.parent.mkdir(parents=True, exist_ok=True)
    on_disk = {k: v for k, v in data.items() if not k.startswith("_")}
    p.write_text(_render_yaml(on_disk))
    return p


def delete(name: str) -> Path:
    p = path_for(name)
    if not p.is_file():
        # Same dashes-vs-underscores fallback as load_raw — when the YAML name
        # differs from its filename, look up by the internal `name:` field.
        md = manifests_dir()
        if md.is_dir():
            for cand in md.glob("*.yml"):
                try:
                    with cand.open() as f:
                        data = yaml.safe_load(f) or {}
                except Exception:
                    continue
                if isinstance(data, dict) and data.get("name") == name:
                    p = cand
                    break
        if not p.is_file():
            raise FileNotFoundError(f"manifest {name!r} not found at {p}")
    p.unlink()
    return p


def validate_for_save(data: dict) -> list[str]:
    """Validate user-submitted form data before writing to disk. Returns
    a list of human-readable error messages (empty list = valid)."""
    errs: list[str] = []
    required = ["name", "owner", "data_sensitivity", "decision_impact",
                "integration_footprint", "user_population"]
    for k in required:
        if not data.get(k):
            errs.append(f"missing required field: {k}")

    name = data.get("name", "")
    if name and not NAME_RE.match(name):
        errs.append(f"name must match {NAME_RE.pattern} "
                    "(letters / digits / dashes / underscores; starts with a letter)")
    # Case-fold uniqueness — refuse only when a DIFFERENT existing manifest
    # casefolds to the same name (e.g. trying to save "MyApp" while "myapp"
    # already exists; on macOS HFS+ / Windows NTFS they'd resolve to the
    # same file). An exact-name match is a normal save/overwrite — that
    # concern is handled by the overwrite= flag in save().
    if name:
        original = data.get("_original_name") or ""
        for existing in list_existing_names():
            if existing == name or existing == original:
                continue   # same file — not a collision
            if existing.lower() == name.lower():
                errs.append(
                    f"manifest name {name!r} would collide on a "
                    f"case-insensitive filesystem with the existing "
                    f"manifest {existing!r}. Pick a name that differs by "
                    f"more than just case."
                )
                break

    for f, opts in (("data_sensitivity", DATA_SENSITIVITY_OPTIONS),
                    ("decision_impact",  DECISION_IMPACT_OPTIONS),
                    ("integration_footprint", INTEGRATION_OPTIONS),
                    ("user_population", USER_POPULATION_OPTIONS)):
        v = data.get(f)
        if v and v not in opts:
            errs.append(f"{f}={v!r} not in {opts}")

    # source_paths must be a list of strings — warn if any look suspect.
    sp = data.get("source_paths") or []
    if not isinstance(sp, list):
        errs.append("source_paths must be a list")
    else:
        for i, entry in enumerate(sp):
            if not isinstance(entry, str) or not entry.strip():
                errs.append(f"source_paths[{i}] must be a non-empty string")

    se = data.get("source_excludes") or []
    if not isinstance(se, list):
        errs.append("source_excludes must be a list")

    # Use the Manifest schema validator as a final pass — catches PHI-without-BAA etc.
    try:
        m = Manifest.from_dict(data)
        for e in m.validate():
            errs.append(f"manifest policy: {e}")
    except (KeyError, TypeError) as e:
        errs.append(f"manifest schema rejected: {e}")

    return errs


def validate_path_warnings(data: dict) -> list[str]:
    """Soft warnings (non-blocking) about path existence. Surfaced in the UI
    so an operator can deliberately save a manifest before the path exists."""
    warns: list[str] = []
    for p in data.get("source_paths") or []:
        if isinstance(p, str):
            expanded = os.path.expanduser(p)
            if not os.path.exists(expanded):
                warns.append(f"source_paths entry does not exist: {p}")
    legacy = data.get("source_path")
    if legacy and isinstance(legacy, str) and not os.path.exists(os.path.expanduser(legacy)):
        warns.append(f"source_path does not exist: {legacy}")
    return warns


# ---- YAML rendering ----------------------------------------------------------

# Canonical key order matches the example manifests so diffs stay clean.
KEY_ORDER = [
    "name", "owner", "on_call", "description",
    "data_sensitivity", "decision_impact", "integration_footprint", "user_population",
    "models", "mcp_servers",
    "surfaces",
    "target",
    "expected_actions", "expected_data_scopes",
    "step_up_auth",
    "threat_model_path",
    "source_path",        # legacy single
    "source_paths",
    "source_excludes",
    "app_aliases",
]


def _ordered(d: dict) -> dict:
    """Reorder top-level keys to KEY_ORDER; append leftovers at the end."""
    out: dict = {}
    for k in KEY_ORDER:
        if k in d and d[k] not in (None, "", [], {}):
            out[k] = d[k]
    for k, v in d.items():
        if k not in out and v not in (None, "", [], {}):
            out[k] = v
    return out


def _render_yaml(data: dict) -> str:
    """Render with a header comment + stable formatting."""
    ordered = _ordered(data)
    body = yaml.safe_dump(
        ordered,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=100,
    )
    header = (
        "# Generated by the ai-protect UI manifest editor.\n"
        "# Edit through /manifests/<name>/edit or update YAML directly — "
        "either is fine.\n\n"
    )
    return header + body


# ---- /api/browse sandbox -----------------------------------------------------

def browse_listing(path: str) -> dict:
    """List directories under `path`. Sandboxed to BROWSE_ROOTS — paths
    outside the allow-list return an error.

    Returns: {root, path, parent, dirs:[{name, path}], can_use: bool}
    can_use indicates whether `path` is a directory the operator can pick
    as a scan target (everything inside a BROWSE_ROOT qualifies).
    """
    target = Path(os.path.expanduser(path or "~")).resolve()
    in_root = any(_is_within(target, Path(r).resolve()) for r in BROWSE_ROOTS)
    if not in_root:
        # Resolve to nearest allow-list root rather than 403'ing.
        target = Path(os.path.expanduser("~")).resolve()
    if not target.is_dir():
        return {
            "root": str(target),
            "path": str(target),
            "parent": str(target.parent) if str(target.parent) != str(target) else None,
            "dirs": [],
            "can_use": False,
            "error": f"not a directory: {target}",
        }

    try:
        entries = sorted(
            (p for p in target.iterdir() if p.is_dir() and not p.name.startswith(".")),
            key=lambda p: p.name.lower(),
        )
    except PermissionError:
        return {
            "root": str(target),
            "path": str(target),
            "parent": None,
            "dirs": [],
            "can_use": False,
            "error": "permission denied",
        }

    return {
        "path": str(target),
        "parent": str(target.parent) if any(
            _is_within(target.parent, Path(r).resolve()) or Path(r).resolve() == target.parent
            for r in BROWSE_ROOTS
        ) else None,
        "roots": [str(Path(r).resolve()) for r in BROWSE_ROOTS if Path(r).is_dir()],
        "dirs": [{"name": p.name, "path": str(p)} for p in entries],
        "can_use": True,
    }


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False
