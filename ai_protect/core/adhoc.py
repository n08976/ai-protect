"""Synthetic ephemeral manifest for ad-hoc DAST scans.

When the operator pastes a URL into /scan (DAST mode → Arbitrary URL), the
orchestrator still expects a Manifest. We build one in memory, serialize it
to a temp YAML file at ~/.ai-protect/adhoc-scans/<scan_id>.yml so the
existing scan_runner subprocess can read it like any other manifest, and
delete it after the run completes (try/finally in scan_runner — see
remediate/scan_runner.py).

Hygiene: a defense-in-depth periodic cleanup removes adhoc-scans/*.yml
older than ADHOC_TTL_DAYS so crashed runners don't accumulate cruft.
"""
from __future__ import annotations

import os
import time
import yaml
from pathlib import Path
from urllib.parse import urlparse

from .url_safety import adhoc_app_name
from ..remediate.state import REMEDIATE_HOME


ADHOC_DIR = REMEDIATE_HOME / "adhoc-scans"
ADHOC_TTL_SECONDS = 7 * 86400


def build_adhoc_manifest_dict(
    url: str, *, name_override: str | None = None,
    allow_internal_scan: bool = False, allow_insecure_http: bool = False,
    actor: str = "operator",
) -> dict:
    """Produce a manifest YAML dict for an ad-hoc DAST URL.

    Conservative defaults: data_sensitivity=public, decision_impact=advisory,
    integration_footprint=read_only, user_population=single_user — these
    feed into classify() which will likely yield Tier 4. Plenty of headroom
    if the operator wants to escalate by registering the URL as a real
    manifest later (the /manifests/new form accepts the same shape).

    allow_mutation stays FALSE — ad-hoc URLs can't run active/mutating
    adapters without the operator explicitly typed-confirming and promoting
    to a saved manifest.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    name = name_override or adhoc_app_name(host, port)
    return {
        "name": name,
        "owner": actor,
        "on_call": actor,
        "description": f"Ad-hoc DAST target: {url}",
        "data_sensitivity": "public",
        "decision_impact": "advisory",
        "integration_footprint": "read_only",
        "user_population": "single_user",
        "target": {
            "base_url": url,
            "allow_mutation": False,
            "network_allowed_zones": [],
            **({"allow_insecure_http": True} if allow_insecure_http else {}),
            **({"allow_internal_scan": True} if allow_internal_scan else {}),
        },
        # Source code paths intentionally empty — DAST adapters don't read source.
        "source_paths": [],
        # Mark as adhoc in raw so other code paths can distinguish.
        "_adhoc": True,
        "_adhoc_url": url,
        "_adhoc_created_at": time.time(),
    }


def write_adhoc_manifest(manifest_dict: dict, scan_id: str) -> Path:
    """Serialize a synthetic manifest to ~/.ai-protect/adhoc-scans/<scan_id>.yml.

    The path is what gets passed to scan_runner. Cleanup is the runner's
    responsibility (try/finally), with periodic janitor as backstop.
    """
    ADHOC_DIR.mkdir(parents=True, exist_ok=True)
    path = ADHOC_DIR / f"{scan_id}.yml"
    with path.open("w") as f:
        yaml.safe_dump(manifest_dict, f, sort_keys=False)
    # The file may carry inferred target context; chmod 600 so it doesn't
    # leak through a multi-user system.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def cleanup_stale_adhoc_manifests(ttl_seconds: int = ADHOC_TTL_SECONDS) -> int:
    """Delete adhoc manifests older than ttl_seconds. Returns count removed.

    Called periodically (e.g. on /scan GET) so a crashed scan_runner that
    skipped its own cleanup doesn't accumulate cruft. Best-effort; errors
    are silently ignored — this is hygiene, not a hard requirement.
    """
    if not ADHOC_DIR.is_dir():
        return 0
    cutoff = time.time() - ttl_seconds
    removed = 0
    for p in ADHOC_DIR.glob("*.yml"):
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def cleanup_one(scan_id: str) -> bool:
    """End-of-run delete for one scan's temp manifest. Returns True on success."""
    p = ADHOC_DIR / f"{scan_id}.yml"
    try:
        p.unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False
