"""Dashboard view helpers — shared between the UI server and the scan runner.

The FindingStore is append-only; the dashboard wants the "current state" view:
    - dedupe by fingerprint (keep latest per fingerprint by detected_at)
    - drop fingerprints resolved by an applied/validated/deployed Change
    - honor manifest app_aliases — re-key resolved Changes from aliased
      predecessor app names onto the current app's fingerprint namespace

Both the Flask UI (for rendering) and the subprocess scan_runner (for
reporting before/after deltas) need the same numbers. Keeping the logic
here so they can't drift.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .findings import Finding, FindingStore
from .manifest import Manifest


# Change states that mean "the underlying finding is resolved" — these
# fingerprints should NOT count toward the dashboard total.
RESOLVED_STATES = {"applied", "validated", "deployed"}


def manifests_dir() -> Path:
    """Resolved at call time so tests/UI can override via env."""
    return Path(os.environ.get(
        "AI_PROTECT_MANIFESTS_DIR",
        "/home/user/ai-protect/pipeline/manifests",
    ))


def alias_map(manifests_dir_path: Path | None = None) -> dict[str, list[str]]:
    """Reverse alias map: predecessor_app_name → [list of apps that inherit it]."""
    md = manifests_dir_path or manifests_dir()
    out: dict[str, list[str]] = {}
    if not md.is_dir():
        return out
    for p in md.glob("*.yml"):
        try:
            m = Manifest.from_yaml(p)
        except Exception:
            continue
        for alias in (m.app_aliases or []):
            out.setdefault(alias, []).append(m.name)
    return out


def resolved_fingerprints(
    store: FindingStore | None = None,
    manifests_dir_path: Path | None = None,
) -> set[str]:
    """Fingerprints currently resolved by an applied/validated/deployed Change.

    Honors revert: latest Change state per (app, fingerprint) wins.

    Honors app_aliases: re-keys resolved Changes from aliased predecessors
    onto the inheriting app's fingerprint namespace. The mechanics here are
    counter-intuitive — the previous implementation had the lookup direction
    reversed and silently matched nothing (see commit log for the May 2026
    example-ads renaming case that exposed this).

    Correct direction: iterate CURRENT findings. For each, recompute what
    its fingerprint would have been under each declared predecessor; if that
    predecessor-keyed fingerprint matches a resolved Change, the current
    finding (under its new name) is also resolved.
    """
    # Lazy import to avoid the core depending on remediate at module load.
    from ..remediate.state import ChangeStore

    latest_by_app_fp: dict[tuple[str, str], str] = {}
    for c in sorted(ChangeStore().all(), key=lambda c: c.last_state_at):
        if not c.finding_fingerprint:
            continue
        latest_by_app_fp[(c.app_name, c.finding_fingerprint)] = c.state.value

    # Direct resolutions — fingerprint matches an active resolved Change
    # under the SAME app_name. Works without any alias inheritance.
    resolved: set[str] = {
        fp for (_, fp), st in latest_by_app_fp.items()
        if st in RESOLVED_STATES
    }

    aliases = alias_map(manifests_dir_path)  # {predecessor_name: [inheritors]}
    if not aliases or store is None:
        return resolved

    # Inverse map: inheritor_name → [predecessor_names]. We walk CURRENT
    # findings and check the predecessors of each finding's app_name.
    inheritors_to_predecessors: dict[str, list[str]] = {}
    for predecessor, inheritors in aliases.items():
        for inh in inheritors:
            inheritors_to_predecessors.setdefault(inh, []).append(predecessor)

    if not inheritors_to_predecessors:
        return resolved

    for f in store.all():
        if f.fingerprint in resolved:
            continue   # already resolved via direct match
        predecessors = inheritors_to_predecessors.get(f.app_name) or []
        for predecessor in predecessors:
            # What would f's fingerprint have been when this app was named
            # `predecessor`? If a resolved Change exists for that
            # (predecessor, recomputed_fp) pair, the current finding inherits.
            old_key = f"{predecessor}|{f.adapter}|{f.category.value}|{f.title}"
            old_fp = hashlib.sha256(old_key.encode()).hexdigest()[:16]
            if latest_by_app_fp.get((predecessor, old_fp)) in RESOLVED_STATES:
                resolved.add(f.fingerprint)
                break

    return resolved


def active_findings(
    store: FindingStore,
    manifests_dir_path: Path | None = None,
) -> list[Finding]:
    """The deduped, resolved-filtered view of findings for the dashboard.

    Dedup: latest Finding per fingerprint (by detected_at).
    Strip: anything in resolved_fingerprints().
    """
    resolved = resolved_fingerprints(store=store, manifests_dir_path=manifests_dir_path)
    latest: dict[str, Finding] = {}
    for f in sorted(store.all(), key=lambda x: x.detected_at):
        latest[f.fingerprint] = f
    return [f for f in latest.values() if f.fingerprint not in resolved]


def active_count_for_app(
    store: FindingStore,
    app_name: str,
    manifests_dir_path: Path | None = None,
) -> int:
    """Count of active findings for a specific app — what scan_runner reports."""
    return sum(1 for f in active_findings(store, manifests_dir_path) if f.app_name == app_name)
