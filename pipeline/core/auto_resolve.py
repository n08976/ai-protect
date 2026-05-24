"""Auto-resolve findings that the scanner no longer reproduces.

Principle: the scanner is ground truth. If a previous scan emitted a
fingerprint and the current scan (same adapter, same app, same stage)
no longer emits it, the underlying vulnerability is either fixed or gone
from scope. Mark it resolved automatically — manual marking defeats the
point of automation.

Gates (each one prevents a class of bug, not just a nicety):
  - Adapter scope: only adapters with status='ok' in this scan can
    auto-resolve their own fingerprints. An adapter that was 'unavailable'
    (tool not installed) or 'error' didn't actually look, so absence is
    not evidence.
  - Stage scope: a build-stage scan can't auto-resolve preprod findings;
    we can only speak to what THIS run covered.
  - Honor revert: if the operator manually reverted a Change for a
    fingerprint, treat that as 'no, leave this open' — don't keep
    auto-resolving on every subsequent scan.
  - Skip already-resolved: if a fingerprint's latest Change is already
    in {applied, validated, deployed}, no new Change needed.
  - Settings toggle: `auto_resolve_on_rescan` (default 'on') lets the
    operator disable globally if it ever misbehaves.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable

from .findings import Finding, FindingStore
from . import settings as user_settings


# State strings that count as "already resolved" — must match the
# RESOLVED_STATES set in core/dashboard.py. Hardcoded here (rather than
# imported) to avoid the orchestrator pulling in dashboard at run time.
_RESOLVED_STATES = {"applied", "validated", "deployed"}
_REVERTED_STATE = "reverted"


@dataclass
class AutoResolution:
    """One auto-resolved fingerprint, with enough context to write the
    Change record and emit the EventStore event."""
    fingerprint: str
    finding_id: str
    app_name: str
    tier: int
    adapter: str            # the adapter that previously emitted this and didn't this run
    stage: str              # the stage of the scan that triggered the resolution
    title: str              # for human-readable Change.summary


def compute_and_apply(
    store: FindingStore,
    manifest_name: str,
    tier: int,
    stage: str,
    ran_adapters: set[str],
    emitted_fingerprints: set[str],
    scan_id: str,
    actor: str = "auto-resolve",
) -> list[AutoResolution]:
    """Detect + persist auto-resolutions for the just-completed scan.

    Returns the list of resolutions applied. Side effects: appends to
    ChangeStore and EventStore. Caller (orchestrator) is responsible for
    deciding *whether* to call this (gate_passed, materialization ok,
    etc.) — once called, we make a best-effort attempt.
    """
    if not user_settings.get("auto_resolve_on_rescan", "on") == "on":
        return []
    if not ran_adapters:
        return []

    # Lazy import — keep the core module loadable in CLI-only contexts.
    from ..remediate.state import ChangeStore, EventStore, Change, ChangeState, new_change_id

    # 1. Pre-active fingerprints: latest Finding per fingerprint in the store,
    #    scoped to this app + stage + adapters that successfully ran.
    pre_finding_by_fp: dict[str, Finding] = {}
    for f in sorted(store.all(), key=lambda x: x.detected_at):
        if f.app_name != manifest_name:
            continue
        if f.stage != stage:
            continue
        if f.adapter not in ran_adapters:
            continue
        pre_finding_by_fp[f.fingerprint] = f

    # 2. Candidates: pre-active fingerprints NOT emitted this scan.
    absent = set(pre_finding_by_fp) - emitted_fingerprints
    if not absent:
        return []

    # 3. Filter out fingerprints whose latest Change is already in a
    #    resolved or reverted state. Sort by last_state_at so the latest wins.
    change_store = ChangeStore()
    latest_state_by_fp: dict[str, str] = {}
    for c in sorted(change_store.all(), key=lambda c: c.last_state_at):
        if c.app_name != manifest_name:
            continue
        if not c.finding_fingerprint:
            continue
        latest_state_by_fp[c.finding_fingerprint] = c.state.value

    apply_targets: list[AutoResolution] = []
    for fp in absent:
        latest = latest_state_by_fp.get(fp)
        if latest in _RESOLVED_STATES:
            continue   # already resolved by a real Change
        if latest == _REVERTED_STATE:
            continue   # operator explicitly rejected a prior resolution
        f = pre_finding_by_fp[fp]
        apply_targets.append(AutoResolution(
            fingerprint=fp,
            finding_id=f.finding_id,
            app_name=f.app_name,
            tier=f.tier,
            adapter=f.adapter,
            stage=stage,
            title=f.title,
        ))

    # 4. Apply: one Change record per target, plus an EventStore row so the
    #    /history page shows the auto-resolution batch.
    events = EventStore()
    for r in apply_targets:
        now = time.time()
        change = Change(
            change_id=new_change_id(),
            finding_id=r.finding_id,
            finding_fingerprint=r.fingerprint,
            app_name=r.app_name,
            tier=r.tier,
            strategy="auto_resolve_absent",
            state=ChangeState.APPLIED,
            confidence=1.0,
            summary=(
                f"Auto-resolved: adapter '{r.adapter}' did not re-emit fingerprint "
                f"{r.fingerprint} on the {r.stage}-stage scan ({scan_id}). "
                f"Original title: {r.title[:120]}"
            ),
            diff="",
            files=[],
            tests=[],
            test_status="auto",
            test_status_reason=f"scanner did not re-emit on scan {scan_id}",
            rescan_adapter=r.adapter,
            proposed_at=now,
            last_state_at=now,
            actor=actor,
            notes=f"scan_id={scan_id} stage={r.stage} adapter={r.adapter}",
        )
        change_store.write(change)
        events.append(
            "scan.auto_resolved",
            scan_id=scan_id,
            app_name=r.app_name,
            adapter=r.adapter,
            stage=r.stage,
            fingerprint=r.fingerprint,
            change_id=change.change_id,
            actor=actor,
        )

    return apply_targets
