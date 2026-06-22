"""Manual dismissal — operator-driven equivalent of the auto-resolve flow.

Writes an applied Change with strategy='manual_dismiss' for a finding's
fingerprint. The dashboard's resolved_fingerprints() then strips it from
the active view (same mechanism as auto-resolve and as a fully-walked
propose→apply Change), and the audit trail records why the operator chose
to dismiss.

Designed to be called from three places:
  - POST /finding/<id>/dismiss            (single)
  - POST /findings/bulk-dismiss           (many at once)
  - The Verify/Dismiss button on /finding/<id> for intel_match_unverified

Behavior:
  - reason: non-empty string is required. The dismissal Change record
    summary embeds this; an audit reviewer should be able to read the
    summary and understand why this finding was closed without a fix.
  - If a resolved Change already exists for the fingerprint (applied /
    validated / deployed), the helper no-ops and returns False rather
    than writing a duplicate.
  - finding.dismissed event row goes to EventStore so /history shows
    the action with the operator's name and reason.
"""
from __future__ import annotations

import time

from ..core.findings import Finding


_RESOLVED_STATES = {"applied", "validated", "deployed"}


def already_resolved(fingerprint: str, app_name: str) -> bool:
    """True if the latest Change for this (app, fingerprint) is in a resolved
    state. Used to skip re-dismissing findings already closed by an earlier
    Change (auto-resolve, manual remediation, etc.)."""
    from .state import ChangeStore
    latest_state = None
    latest_ts = -1.0
    for c in ChangeStore().all():
        if c.app_name != app_name:
            continue
        if c.finding_fingerprint != fingerprint:
            continue
        if c.last_state_at > latest_ts:
            latest_ts = c.last_state_at
            latest_state = c.state.value
    return latest_state in _RESOLVED_STATES


def dismiss_finding(finding: Finding, *, reason: str, actor: str) -> bool:
    """Create an applied Change marking this finding dismissed.

    Returns True if a new dismissal Change was written, False if the
    finding was already resolved (no-op). Raises ValueError on missing
    reason — dismissal without a recorded justification is a misuse.
    """
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("reason is required for manual dismissal")
    if already_resolved(finding.fingerprint, finding.app_name):
        return False

    # Lazy import — keep the module loadable in CLI-only contexts where
    # the orchestrator never references dismissals.
    from .state import Change, ChangeState, ChangeStore, EventStore, new_change_id

    now = time.time()
    change = Change(
        change_id=new_change_id(),
        finding_id=finding.finding_id,
        finding_fingerprint=finding.fingerprint,
        app_name=finding.app_name,
        tier=finding.tier,
        strategy="manual_dismiss",
        state=ChangeState.APPLIED,
        confidence=1.0,
        summary=(
            f"Manually dismissed by {actor}: {reason[:280]}"
            f"{'…' if len(reason) > 280 else ''}"
        ),
        diff="",
        files=[],
        tests=[],
        test_status="auto",
        test_status_reason="manual dismissal — no scanner re-run required",
        rescan_adapter=finding.adapter,
        proposed_at=now,
        last_state_at=now,
        actor=actor,
        notes=f"reason={reason}",
    )
    ChangeStore().write(change)
    EventStore().append(
        "finding.dismissed",
        change_id=change.change_id,
        finding_id=finding.finding_id,
        finding_fingerprint=finding.fingerprint,
        app_name=finding.app_name,
        adapter=finding.adapter,
        actor=actor,
        reason=reason,
    )
    return True
