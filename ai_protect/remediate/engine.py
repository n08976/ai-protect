"""Engine — orchestrates the full lifecycle.

Public API (used by the UI):
    propose(finding)               -> Change                    (state PROPOSED → TESTS_GENERATED|NO_TEST_POSSIBLE)
    approve(change_id, actor)      -> Change                    (state APPROVED)
    reject(change_id, actor, why)  -> Change                    (state REJECTED)
    apply(change_id, actor)        -> Change                    (state APPLIED — backups + write + post-apply tests)
    rollback(change_id, actor)     -> Change                    (state REVERTED — restore backups)
    rescan(change_id, actor)       -> (Change, run_summary)     (state VALIDATED or stays APPLIED)
    deploy(change_id, actor)       -> Change                    (state DEPLOYED)

Every transition appends to events.jsonl. Every change snapshot appends to
changes.jsonl. Backups under ~/.ai-protect/backups/<change_id>/.

The state machine is enforced — invalid transitions raise ValueError.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..adapters.registry import get_adapter_class
from ..core.findings import Finding, FindingStore, Severity
from ..core.manifest import Manifest
from ..core.tiering import classify
from .backup import backup_file, restore_change, sha256_file, write_change_manifest
from .base import Proposal
from .registry import remediators_for
from .state import (
    ALLOWED,
    Change,
    ChangeState,
    ChangeStore,
    EventStore,
    FileEdit,
    TestRecord,
    new_change_id,
)
from .test_authoring import author_tests
from .test_runner import run_tests


class EngineError(Exception):
    pass


class Engine:
    def __init__(self, manifest: Manifest, finding_store: FindingStore,
                 change_store: ChangeStore | None = None,
                 event_store: EventStore | None = None):
        self.manifest = manifest
        self.findings = finding_store
        self.changes = change_store or ChangeStore()
        self.events = event_store or EventStore()
        self.tier = classify(manifest).tier

    # ---------- helpers ----------

    def _transition(self, change: Change, target: ChangeState, *, actor: str = "auto", **payload):
        if target not in ALLOWED.get(change.state, set()):
            raise EngineError(f"Invalid transition {change.state} -> {target} for change {change.change_id}")
        prev = change.state.value
        change.state = target
        change.actor = actor
        self.events.append(
            f"change.{target.value}",
            change_id=change.change_id, finding_id=change.finding_id,
            from_state=prev, to_state=target.value, actor=actor, **payload,
        )
        self.changes.write(change)
        return change

    def _find_finding(self, finding_id: str) -> Finding:
        for f in self.findings.all():
            if f.finding_id == finding_id:
                return f
        raise EngineError(f"Finding {finding_id!r} not found")

    # ---------- propose ----------

    def propose(self, finding_id: str, actor: str = "auto") -> Change:
        finding = self._find_finding(finding_id)
        rs = remediators_for(finding, self.manifest.raw)
        if not rs:
            raise EngineError(f"No remediator handles category={finding.category.value}, adapter={finding.adapter}")
        # Phase 1: pick the first applicable strategy.
        remediator = rs[0]
        proposal: Proposal | None = remediator.propose(finding, self.manifest.raw)
        if proposal is None:
            raise EngineError(f"{remediator.name}: no fix applicable for {finding_id}")

        change = Change(
            change_id=new_change_id(),
            finding_id=finding.finding_id,
            finding_fingerprint=finding.fingerprint,
            app_name=finding.app_name,
            tier=self.tier,
            strategy=remediator.name,
            state=ChangeState.PROPOSED,
            confidence=proposal.confidence,
            summary=proposal.summary,
            diff=proposal.unified_diff(),
            files=[FileEdit(path=fc.path, created=fc.create) for fc in proposal.file_changes],
            rescan_adapter=proposal.rescan_adapter,
            actor=actor,
            notes=proposal.notes,
        )
        self.events.append(
            "change.proposed", change_id=change.change_id, finding_id=finding.finding_id,
            strategy=remediator.name, confidence=proposal.confidence, actor=actor,
        )
        self.changes.write(change)

        # Author tests, then transition state.
        plan = proposal.test_plan
        try:
            authored = author_tests(change.change_id, plan)
        except Exception as e:
            authored = []
            change.test_status_reason = f"author error: {e}"

        # Stash plan/changes for later phases (apply needs the new_content)
        change.notes = (change.notes or "") + "\n\n_proposal_blob_:\n" + proposal.unified_diff()
        # We need the actual file content for apply. Stash on change as a separate
        # JSON-friendly attribute via an internal note key.
        change._proposal_files = [
            {"path": fc.path, "new_content": fc.new_content, "create": fc.create}
            for fc in proposal.file_changes
        ]
        # Persist the proposal blob in a sibling file (not in jsonl row, too big).
        from .state import REMEDIATE_HOME
        blob_path = REMEDIATE_HOME / "blobs" / f"{change.change_id}.json"
        blob_path.parent.mkdir(parents=True, exist_ok=True)
        import json as _json
        blob_path.write_text(_json.dumps(change._proposal_files))

        if not authored:
            change.test_status = "not_generatable"
            change.test_status_reason = (
                change.test_status_reason
                or "No test author registered for this proposal kind."
            )
            self.events.append(
                "change.no_test_possible", change_id=change.change_id,
                reason=change.test_status_reason, actor=actor,
            )
            return self._transition(change, ChangeState.NO_TEST_POSSIBLE, actor=actor)

        for name, path, source in authored:
            Path(path).write_text(source)
            change.tests.append(TestRecord(name=name, path=path))

        # Run pre-apply — should FAIL (bug present).
        results = run_tests([t.path for t in change.tests])
        for t, r in zip(change.tests, results):
            t.pre_apply_passed = r.passed
        change.test_status = "generated"
        self.events.append(
            "change.tests_generated", change_id=change.change_id,
            test_count=len(change.tests),
            pre_apply_passed=[t.pre_apply_passed for t in change.tests],
            actor=actor,
        )
        return self._transition(change, ChangeState.TESTS_GENERATED, actor=actor)

    # ---------- approve / reject ----------

    def approve(self, change_id: str, actor: str) -> Change:
        change = self._require(change_id)
        return self._transition(change, ChangeState.APPROVED, actor=actor)

    def reject(self, change_id: str, actor: str, reason: str = "") -> Change:
        change = self._require(change_id)
        return self._transition(change, ChangeState.REJECTED, actor=actor, reason=reason)

    # ---------- apply ----------

    def apply(self, change_id: str, actor: str) -> Change:
        change = self._require(change_id)
        if change.state != ChangeState.APPROVED:
            raise EngineError(f"Cannot apply from state {change.state.value}; approve first.")
        # Tier guard: high-tier never auto-applies; this requires explicit human actor.
        if self.tier <= 2 and actor == "auto":
            raise EngineError(f"Tier {self.tier} requires human actor for apply.")

        # Load the proposal blob.
        from .state import REMEDIATE_HOME
        import json as _json
        blob = _json.loads((REMEDIATE_HOME / "blobs" / f"{change.change_id}.json").read_text())

        # Backup → write → record sha_after.
        new_files: list[FileEdit] = []
        for entry in blob:
            fe = backup_file(change.change_id, entry["path"])
            target = Path(entry["path"])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(entry["new_content"])
            fe.sha_after = sha256_file(target)
            new_files.append(fe)
        change.files = new_files
        write_change_manifest(change)

        # Re-run generated tests post-apply (expect PASS).
        if change.tests:
            results = run_tests([t.path for t in change.tests])
            for t, r in zip(change.tests, results):
                t.post_apply_passed = r.passed
            change.test_status = "passed" if all(t.post_apply_passed for t in change.tests) else "failed"

        self.events.append(
            "change.applied", change_id=change.change_id,
            files=[fe.path for fe in change.files],
            backup_dir=str(REMEDIATE_HOME / "backups" / change.change_id),
            test_status=change.test_status, actor=actor,
        )
        return self._transition(change, ChangeState.APPLIED, actor=actor)

    # ---------- rollback ----------

    def rollback(self, change_id: str, actor: str) -> Change:
        change = self._require(change_id)
        if change.state not in (ChangeState.APPLIED, ChangeState.VALIDATED, ChangeState.DEPLOYED):
            raise EngineError(f"Cannot rollback from state {change.state.value}")
        actions = restore_change(change)
        self.events.append(
            "change.reverted", change_id=change.change_id,
            actions=actions, actor=actor,
        )
        return self._transition(change, ChangeState.REVERTED, actor=actor)

    # ---------- rescan ----------

    def rescan(self, change_id: str, actor: str) -> tuple[Change, dict]:
        change = self._require(change_id)
        if change.state not in (ChangeState.APPLIED,):
            raise EngineError(f"Rescan requires APPLIED state; was {change.state.value}")
        adapter_name = change.rescan_adapter
        AdapterCls = get_adapter_class(adapter_name)
        adapter = AdapterCls(self.manifest, stage="build", config={})

        # Snapshot pre-rescan fingerprints for this app
        before = {f.fingerprint for f in self.findings.by_app(change.app_name)}

        self.events.append(
            "scan.started", change_id=change.change_id, app=change.app_name,
            scope=adapter_name, actor=actor, kind="rescan",
        )
        try:
            new_findings = adapter.run()
        except Exception as e:
            self.events.append(
                "scan.error", change_id=change.change_id, scope=adapter_name,
                error=str(e), actor=actor,
            )
            return change, {"error": str(e)}

        if new_findings:
            self.findings.append_many(new_findings)

        # A fix is verified when the FRESH re-scan no longer re-emits the
        # finding. (Comparing against the accumulated append-only store would
        # always still contain the original row, so it could never clear.)
        re_emitted = {f.fingerprint for f in new_findings}
        cleared = change.finding_fingerprint not in re_emitted
        new_high = sum(
            1 for f in new_findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL)
            and f.fingerprint not in before
        )
        summary = {
            "adapter": adapter_name,
            "new_findings": len(new_findings),
            "new_high_or_above": new_high,
            "original_cleared": cleared,
        }
        self.events.append(
            "scan.completed", change_id=change.change_id, scope=adapter_name,
            actor=actor, **summary,
        )
        if cleared and new_high == 0:
            self._transition(change, ChangeState.VALIDATED, actor=actor, summary=summary)
        return change, summary

    def deploy(self, change_id: str, actor: str) -> Change:
        change = self._require(change_id)
        return self._transition(change, ChangeState.DEPLOYED, actor=actor)

    # ---------- support ----------

    def _require(self, change_id: str) -> Change:
        c = self.changes.get(change_id)
        if not c:
            raise EngineError(f"Change {change_id!r} not found")
        return c
