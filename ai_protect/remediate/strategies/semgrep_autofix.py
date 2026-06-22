"""semgrep_autofix — apply Semgrep's own rule-authored fix.

Many Semgrep rules ship a ``fix:`` (the autofix Semgrep applies with
``--autofix``). When the semgrep adapter captured one (``evidence.fix`` plus the
match byte-offsets), this strategy applies it the same way Semgrep does: replace
the matched span ``[start_offset, end_offset)`` with the fix text. This makes
*any* Semgrep rule that carries a fix auto-remediable — the broadest single
lever for widening coverage — while staying deterministic (no guessing: we apply
exactly what the rule author wrote) and re-scan-verified.
"""
from __future__ import annotations

from ...core.findings import Category, Finding
from ..base import FileChange, Proposal, Remediator
from .insecure_pattern_fix import _resolve


class SemgrepAutofixRemediator(Remediator):
    name = "semgrep_autofix"
    # Any category — the real gate is can_fix (semgrep finding that carries a fix).
    handles = set(Category)
    description = ("Apply Semgrep's own rule-authored autofix (evidence.fix) at the exact "
                  "match span; re-scan to verify.")

    def can_fix(self, finding: Finding, manifest_raw: dict) -> bool:
        if finding.adapter != "semgrep":
            return False
        ev = finding.evidence or {}
        if not ev.get("fix"):
            return False
        if ev.get("start_offset") is None or ev.get("end_offset") is None:
            return False
        if not ev.get("file"):
            return False
        return _resolve(ev["file"], manifest_raw) is not None

    def propose(self, finding: Finding, manifest_raw: dict) -> Proposal | None:
        ev = finding.evidence or {}
        path = _resolve(ev.get("file", ""), manifest_raw)
        if path is None:
            return None
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        s, e = int(ev["start_offset"]), int(ev["end_offset"])
        if not (0 <= s <= e <= len(raw)):
            return None
        new_raw = raw[:s] + ev["fix"].encode() + raw[e:]
        try:
            new_content = new_raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if new_raw == raw:
            return None

        rule = ev.get("rule_id", "rule")
        return Proposal(
            summary=f"Apply Semgrep autofix for {rule.split('.')[-1]} in {path}",
            confidence=0.8,
            rescan_adapter="semgrep",
            file_changes=[FileChange(path=str(path.resolve()), new_content=new_content)],
            test_plan={"kind": "source_swap", "file": str(path.resolve()),
                       "label": f"semgrep:{rule}"},
            notes=(f"Rule-authored fix from Semgrep ({rule}) applied at the matched span. "
                   "Verified by re-scan."),
        )
