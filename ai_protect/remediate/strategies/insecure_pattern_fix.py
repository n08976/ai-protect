"""insecure_pattern_fix — deterministic, drop-in-safe swaps for known-insecure
Python calls flagged by bandit / semgrep.

Only a small, curated set of replacements that are genuinely behaviour-preserving
for the safe path and surgically scoped to the *exact flagged line* (so we never
rewrite an unrelated occurrence):

  - ``yaml.load(...)``  → ``yaml.safe_load(...)``   (only when no explicit Loader= ; bandit B506)
  - ``verify=False``    → ``verify=True``           (requests/TLS verification ; bandit B501)

The re-scan (bandit/semgrep) is the verifier: if it can't confirm the pattern is
gone, ``cli remediate`` reverts the change. Anything outside this curated set is
left to a human (no_fix), by design — we don't guess at risky source edits.
"""
from __future__ import annotations

from pathlib import Path

from ...core.findings import Category, Finding
from ..base import FileChange, Proposal, Remediator


# Each swap: literal find → replace, an optional guard on the line, a label.
# All are behaviour-preserving for the secure path and surgically scoped to the
# flagged line. Order matters: the explicit-Loader swaps run before the bare
# yaml.load swap so `yaml.load(s, Loader=yaml.Loader)` becomes SafeLoader.
SAFE_SWAPS = [
    {"find": "Loader=yaml.UnsafeLoader", "replace": "Loader=yaml.SafeLoader",
     "guard": lambda line: True, "label": "yaml UnsafeLoader → SafeLoader"},
    {"find": "Loader=yaml.Loader", "replace": "Loader=yaml.SafeLoader",
     "guard": lambda line: True, "label": "yaml Loader → SafeLoader"},
    {"find": "yaml.load(", "replace": "yaml.safe_load(",
     "guard": lambda line: "Loader=" not in line and "safe_load" not in line,
     "label": "yaml.load → yaml.safe_load"},
    {"find": "verify=False", "replace": "verify=True",
     "guard": lambda line: True,
     "label": "verify=False → verify=True"},
    {"find": "ssl._create_unverified_context", "replace": "ssl.create_default_context",
     "guard": lambda line: True,
     "label": "ssl unverified → default (verified) context"},
    {"find": "debug=True", "replace": "debug=False",
     "guard": lambda line: True,
     "label": "debug=True → debug=False"},
]


def _resolve(file: str, manifest_raw: dict) -> Path | None:
    cand = [Path(file)]
    for root in ([manifest_raw.get("source_path")] +
                 list(manifest_raw.get("source_paths") or [])):
        if root:
            cand.append(Path(root).expanduser() / file)
    for p in cand:
        if p.exists():
            return p
    return None


def _target_lines(ev: dict) -> list[int]:
    """1-based line numbers the finding points at (bandit: line; semgrep: range)."""
    if ev.get("line"):
        return [int(ev["line"])]
    start = ev.get("start_line")
    end = ev.get("end_line") or start
    if start:
        return list(range(int(start), int(end) + 1))
    return []


class InsecurePatternFixRemediator(Remediator):
    name = "insecure_pattern_fix"
    handles = {Category.AUTH, Category.INFRA_VULN}
    description = ("Apply a deterministic, drop-in-safe swap for a known-insecure Python "
                   "call (yaml.load, verify=False) on the flagged line; re-scan to verify.")

    def can_fix(self, finding: Finding, manifest_raw: dict) -> bool:
        return self._plan(finding, manifest_raw) is not None

    def propose(self, finding: Finding, manifest_raw: dict) -> Proposal | None:
        plan = self._plan(finding, manifest_raw)
        if plan is None:
            return None
        path, lines, swap, content = plan
        src_lines = content.splitlines(keepends=True)
        for ln in lines:                       # 1-based
            i = ln - 1
            if 0 <= i < len(src_lines) and swap["find"] in src_lines[i]:
                src_lines[i] = src_lines[i].replace(swap["find"], swap["replace"], 1)
        new_content = "".join(src_lines)
        if new_content == content:
            return None

        return Proposal(
            summary=f"{swap['label']} in {path}",
            confidence=0.8,
            rescan_adapter=finding.adapter,
            file_changes=[FileChange(path=str(path.resolve()), new_content=new_content)],
            test_plan={"kind": "source_swap", "file": str(path.resolve()),
                       "label": swap["label"]},
            notes=(f"Deterministic safe replacement '{swap['label']}' applied to the line(s) "
                   f"flagged by {finding.adapter}. Verified by re-scan."),
        )

    @staticmethod
    def _plan(finding: Finding, manifest_raw: dict):
        if finding.adapter not in ("bandit", "semgrep"):
            return None
        ev = finding.evidence or {}
        file = ev.get("file")
        if not file:
            return None
        path = _resolve(file, manifest_raw)
        if path is None:
            return None
        lines = _target_lines(ev)
        if not lines:
            return None
        try:
            content = path.read_text()
        except OSError:
            return None
        src_lines = content.splitlines()
        for swap in SAFE_SWAPS:
            for ln in lines:
                i = ln - 1
                if 0 <= i < len(src_lines) and swap["find"] in src_lines[i] and swap["guard"](src_lines[i]):
                    return path, lines, swap, content
        return None
