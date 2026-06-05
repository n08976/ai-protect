"""weak_hash_fix — clear a weak-hash finding (bandit B324) the safe way.

Adds ``usedforsecurity=False`` to the flagged md5/sha1 call. This is exactly the
remediation bandit recommends for NON-security uses (cache keys, dedup ids,
ETags): it does NOT change the digest — it only declares the hash isn't used for
security, which clears B324. We never switch the algorithm (md5→sha256 would
change every digest and break callers), so the fix is behaviour-preserving.

AST-based so the insertion is exact (handles chained / nested calls like
``hashlib.sha1(k.encode()).hexdigest()[:16]``).
"""
from __future__ import annotations

import ast

from ...core.findings import Category, Finding
from ..base import FileChange, Proposal, Remediator
from .insecure_pattern_fix import _resolve

_WEAK = {"md5", "sha1"}


def _is_weak_call(node: ast.Call) -> bool:
    f = node.func
    if isinstance(f, ast.Attribute) and f.attr in _WEAK:        # hashlib.md5(...)
        return True
    if isinstance(f, ast.Name) and f.id in _WEAK:               # md5(...) (from hashlib import md5)
        return True
    if isinstance(f, ast.Attribute) and f.attr == "new" and node.args:   # hashlib.new("md5", ...)
        a0 = node.args[0]
        if isinstance(a0, ast.Constant) and isinstance(a0.value, str) and a0.value.lower() in _WEAK:
            return True
    return False


def _has_usedforsecurity(node: ast.Call) -> bool:
    return any(k.arg == "usedforsecurity" for k in node.keywords)


def _find_call(tree: ast.AST, line: int) -> ast.Call | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node, "lineno", None) == line \
                and _is_weak_call(node) and not _has_usedforsecurity(node):
            return node
    return None


class WeakHashFixRemediator(Remediator):
    name = "weak_hash_fix"
    handles = {Category.AUTH, Category.INFRA_VULN, Category.SECRETS}
    description = ("Add usedforsecurity=False to a weak md5/sha1 call flagged by bandit "
                  "B324 (behaviour-preserving; clears the finding).")

    def can_fix(self, finding: Finding, manifest_raw: dict) -> bool:
        return self._plan(finding, manifest_raw) is not None

    def propose(self, finding: Finding, manifest_raw: dict) -> Proposal | None:
        plan = self._plan(finding, manifest_raw)
        if plan is None:
            return None
        path, node, content = plan
        lines = content.split("\n")
        ln = node.end_lineno - 1
        line_b = lines[ln].encode("utf-8")
        pos = node.end_col_offset - 1                 # byte index of the call's closing ')'
        if not (0 <= pos < len(line_b) and line_b[pos:pos + 1] == b")"):
            return None
        insert = b", usedforsecurity=False" if (node.args or node.keywords) else b"usedforsecurity=False"
        lines[ln] = (line_b[:pos] + insert + line_b[pos:]).decode("utf-8")
        new_content = "\n".join(lines)
        if new_content == content:
            return None

        return Proposal(
            summary=f"Add usedforsecurity=False to weak hash in {path}",
            confidence=0.85,
            rescan_adapter=finding.adapter,
            file_changes=[FileChange(path=str(path.resolve()), new_content=new_content)],
            test_plan={"kind": "source_swap", "file": str(path.resolve()),
                       "label": "weak_hash usedforsecurity=False"},
            notes=("Behaviour-preserving: the digest is unchanged; usedforsecurity=False "
                   "just declares non-security use, which clears bandit B324."),
        )

    @staticmethod
    def _plan(finding: Finding, manifest_raw: dict):
        if finding.adapter != "bandit":
            return None
        ev = finding.evidence or {}
        if ev.get("test_id") != "B324":
            return None
        file, line = ev.get("file"), ev.get("line")
        if not file or not line:
            return None
        path = _resolve(file, manifest_raw)
        if path is None:
            return None
        try:
            content = path.read_text()
            tree = ast.parse(content)
        except (OSError, SyntaxError, ValueError):
            return None
        node = _find_call(tree, int(line))
        if node is None:
            return None
        return path, node, content
