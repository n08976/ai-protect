"""Strategy registry — pick the right Remediator for a Finding."""
from __future__ import annotations

from typing import Iterable

from ..core.findings import Category, Finding
from .base import Remediator
from .strategies.header_snippet import HeaderSnippetRemediator
from .strategies.insecure_pattern_fix import InsecurePatternFixRemediator
from .strategies.npm_bump import NpmBumpRemediator
from .strategies.pip_bump import PipBumpRemediator
from .strategies.semgrep_autofix import SemgrepAutofixRemediator


# Order matters: the engine applies the FIRST remediator whose can_fix() is True
# (remediators_for preserves this order).
#   - npm_bump before pip_bump  → npm SUPPLY_CHAIN findings claimed by the right ecosystem.
#   - semgrep_autofix before insecure_pattern_fix → prefer the rule-authored fix
#     when Semgrep shipped one; fall back to our curated swaps otherwise.
REMEDIATORS: list[Remediator] = [
    NpmBumpRemediator(),
    PipBumpRemediator(),
    SemgrepAutofixRemediator(),
    InsecurePatternFixRemediator(),
    HeaderSnippetRemediator(),
]


def remediators_for(finding: Finding, manifest_raw: dict) -> list[Remediator]:
    """Return all Remediators that can fix this finding."""
    out: list[Remediator] = []
    for r in REMEDIATORS:
        if finding.category not in r.handles:
            continue
        try:
            if r.can_fix(finding, manifest_raw):
                out.append(r)
        except Exception:
            continue
    return out
