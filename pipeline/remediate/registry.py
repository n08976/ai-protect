"""Strategy registry — pick the right Remediator for a Finding."""
from __future__ import annotations

from typing import Iterable

from ..core.findings import Category, Finding
from .base import Remediator
from .strategies.header_snippet import HeaderSnippetRemediator
from .strategies.insecure_pattern_fix import InsecurePatternFixRemediator
from .strategies.npm_bump import NpmBumpRemediator
from .strategies.pip_bump import PipBumpRemediator


# Order matters: the engine applies the FIRST remediator whose can_fix() is True
# (remediators_for preserves this order). npm_bump is listed before pip_bump so
# npm SUPPLY_CHAIN findings are claimed by the right ecosystem.
REMEDIATORS: list[Remediator] = [
    NpmBumpRemediator(),
    PipBumpRemediator(),
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
