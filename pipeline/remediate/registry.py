"""Strategy registry — pick the right Remediator for a Finding."""
from __future__ import annotations

from typing import Iterable

from ..core.findings import Category, Finding
from .base import Remediator
from .strategies.header_snippet import HeaderSnippetRemediator
from .strategies.pip_bump import PipBumpRemediator


REMEDIATORS: list[Remediator] = [
    PipBumpRemediator(),
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
