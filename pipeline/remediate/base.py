"""Remediator base class + Proposal dataclass.

A Remediator takes a Finding and produces a Proposal: a unified diff, a list
of files affected, a confidence score, a re-scan adapter, and a test plan.

The engine separately turns a Proposal into a Change, generates tests, runs
the user-approval flow, and (on confirm) applies + validates.

Concrete remediators live under pipeline/remediate/strategies/.
"""
from __future__ import annotations

import difflib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..core.findings import Category, Finding


@dataclass
class FileChange:
    """One file modification proposal."""
    path: str                        # absolute path
    new_content: str                 # full content the engine will write
    create: bool = False             # true if file doesn't currently exist


@dataclass
class Proposal:
    summary: str
    confidence: float                # 0.0-1.0
    rescan_adapter: str              # adapter name to re-run on apply
    file_changes: list[FileChange] = field(default_factory=list)
    test_plan: dict[str, Any] = field(default_factory=dict)  # strategy → instructions for test_authoring
    notes: str = ""

    def unified_diff(self) -> str:
        """Render a unified diff across all file changes."""
        out = []
        for fc in self.file_changes:
            old = ""
            if not fc.create:
                try:
                    with open(fc.path) as f:
                        old = f.read()
                except FileNotFoundError:
                    pass
            diff = difflib.unified_diff(
                old.splitlines(keepends=True),
                fc.new_content.splitlines(keepends=True),
                fromfile=("/dev/null" if fc.create else fc.path),
                tofile=fc.path,
                lineterm="",
            )
            out.append("".join(diff))
        return "\n".join(s for s in out if s)


class Remediator(ABC):
    """Base class for every remediation strategy."""

    name: str = ""
    handles: set[Category] = set()
    description: str = ""

    @abstractmethod
    def can_fix(self, finding: Finding, manifest_raw: dict) -> bool:
        """Quick check: does this remediator apply to this finding given the manifest?"""

    @abstractmethod
    def propose(self, finding: Finding, manifest_raw: dict) -> Proposal | None:
        """Build a concrete Proposal, or return None if not fixable in this context."""
