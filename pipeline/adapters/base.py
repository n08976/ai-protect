"""Adapter base class. Every tool integration subclasses this.

An adapter has a single job: probe a target, normalize whatever the tool
produced into Finding objects, return them. Adapters are stateless wrt the
target — the manifest is the only target description they get.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from ..core.compliance import controls_for
from ..core.findings import Category, Finding, Severity, new_finding
from ..core.manifest import Manifest


log = logging.getLogger("ai-protect.adapters")


class AdapterError(Exception):
    pass


class AdapterUnavailable(AdapterError):
    """Tool isn't installed or the target isn't reachable. Non-fatal — orchestrator skips."""


class AdapterAuthorizationRequired(AdapterError):
    """Adapter refuses to run because the manifest doesn't authorize the action.

    Used by adapters that mutate state (atomic-red-team, metasploit exploit modules,
    burp active scan) when target.allow_mutation is False.
    """


class Adapter(ABC):
    """Base class for every tool adapter."""

    name: str = ""           # set by subclass
    requires_mutation: bool = False  # if True, target.allow_mutation must be True
    description: str = ""

    def __init__(self, manifest: Manifest, stage: str, config: dict[str, Any] | None = None):
        self.manifest = manifest
        self.stage = stage
        self.config = config or {}

    @abstractmethod
    def run(self) -> list[Finding]:
        """Probe the target and return normalized findings."""

    def preflight(self) -> None:
        """Raise AdapterUnavailable / AdapterAuthorizationRequired if we can't run."""
        if self.requires_mutation and not self.manifest.target.allow_mutation:
            raise AdapterAuthorizationRequired(
                f"{self.name}: requires target.allow_mutation=True in the manifest "
                "(this adapter modifies state on the target)."
            )

    def make_finding(
        self,
        *,
        category: Category,
        severity: Severity,
        title: str,
        description: str,
        evidence: dict | None = None,
        affected: dict | None = None,
        remediation: str | None = None,
        references: list[str] | None = None,
        tier: int,
    ) -> Finding:
        """Helper: build a Finding with category-driven compliance auto-tagging."""
        return new_finding(
            app_name=self.manifest.name,
            tier=tier,
            stage=self.stage,
            adapter=self.name,
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence or {},
            affected=affected or {},
            compliance=controls_for(category),
            remediation=remediation,
            references=references or [],
        )
