"""Findings-sink abstraction.

A *sink* is anywhere normalized findings are shipped after a scan: a defect
tracker (DefectDojo), a SARIF/OCSF file, a ticketing system, a webhook. The
pipeline produces ``Finding`` objects once; sinks decide where they go.

Keeping this generic means new destinations plug in by implementing
``FindingsSink`` and registering in ``ai_protect/integrations/registry.py`` — no
changes to the orchestrator, CLI, or run flow.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..core.findings import Finding


@dataclass
class SinkContext:
    """Provenance for a push — lets a sink derive product/engagement/test names."""
    app_name: str = "ai-protect"
    tier: int | None = None
    stage: str = ""
    scan_id: str = ""
    product: str = ""            # explicit override; sink falls back to a default if empty
    engagement: str = ""         # explicit override
    test_title: str = ""         # explicit override


@dataclass
class SinkResult:
    sink: str
    ok: bool
    detail: str = ""
    pushed: int = 0
    ref: dict[str, Any] = field(default_factory=dict)   # ids / urls returned by the destination

    def to_dict(self) -> dict:
        return {"sink": self.sink, "ok": self.ok, "detail": self.detail,
                "pushed": self.pushed, "ref": self.ref}


class SinkNotConfigured(RuntimeError):
    """Raised when a sink is asked to push but isn't configured."""


class FindingsSink(ABC):
    """Base class for a findings destination."""

    name: str = "sink"
    label: str = "Findings sink"

    @abstractmethod
    def is_configured(self) -> bool:
        """True when the sink has everything it needs to push (creds, URL, ...)."""

    @abstractmethod
    def push(self, findings: list[Finding], ctx: SinkContext) -> SinkResult:
        """Ship findings to the destination. Raise SinkNotConfigured if not ready."""
