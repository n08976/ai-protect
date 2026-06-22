"""DefectDojo findings export (open source).

Public API — import from ``ai_protect.integrations.defectdojo``:

    from ai_protect.integrations.defectdojo import DefectDojoSink, DefectDojoConfig

The pipeline serializes normalized ``Finding`` objects into DefectDojo's
**Generic Findings Import** format and POSTs them to the import-scan /
reimport-scan REST API. reimport-scan reconciles against the prior test (keyed
on the stable ``unique_id_from_tool`` fingerprint) so a re-scan updates findings
in place instead of duplicating them; we also request ``close_old_findings`` so
DefectDojo can mitigate findings no longer reported once remediated.

Config resolves from CLI args → env (DEFECTDOJO_URL / DEFECTDOJO_API_TOKEN) →
UI settings, so it works the same in CI and from the dashboard.
"""
from __future__ import annotations

from .client import DefectDojoClient, DefectDojoError
from .config import DefectDojoConfig, DefectDojoConfigError
from .serialize import (
    SCAN_TYPE,
    filter_by_severity,
    finding_to_generic,
    to_generic_report,
)
from .sink import DefectDojoSink

__all__ = [
    "DefectDojoClient",
    "DefectDojoConfig",
    "DefectDojoConfigError",
    "DefectDojoError",
    "DefectDojoSink",
    "SCAN_TYPE",
    "filter_by_severity",
    "finding_to_generic",
    "to_generic_report",
]
