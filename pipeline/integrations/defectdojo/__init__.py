"""DefectDojo findings export (open source).

Public API — import from ``pipeline.integrations.defectdojo``:

    from pipeline.integrations.defectdojo import DefectDojoSink, DefectDojoConfig

The pipeline serializes normalized ``Finding`` objects into DefectDojo's
**Generic Findings Import** format and POSTs them to the import-scan /
reimport-scan REST API. reimport-scan reconciles against the prior test, so
remediated findings auto-close — closing the continuous fix→verify→track loop.

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
