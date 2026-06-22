"""Serialize normalized Findings into DefectDojo's Generic Findings Import."""
from __future__ import annotations

import json
import time

from ...core.findings import Finding, Severity

SCAN_TYPE = "Generic Findings Import"

# ai-protect Severity -> DefectDojo severity label (DefectDojo wants Title-case).
_DD_SEVERITY = {
    Severity.INFO: "Info",
    Severity.LOW: "Low",
    Severity.MEDIUM: "Medium",
    Severity.HIGH: "High",
    Severity.CRITICAL: "Critical",
}

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _fmt_date(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def _tags(f: Finding) -> list[str]:
    tags = [f"app:{f.app_name}", f"tier:{f.tier}", f"stage:{f.stage}",
            f"adapter:{f.adapter}", f"category:{f.category.value}"]
    tags += [f"compliance:{c}" for c in f.compliance]
    return tags


def _description(f: Finding) -> str:
    parts = [f.description or ""]
    if f.affected:
        parts.append("**Affected**\n" + "\n".join(f"- {k}: {v}" for k, v in f.affected.items()))
    if f.evidence:
        # `response` bodies from red-team adapters can be huge — drop them here;
        # the full evidence is preserved in the findings store.
        ev = {k: v for k, v in f.evidence.items() if k != "response"}
        if ev:
            blob = json.dumps(ev, indent=2, default=str)
            parts.append("**Evidence**\n```json\n" + blob[:4000] + "\n```")
    parts.append(f"_stage={f.stage} · adapter={f.adapter} · tier={f.tier} · "
                 f"category={f.category.value}_")
    return "\n\n".join(p for p in parts if p).strip()


def finding_to_generic(f: Finding) -> dict:
    """Map one Finding to a DefectDojo Generic Findings Import entry."""
    ev = f.evidence or {}
    out: dict = {
        "title": f.title,
        "description": _description(f),
        "severity": _DD_SEVERITY[f.severity],
        "date": _fmt_date(f.detected_at),
        "active": True,
        "verified": False,
        "unique_id_from_tool": f.fingerprint,   # stable across runs -> reimport reconcile (no dupes)
        "vuln_id_from_tool": f.fingerprint,
        "service": f.app_name,
        "tags": _tags(f),
    }
    if f.remediation:
        out["mitigation"] = f.remediation
    if f.references:
        out["references"] = "\n".join(f.references)
    if f.compliance:
        out["severity_justification"] = "Compliance: " + ", ".join(f.compliance)

    file_path = ev.get("file") or ev.get("file_path") or ev.get("path")
    if file_path:
        out["file_path"] = str(file_path)
    line = ev.get("line", ev.get("line_number"))
    if line is not None:
        try:
            out["line"] = int(line)
        except (TypeError, ValueError):
            pass
    cwe = ev.get("cwe")
    if cwe is not None:
        try:
            out["cwe"] = int(str(cwe).lower().replace("cwe-", "").strip())
        except (TypeError, ValueError):
            pass
    return out


def to_generic_report(findings: list[Finding]) -> dict:
    """Wrap findings in the Generic Findings Import envelope."""
    return {"findings": [finding_to_generic(f) for f in findings]}


def filter_by_severity(findings: list[Finding], minimum: str) -> list[Finding]:
    """Keep findings at or above ``minimum`` (info|low|medium|high|critical)."""
    thr = _SEV_ORDER.index(minimum)
    return [f for f in findings if _SEV_ORDER.index(f.severity.value) >= thr]
