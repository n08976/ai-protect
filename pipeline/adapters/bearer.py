"""Bearer adapter — privacy-flow SAST.

Bearer tracks how sensitive data classes (PHI, PII, payment, auth) flow
through code. Direct fit for healthcare context: catches when patient-data
fields end up in logs, prompts, or unsanctioned destinations — failure
modes that other SAST tools won't surface.

Repo: https://github.com/Bearer/bearer
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "warning": Severity.LOW,
}


def _categorize(rule_id: str, data_types: list) -> Category:
    rid = (rule_id or "").lower()
    types = " ".join(data_types or []).lower()
    # PHI/PII flow → DATA_LEAKAGE
    if any(k in types for k in ("health", "phi", "medical", "patient", "pii", "personal", "biometric")):
        return Category.DATA_LEAKAGE
    # Auth / secrets
    if "secret" in rid or "credential" in rid or "auth" in rid:
        return Category.SECRETS if "secret" in rid or "credential" in rid else Category.AUTH
    # Default to infra-vuln (logging issues, weak crypto, etc.)
    return Category.INFRA_VULN


class BearerAdapter(Adapter):
    name = "bearer"
    description = "Bearer — privacy-flow SAST tracking PHI/PII through code paths"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("bearer"):
            raise AdapterUnavailable(
                "bearer not on PATH. Install: "
                "curl -sSfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b ~/bin"
            )

    def run(self):
        self.preflight()
        path = self.config.get("path", self.manifest.raw.get("source_path", "."))
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "bearer.json"
            cmd = [
                "bearer", "scan", path,
                "--format", "json",
                "--output", str(report),
                "--quiet", "--exit-code", "0",
                "--skip-path", ".git,node_modules,.venv,venv,__pycache__",
            ]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=900, check=False)
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("bearer timed out")
            if not report.exists():
                return []
            try:
                data = json.loads(report.read_text())
            except json.JSONDecodeError:
                return []

        tier = classify(self.manifest).tier
        findings = []
        # Bearer JSON groups results under severity buckets.
        for sev_bucket, sev_enum in (("critical", Severity.CRITICAL), ("high", Severity.HIGH),
                                     ("medium", Severity.MEDIUM), ("low", Severity.LOW),
                                     ("warning", Severity.LOW)):
            for issue in data.get(sev_bucket, []) or []:
                rule_id = issue.get("id") or issue.get("rule_id", "bearer-rule")
                title = issue.get("title") or issue.get("description", rule_id)
                data_types = issue.get("detectors") or issue.get("data_types") or []
                if isinstance(data_types, dict):
                    data_types = list(data_types.keys())
                cat = _categorize(rule_id, data_types if isinstance(data_types, list) else [])
                # If PHI is involved on a non-PHI manifest, that's HIGH+ regardless.
                severity = sev_enum
                if cat == Category.DATA_LEAKAGE and self.manifest.data_sensitivity != "phi":
                    severity = Severity.HIGH
                findings.append(self.make_finding(
                    tier=tier,
                    category=cat,
                    severity=severity,
                    title=f"Bearer: {title}",
                    description=(issue.get("description") or rule_id)[:1500],
                    evidence={
                        "rule_id": rule_id,
                        "file": issue.get("filename") or issue.get("full_filename"),
                        "line": issue.get("line_number") or issue.get("line"),
                        "data_types": data_types,
                        "snippet": (issue.get("snippet") or "")[:500],
                    },
                    affected={"file": issue.get("filename") or issue.get("full_filename")},
                    remediation=(issue.get("documentation_url") or ""),
                    references=[issue.get("documentation_url")] if issue.get("documentation_url") else [],
                ))
        return findings
