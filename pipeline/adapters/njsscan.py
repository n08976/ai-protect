"""njsscan — Node.js / JavaScript-specific SAST.

Purpose-built for Node API patterns: Express middleware mistakes, prototype
pollution, unsafe eval, JWT misconfiguration. Catches what Semgrep's generic
JS rules miss in Node-specific framework code.

Repo: https://github.com/ajinabraham/njsscan
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
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def _categorize(rule_id: str, owasp: str | None) -> Category:
    s = (rule_id or "").lower()
    if "secret" in s or "credential" in s or "hardcoded" in s:
        return Category.SECRETS
    if "auth" in s or "jwt" in s or "session" in s:
        return Category.AUTH
    if "prototype_pollution" in s or "xss" in s or "ssrf" in s or "sqli" in s:
        return Category.INFRA_VULN
    return Category.INFRA_VULN


class NjsscanAdapter(Adapter):
    name = "njsscan"
    description = "njsscan — Node.js-specific SAST (Express, prototype pollution, JWT misconfig, eval)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("njsscan"):
            raise AdapterUnavailable(
                "njsscan not on PATH. Install: pip install njsscan"
            )

    def run(self):
        self.preflight()
        path = self.config.get("path", self.manifest.raw.get("source_path", "."))
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "njsscan.json"
            try:
                subprocess.run(
                    ["njsscan", "--json", "-o", str(report), path],
                    capture_output=True, text=True, timeout=600, check=False,
                )
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("njsscan timed out")
            if not report.exists():
                return []
            try:
                data = json.loads(report.read_text())
            except json.JSONDecodeError:
                return []

        tier = classify(self.manifest).tier
        findings = []
        for section in ("nodejs", "templates"):
            for rid, rule in (data.get(section) or {}).items():
                metadata = rule.get("metadata", {}) or {}
                severity_str = (metadata.get("severity") or "WARNING").upper()
                severity = SEVERITY_MAP.get(severity_str, Severity.LOW)
                cat = _categorize(rid, metadata.get("owasp"))
                for f in rule.get("files", []) or []:
                    findings.append(self.make_finding(
                        tier=tier,
                        category=cat,
                        severity=severity,
                        title=f"njsscan: {rid}",
                        description=(metadata.get("description") or rid)[:1500],
                        evidence={
                            "rule": rid,
                            "file": f.get("file_path"),
                            "lines": f.get("match_lines"),
                            "match_string": (f.get("match_string") or "")[:500],
                            "cwe": metadata.get("cwe"),
                            "owasp": metadata.get("owasp"),
                        },
                        affected={"file": f.get("file_path")},
                        remediation=metadata.get("description"),
                        references=metadata.get("reference", "").split() if metadata.get("reference") else [],
                    ))
        return findings
