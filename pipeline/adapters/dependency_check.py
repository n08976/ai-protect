"""OWASP Dependency-Check — multi-language CVE scanner.

Covers Maven / NPM / Gradle / .NET / Ruby / PHP / Python and more. Same role
as pip-audit/grype/osv-scanner but with broader language coverage and a
different (NIST NVD-anchored) database.

Install:
    Download the CLI ZIP from https://github.com/dependency-check/DependencyCheck/releases
    (current stable: v12.2.0 — direct link in repo README). Extract somewhere;
    symlink ~/bin/dependency-check.sh to the script. First run downloads the
    NVD feed (~250MB+).

NVD API key (required for v9+):
    NIST throttles unauthenticated NVD pulls. Set NVD_API_KEY to a key issued
    at https://nvd.nist.gov/developers/request-an-api-key. Without it, runs
    will time out on the feed sync.

Repo: https://github.com/dependency-check/DependencyCheck
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


def _severity_for(cve: dict) -> Severity:
    # CVSS v3.x base score → severity
    metrics = cve.get("cvssv3") or cve.get("cvssv2") or {}
    try:
        score = float(metrics.get("baseScore", 0))
    except (TypeError, ValueError):
        score = 0
    if score >= 9: return Severity.CRITICAL
    if score >= 7: return Severity.HIGH
    if score >= 4: return Severity.MEDIUM
    if score > 0: return Severity.LOW
    return Severity.LOW


class DependencyCheckAdapter(Adapter):
    name = "dependency_check"
    description = "OWASP Dependency-Check — multi-language CVE scanner against NIST NVD"

    def preflight(self) -> None:
        super().preflight()
        if not (shutil.which("dependency-check") or shutil.which("dependency-check.sh")):
            raise AdapterUnavailable(
                "dependency-check not on PATH. Download from "
                "https://github.com/dependency-check/DependencyCheck/releases."
            )

    def run(self):
        self.preflight()
        path = self.config.get("path", self.manifest.raw.get("source_path", "."))
        bin_name = "dependency-check" if shutil.which("dependency-check") else "dependency-check.sh"
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            cmd = [
                bin_name,
                "--project", self.manifest.name,
                "--scan", path,
                "--format", "JSON",
                "--out", str(out_dir),
                "--noupdate",  # rely on cached feed; first run requires --update
            ]
            api_key = os.environ.get("NVD_API_KEY")
            if api_key:
                cmd += ["--nvdApiKey", api_key]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("dependency-check timed out")
            report = out_dir / "dependency-check-report.json"
            if not report.exists():
                return []
            try:
                data = json.loads(report.read_text())
            except json.JSONDecodeError:
                return []

        tier = classify(self.manifest).tier
        findings = []
        for dep in data.get("dependencies", []) or []:
            for cve in dep.get("vulnerabilities", []) or []:
                vid = cve.get("name", "VULN")
                severity = _severity_for(cve)
                findings.append(self.make_finding(
                    tier=tier,
                    category=Category.SUPPLY_CHAIN,
                    severity=severity,
                    title=f"{vid}: {dep.get('fileName', dep.get('filePath'))} vulnerable",
                    description=(cve.get("description") or "")[:1500],
                    evidence={
                        "vuln_id": vid,
                        "package_file": dep.get("fileName"),
                        "path": dep.get("filePath"),
                        "cvss": cve.get("cvssv3", cve.get("cvssv2")),
                    },
                    affected={"package_file": dep.get("fileName"), "path": dep.get("filePath")},
                    remediation="Upgrade to a fixed version per the CVE entry.",
                    references=[r.get("url") for r in (cve.get("references") or []) if r.get("url")][:5],
                ))
        return findings
