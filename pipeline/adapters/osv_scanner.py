"""OSV-Scanner (Google) — multi-language CVE scanner.

OSV-Scanner reads OSV.dev (Open Source Vulnerability database) and supports
broader language coverage than pip-audit (Python-only) or Grype (image-leaning).
Useful for polyglot apps and as a third opinion alongside Trivy + Grype.

Repo: https://github.com/google/osv-scanner
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
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class OSVScannerAdapter(Adapter):
    name = "osv_scanner"
    description = "Google OSV-Scanner — multi-language vuln scanner against OSV.dev database"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("osv-scanner"):
            raise AdapterUnavailable(
                "osv-scanner not on PATH. Install: "
                "https://github.com/google/osv-scanner/releases"
            )

    def run(self):
        self.preflight()
        findings: list = []
        for path in self.scan_paths():
            findings.extend(self._scan_one(path))
        return self.filter_findings(findings)

    def _scan_one(self, path: str) -> list:
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "osv.json"
            cmd = ["osv-scanner", "--format", "json", "--output", str(report), "-r", path]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("osv-scanner timed out")
            if not report.exists():
                return []
            try:
                data = json.loads(report.read_text())
            except json.JSONDecodeError:
                return []

        tier = classify(self.manifest).tier
        findings = []
        for r in data.get("results", []) or []:
            source_path = (r.get("source") or {}).get("path", "?")
            for pkg in r.get("packages", []) or []:
                name = (pkg.get("package") or {}).get("name", "?")
                version = (pkg.get("package") or {}).get("version", "?")
                ecosystem = (pkg.get("package") or {}).get("ecosystem", "?")
                for v in pkg.get("vulnerabilities", []) or []:
                    vid = v.get("id", "VULN")
                    severity = self._severity_for(pkg, v)
                    findings.append(self.make_finding(
                        tier=tier,
                        category=Category.SUPPLY_CHAIN,
                        severity=severity,
                        title=f"{vid}: {name} {version} ({ecosystem}) vulnerable",
                        description=(v.get("summary") or v.get("details") or "")[:1500],
                        evidence={
                            "vuln_id": vid,
                            "package": name,
                            "version": version,
                            "ecosystem": ecosystem,
                            "manifest_file": source_path,
                            "aliases": v.get("aliases", [])[:5],
                        },
                        affected={"package": name, "manifest_file": source_path},
                        remediation=(
                            "Check OSV entry for fixed versions; upgrade or apply mitigation."
                        ),
                        references=[f"https://osv.dev/vulnerability/{vid}"],
                    ))
        return findings

    @staticmethod
    def _severity_for(pkg: dict, v: dict) -> Severity:
        # OSV-Scanner severity is per-vuln group; default conservative.
        for g in pkg.get("groups", []) or []:
            for sev in g.get("max_severity", []) or []:
                # Sometimes a numeric CVSS string
                try:
                    score = float(sev)
                    if score >= 9: return Severity.CRITICAL
                    if score >= 7: return Severity.HIGH
                    if score >= 4: return Severity.MEDIUM
                    return Severity.LOW
                except (ValueError, TypeError):
                    pass
        # Else best-effort by alias prefix
        if any(a.startswith("GHSA-") for a in v.get("aliases", []) or []):
            return Severity.MEDIUM
        return Severity.MEDIUM
