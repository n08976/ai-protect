"""Grype (Anchore) — vulnerability scanner that consumes SBOMs or filesystems.

Grype pairs naturally with Syft: Syft produces SBOM, Grype scans it. Grype is
faster than Trivy for image scans and has better SBOM-driven workflows; we run
both because each maintains its own vuln database and they disagree on edge
cases — high recall is the goal at preprod.

Repo: https://github.com/anchore/grype
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
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Negligible": Severity.LOW,
    "Unknown": Severity.LOW,
}


class GrypeAdapter(Adapter):
    name = "grype"
    description = "Anchore Grype — vuln scanner (SBOM-aware). Pair with Syft for the build → preprod chain."

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("grype"):
            raise AdapterUnavailable(
                "grype not on PATH. Install: "
                "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/bin"
            )

    def run(self):
        self.preflight()
        findings: list = []
        for path in self.scan_paths():
            findings.extend(self._scan_one(path))
        return self.filter_findings(findings)

    def _scan_one(self, path: str) -> list:
        # If a Syft SBOM was generated for this manifest+path, prefer it.
        sbom_dir = Path(self.config.get("sbom_dir", "/tmp/sboms"))
        path_slug = path.strip("/").replace("/", "_") or "root"
        sbom_path = sbom_dir / f"{self.manifest.name}.{path_slug}.cdx.json"
        # Back-compat fallback: legacy SBOM name (pre-multi-path).
        if not sbom_path.exists():
            sbom_path = sbom_dir / f"{self.manifest.name}.cdx.json"
        target = str(sbom_path) if sbom_path.exists() else path
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "grype.json"
            cmd = [
                "grype", target,
                "-o", "json",
                "--file", str(report),
                "--quiet",
            ]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("grype timed out")
            if not report.exists():
                return []
            try:
                data = json.loads(report.read_text())
            except json.JSONDecodeError:
                return []

        tier = classify(self.manifest).tier
        findings = []
        for m in data.get("matches", []) or []:
            v = m.get("vulnerability", {}) or {}
            artifact = m.get("artifact", {}) or {}
            severity = SEVERITY_MAP.get(v.get("severity", "Low"), Severity.LOW)
            findings.append(self.make_finding(
                tier=tier,
                category=Category.SUPPLY_CHAIN,
                severity=severity,
                title=f"{v.get('id', 'VULN')}: {artifact.get('name')} {artifact.get('version')} vulnerable",
                description=(v.get("description") or "")[:1500],
                evidence={
                    "vuln_id": v.get("id"),
                    "package": artifact.get("name"),
                    "version": artifact.get("version"),
                    "fixed_in": (v.get("fix") or {}).get("versions") or [],
                    "cvss": v.get("cvss"),
                    "language": artifact.get("language"),
                },
                affected={"package": artifact.get("name"), "version": artifact.get("version")},
                remediation=(
                    f"Upgrade {artifact.get('name')} to "
                    f"{', '.join((v.get('fix') or {}).get('versions') or ['a fixed version'])}."
                ),
                references=v.get("urls", [])[:5],
            ))
        return findings
