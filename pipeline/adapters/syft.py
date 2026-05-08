"""Syft (Anchore) — SBOM generator.

HITRUST audit asks for SBOM evidence; Trivy can produce one but Syft's
CycloneDX/SPDX output is the format compliance tooling expects. This
adapter generates an SBOM and records a single info-level finding linking
to the artifact, plus a finding per package above a license-allowlist
violation if one is configured.

Repo: https://github.com/anchore/syft
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


# Packages with these licenses block the build (configurable per manifest).
DEFAULT_LICENSE_DENY = {"AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "GPL-3.0-only"}


class SyftAdapter(Adapter):
    name = "syft"
    description = "Anchore Syft — SBOM generator (CycloneDX / SPDX). Compliance evidence for HITRUST."

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("syft"):
            raise AdapterUnavailable(
                "syft not on PATH. Install: "
                "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/bin"
            )

    def run(self):
        self.preflight()
        path = self.config.get("path", self.manifest.raw.get("source_path", "."))
        out_dir = Path(self.config.get("output_dir", "/tmp/sboms"))
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{self.manifest.name}.cdx.json"
        cmd = [
            "syft", "scan", path,
            "-o", f"cyclonedx-json={out_file}",
            "--quiet",
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable("syft timed out")
        if not out_file.exists():
            return []
        try:
            data = json.loads(out_file.read_text())
        except json.JSONDecodeError:
            return []

        tier = classify(self.manifest).tier
        components = data.get("components", []) or []
        findings = []

        # Always emit a single info finding pointing at the SBOM artifact.
        findings.append(self.make_finding(
            tier=tier,
            category=Category.SUPPLY_CHAIN,
            severity=Severity.INFO,
            title=f"SBOM generated: {len(components)} components",
            description=(
                f"Syft generated a CycloneDX SBOM for {self.manifest.name} containing "
                f"{len(components)} components. Stored as audit evidence."
            ),
            evidence={
                "sbom_path": str(out_file),
                "component_count": len(components),
                "format": "cyclonedx-json",
            },
            affected={"app": self.manifest.name},
            references=["https://github.com/anchore/syft", "https://cyclonedx.org/"],
        ))

        # License deny-list scan.
        deny = set(self.config.get("license_deny", DEFAULT_LICENSE_DENY))
        for c in components:
            licenses = []
            for lic in (c.get("licenses") or []):
                lid = (lic.get("license") or {}).get("id") or (lic.get("license") or {}).get("name")
                if lid:
                    licenses.append(lid)
            for lid in licenses:
                if lid in deny:
                    findings.append(self.make_finding(
                        tier=tier,
                        category=Category.SUPPLY_CHAIN,
                        severity=Severity.HIGH,
                        title=f"License deny-list hit: {c.get('name')} ({lid})",
                        description=(
                            f"Package {c.get('name')} v{c.get('version')} is licensed {lid}, "
                            "which is on the configured deny-list. Coordinate with Legal "
                            "before consuming this package."
                        ),
                        evidence={"package": c.get("name"), "version": c.get("version"), "license": lid},
                        affected={"package": c.get("name")},
                        remediation="Replace with a permissively-licensed alternative or get explicit Legal approval.",
                    ))
        return findings
