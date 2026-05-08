"""Checkov adapter — IaC scanning specialist.

Checkov reads Terraform / K8s / Helm / CloudFormation / Dockerfile and
flags misconfigurations against a 1000+ rule catalog. Use it to validate
the v2.1 sanctioned infrastructure: gateway IaC, MCP farm IaC, agent runtime
deployment manifests.

Repo: https://github.com/bridgecrewio/checkov
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


# Checkov severity strings come from BC_SEV; default conservative.
SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


class CheckovAdapter(Adapter):
    name = "checkov"
    description = "Bridgecrew Checkov — IaC scanning (Terraform, K8s, Helm, Dockerfile)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("checkov"):
            raise AdapterUnavailable("checkov not on PATH. Install: pip install checkov")

    def run(self):
        self.preflight()
        path = self.config.get("path", self.manifest.raw.get("source_path", "."))
        # Quietly suppress non-IaC files; if no IaC found, exit cleanly with empty results.
        cmd = [
            "checkov", "-d", path,
            "--output", "json",
            "--quiet", "--compact",
            "--soft-fail",
        ]
        frameworks = self.config.get("frameworks")
        if frameworks:
            cmd.extend(["--framework", ",".join(frameworks)])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable("checkov timed out")
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return []
        # Checkov returns either a single object or a list when multiple frameworks scan.
        if isinstance(data, dict):
            data = [data]

        tier = classify(self.manifest).tier
        findings = []
        for fw in data:
            results = (fw.get("results") or {}).get("failed_checks", [])
            for r in results:
                severity = SEVERITY_MAP.get((r.get("severity") or "").upper(), Severity.MEDIUM)
                findings.append(self.make_finding(
                    tier=tier,
                    category=Category.INFRA_VULN,
                    severity=severity,
                    title=f"Checkov {r.get('check_id')}: {r.get('check_name')}",
                    description=(r.get("description") or r.get("check_name") or "")[:1500],
                    evidence={
                        "check_id": r.get("check_id"),
                        "file": r.get("file_path"),
                        "lines": r.get("file_line_range"),
                        "resource": r.get("resource"),
                        "framework": fw.get("check_type"),
                    },
                    affected={"file": r.get("file_path"), "resource": r.get("resource")},
                    remediation=r.get("guideline"),
                    references=[r.get("guideline")] if r.get("guideline") else [],
                ))
        return findings
