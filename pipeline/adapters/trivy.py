"""Trivy adapter — containers, deps, IaC, secrets in one tool.

Trivy is the swiss-army knife: filesystem scans for OS/lang vulns + secrets +
misconfig, container image scans, K8s manifest scans. Useful at multiple
stages — build (filesystem + secrets), preprod (container image), production
(IaC drift).

Repo: https://github.com/aquasecurity/trivy
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
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.LOW,
}


class TrivyAdapter(Adapter):
    name = "trivy"
    description = "Aqua Trivy — filesystem / image / IaC / secret scanner (multi-mode)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("trivy"):
            raise AdapterUnavailable(
                "trivy not on PATH. Install: "
                "https://github.com/aquasecurity/trivy/releases"
            )

    def run(self):
        self.preflight()
        mode = self.config.get("mode", "filesystem")  # filesystem | image | config | k8s
        # Explicit config.target wins (e.g. image:tag for mode=image).
        # Otherwise filesystem mode iterates manifest source paths.
        explicit_target = self.config.get("target")
        if explicit_target:
            targets = [explicit_target]
        elif mode == "filesystem":
            targets = self.scan_paths()
        else:
            raise AdapterUnavailable(f"trivy mode={mode} requires target in config")
        findings: list = []
        for target in targets:
            findings.extend(self._scan_one(target, mode))
        return self.filter_findings(findings)

    def _scan_one(self, target: str, mode: str) -> list:
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "trivy.json"
            scanners = self.config.get("scanners", "vuln,secret,misconfig")
            cmd = [
                "trivy", mode, target,
                "--format", "json",
                "--output", str(report),
                "--scanners", scanners,
                "--quiet", "--no-progress",
                "--cache-dir", str(Path.home() / ".cache" / "trivy"),
            ]
            timeout = self.config.get("timeout_s", 600)
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("trivy timed out")
            if not report.exists():
                return []
            try:
                data = json.loads(report.read_text() or "{}")
            except json.JSONDecodeError:
                return []

        tier = classify(self.manifest).tier
        findings = []
        for result in data.get("Results", []) or []:
            target_name = result.get("Target", "?")
            for v in result.get("Vulnerabilities", []) or []:
                vid = v.get("VulnerabilityID", "VULN")
                severity = SEVERITY_MAP.get(v.get("Severity", "LOW"), Severity.LOW)
                findings.append(self.make_finding(
                    tier=tier,
                    category=Category.SUPPLY_CHAIN,
                    severity=severity,
                    title=f"{vid}: {v.get('PkgName')} {v.get('InstalledVersion')} vulnerable",
                    description=(v.get("Description") or v.get("Title") or "")[:1500],
                    evidence={
                        "vuln_id": vid,
                        "package": v.get("PkgName"),
                        "installed": v.get("InstalledVersion"),
                        "fixed_in": v.get("FixedVersion"),
                        "source": target_name,
                        "cvss": (v.get("CVSS") or {}),
                    },
                    affected={"target": target_name, "package": v.get("PkgName")},
                    remediation=(
                        f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion')}." if v.get("FixedVersion")
                        else "Track upstream for fix; consider mitigations."
                    ),
                    references=v.get("References", [])[:5],
                ))
            for s in result.get("Secrets", []) or []:
                severity = SEVERITY_MAP.get(s.get("Severity", "LOW"), Severity.LOW)
                findings.append(self.make_finding(
                    tier=tier,
                    category=Category.SECRETS,
                    severity=severity,
                    title=f"Trivy secret: {s.get('RuleID')}",
                    description=(s.get("Title") or s.get("RuleID", "secret"))[:1500],
                    evidence={
                        "rule": s.get("RuleID"),
                        "file": target_name,
                        "line": s.get("StartLine"),
                        "category": s.get("Category"),
                    },
                    affected={"file": target_name},
                    remediation="Rotate the credential and remove from source.",
                ))
            for m in result.get("Misconfigurations", []) or []:
                severity = SEVERITY_MAP.get(m.get("Severity", "LOW"), Severity.LOW)
                findings.append(self.make_finding(
                    tier=tier,
                    category=Category.INFRA_VULN,
                    severity=severity,
                    title=f"Trivy misconfig: {m.get('ID')} {m.get('Title')}",
                    description=(m.get("Description") or "")[:1500],
                    evidence={
                        "rule": m.get("ID"),
                        "file": target_name,
                        "line": (m.get("CauseMetadata") or {}).get("StartLine"),
                    },
                    affected={"target": target_name},
                    remediation=(m.get("Resolution") or "")[:1000] or None,
                    references=m.get("References", [])[:5],
                ))
        return findings
