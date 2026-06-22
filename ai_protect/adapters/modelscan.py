"""ModelScan (Protect AI) — malicious model file detector.

Scans .pkl / .pickle / .joblib / .h5 / .pt / .pth / .ckpt / .safetensors / .onnx
files for malicious code paths (e.g., pickle reduce-based code execution
when the model is loaded).

Cited in the v2.1 companion doc as the model-SBOM check at the build stage.
Critical when citizen developers start uploading model artifacts.

Repo: https://github.com/protectai/modelscan
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable

log = logging.getLogger("ai-protect.modelscan")


SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class ModelScanAdapter(Adapter):
    name = "modelscan"
    description = "Protect AI ModelScan — malicious model file detection (pickle, h5, pt, safetensors, onnx)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("modelscan"):
            raise AdapterUnavailable("modelscan not on PATH. Install: pip install modelscan")

    def run(self):
        self.preflight()
        findings: list = []
        for path in self.scan_paths():
            findings.extend(self._scan_one(path))
        return self.filter_findings(findings)

    def _scan_one(self, path: str) -> list:
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "modelscan.json"
            cmd = ["modelscan", "-p", path, "-r", "json", "-o", str(report)]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("modelscan timed out")
            if not report.exists():
                return []
            try:
                data = json.loads(report.read_text())
            except json.JSONDecodeError:
                return []
        tier = classify(self.manifest).tier
        findings = []
        for issue in data.get("issues", []) or []:
            severity = SEVERITY_MAP.get(issue.get("severity", "MEDIUM"), Severity.MEDIUM)
            findings.append(self.make_finding(
                tier=tier,
                category=Category.SUPPLY_CHAIN,
                severity=severity,
                title=f"ModelScan: {issue.get('description', 'malicious model artifact')}",
                description=(
                    f"ModelScan detected a {issue.get('scanner', 'pattern')} match in a model "
                    "artifact. Malicious model files can execute code on load — quarantine and "
                    "investigate before any consumer uses the artifact."
                ),
                evidence={
                    "scanner": issue.get("scanner"),
                    "file": (issue.get("source") or {}),
                    "operator": issue.get("operator"),
                    "module": issue.get("module"),
                },
                affected={"file": (issue.get("source") or {}).get("source")},
                remediation=(
                    "Quarantine the file. Re-source from a trusted, signed registry. "
                    "Treat any agent that loaded this artifact as compromised until proven otherwise."
                ),
                references=["https://github.com/protectai/modelscan"],
            ))
        # Also surface scan summary as info — useful for dashboards even when clean.
        summary = data.get("summary") or {}
        scanned = summary.get("scanned", {}).get("scanned_files", 0)
        if scanned and not findings:
            findings.append(self.make_finding(
                tier=tier,
                category=Category.SUPPLY_CHAIN,
                severity=Severity.INFO,
                title=f"ModelScan: {scanned} model file(s) scanned, no malicious patterns",
                description="Control validation: ModelScan ran clean on the model artifacts.",
                evidence={"scanned": scanned, "skipped": summary.get("skipped", {}).get("total_skipped", 0)},
                affected={"app": self.manifest.name},
                references=["https://github.com/protectai/modelscan"],
            ))
        return findings
