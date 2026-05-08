"""Gitleaks adapter — secret scanning with a different ruleset than TruffleHog.

Gitleaks and TruffleHog disagree on edge cases — running both catches more
than either alone, with negligible additional cost. Gitleaks ships ~120
default rules; TruffleHog ~700 detectors with live-verification.

Repo: https://github.com/gitleaks/gitleaks
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


class GitleaksAdapter(Adapter):
    name = "gitleaks"
    description = "Gitleaks — fast pattern-based secret scanning (complement to TruffleHog)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("gitleaks"):
            raise AdapterUnavailable(
                "gitleaks not on PATH. Install: "
                "https://github.com/gitleaks/gitleaks/releases"
            )

    def run(self):
        self.preflight()
        path = self.config.get("path", self.manifest.raw.get("source_path", "."))
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "gitleaks.json"
            cmd = [
                "gitleaks", "directory", path,
                "--report-format", "json",
                "--report-path", str(report),
                "--no-git",
                "--exit-code", "0",  # don't fail; we'll surface findings via the schema
            ]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("gitleaks timed out")
            if not report.exists():
                return []
            try:
                data = json.loads(report.read_text() or "[]")
            except json.JSONDecodeError:
                return []

        tier = classify(self.manifest).tier
        findings = []
        for r in data:
            rule = r.get("RuleID") or r.get("Description", "secret")
            findings.append(self.make_finding(
                tier=tier,
                category=Category.SECRETS,
                severity=Severity.HIGH,
                title=f"Gitleaks: {rule}",
                description=(r.get("Description") or rule)[:1500],
                evidence={
                    "rule": rule,
                    "file": r.get("File"),
                    "line": r.get("StartLine"),
                    "match": (r.get("Match") or "")[:200],
                    "secret": "[redacted]",  # never echo the secret itself
                    "entropy": r.get("Entropy"),
                },
                affected={"file": r.get("File")},
                remediation=(
                    "Remove the secret from source. Rotate the credential at the issuer. "
                    "If this is a documented test fixture, add to .gitleaksignore."
                ),
                references=["https://github.com/gitleaks/gitleaks"],
            ))
        return findings
