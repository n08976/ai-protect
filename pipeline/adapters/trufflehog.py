"""TruffleHog adapter — secret scanning.

Scans the application's source tree (or container image, if configured) for
hardcoded credentials, API keys, signing keys. Critical at the build stage:
LLM apps glue together prompt templates, gateway tokens, MCP credentials —
high concentration of high-value secrets.

Repo: https://github.com/trufflesecurity/trufflehog
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


class TruffleHogAdapter(Adapter):
    name = "trufflehog"
    description = "TruffleHog — credential / secret scanning of source tree or container"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("trufflehog"):
            raise AdapterUnavailable(
                "trufflehog CLI not on PATH. Install: "
                "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh"
            )

    def run(self):
        self.preflight()
        path = self.config.get("path", self.manifest.raw.get("source_path", "."))
        # Default to surfacing unverified secrets too — without network egress to
        # validate, only-verified mode silently produces zero findings on offline
        # codebases.
        only_verified = self.config.get("only_verified", False)
        cmd = ["trufflehog", "filesystem", path, "--json", "--no-update"]
        if only_verified:
            cmd.append("--only-verified")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable("trufflehog timed out")

        tier = classify(self.manifest).tier
        findings = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            detector = rec.get("DetectorName", "unknown")
            verified = rec.get("Verified", False)
            severity = Severity.CRITICAL if verified else Severity.HIGH
            findings.append(self.make_finding(
                tier=tier,
                category=Category.SECRETS,
                severity=severity,
                title=f"Hardcoded credential detected by {detector}" + (" (verified)" if verified else ""),
                description=(
                    f"TruffleHog identified a {detector} credential in the source tree. "
                    + ("Detector confirmed the secret is live (verified=true). "
                       if verified else "Live status not verified, but pattern matched. ")
                    + "Rotate immediately if live; remove from source regardless."
                ),
                evidence={
                    "detector": detector,
                    "file": (rec.get("SourceMetadata", {}).get("Data", {}) or {}).get("Filesystem", {}).get("file"),
                    "line": (rec.get("SourceMetadata", {}).get("Data", {}) or {}).get("Filesystem", {}).get("line"),
                    "verified": verified,
                },
                affected={"app": self.manifest.name},
                remediation=(
                    "Remove the secret from source. Rotate the credential at the issuer. "
                    "Add the path to .trufflehog-allowlist if it's a documented test fixture."
                ),
                references=["https://github.com/trufflesecurity/trufflehog"],
            ))
        return findings
