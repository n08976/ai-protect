"""detect-secrets adapter — third secret scanner alongside TruffleHog + Gitleaks.

Yelp's detect-secrets uses entropy analysis + pattern matching with an
audited baseline. Different rule philosophy than the other two, so
running all three catches edge cases each individually misses.

Repo: https://github.com/Yelp/detect-secrets
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


class DetectSecretsAdapter(Adapter):
    name = "detect_secrets"
    description = "Yelp detect-secrets — entropy + pattern secret scanning (third opinion)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("detect-secrets"):
            raise AdapterUnavailable(
                "detect-secrets not on PATH. Install: pip install detect-secrets"
            )

    def run(self):
        self.preflight()
        path = self.config.get("path", self.manifest.raw.get("source_path", "."))
        with tempfile.TemporaryDirectory() as td:
            baseline = Path(td) / "baseline.json"
            try:
                proc = subprocess.run(
                    ["detect-secrets", "scan", path],
                    capture_output=True, text=True, timeout=600, check=False,
                )
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("detect-secrets timed out")
            try:
                data = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError:
                return []

        tier = classify(self.manifest).tier
        findings = []
        for fpath, entries in (data.get("results") or {}).items():
            for e in entries:
                ptype = e.get("type", "Secret")
                # Filter False Positives the audit step would catch — anything with
                # "is_secret" explicitly False after audit.
                if e.get("is_secret") is False:
                    continue
                findings.append(self.make_finding(
                    tier=tier,
                    category=Category.SECRETS,
                    severity=Severity.HIGH,
                    title=f"detect-secrets: {ptype}",
                    description=(
                        f"detect-secrets pattern-matched a {ptype} in source. "
                        "Cross-check against TruffleHog/Gitleaks results and the "
                        ".secrets.baseline before treating as ground truth."
                    ),
                    evidence={
                        "type": ptype,
                        "file": fpath,
                        "line": e.get("line_number"),
                        "hashed_secret": e.get("hashed_secret"),
                    },
                    affected={"file": fpath},
                    remediation=(
                        "If real: rotate the credential, remove from source, audit blame "
                        "for prior exposure. If false positive: add to .secrets.baseline."
                    ),
                    references=["https://github.com/Yelp/detect-secrets"],
                ))
        return findings
