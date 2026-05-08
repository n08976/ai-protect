"""sqlmap adapter — confirm + characterize SQL injection findings.

Nuclei/ZAP detect probable injection; sqlmap takes a URL/parameter and tries
to confirm exploitability (boolean-based, time-based, error-based, UNION).
Pipeline-shaped via --batch + --output-dir.

This adapter REQUIRES `target.allow_mutation = True` because sqlmap's
detection-only mode still issues many requests with crafted payloads.

Repo: https://github.com/sqlmapproject/sqlmap
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

log = logging.getLogger("ai-protect.sqlmap")


class SqlmapAdapter(Adapter):
    name = "sqlmap"
    description = "sqlmap — SQL injection confirmation + characterization (DAST exploitation)"
    requires_mutation = True

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("sqlmap"):
            raise AdapterUnavailable("sqlmap not on PATH. Install: pip install sqlmap")
        if not self.manifest.target.base_url:
            raise AdapterUnavailable("Manifest has no target.base_url to test.")

    def run(self):
        self.preflight()
        target = self.manifest.target.base_url
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            cmd = [
                "sqlmap", "-u", target,
                "--batch",                  # never prompt
                "--output-dir", str(out_dir),
                "--smart",                  # only deep-test on suspected injectable params
                "--level", str(self.config.get("level", 2)),
                "--risk", str(self.config.get("risk", 1)),
                "--timeout", str(self.config.get("timeout_s_per_request", 15)),
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900, check=False)
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("sqlmap timed out")
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")

        tier = classify(self.manifest).tier
        findings = []
        # sqlmap doesn't have stable JSON output across versions; parse stdout
        # for the canonical "is vulnerable" / "Type:" lines.
        if "is vulnerable" in output.lower() or "is not vulnerable" not in output.lower() and "Type:" in output:
            findings.append(self.make_finding(
                tier=tier,
                category=Category.INFRA_VULN,
                severity=Severity.HIGH,
                title="sqlmap: SQL injection confirmed",
                description=(
                    "sqlmap was able to detect or exploit a SQL injection. "
                    "Inspect the captured stdout for technique, parameter, and DB type."
                ),
                evidence={
                    "target": target,
                    "stdout_tail": output[-3000:],
                },
                affected={"target": target},
                remediation=(
                    "Use parameterized queries; an ORM with bound parameters; or a strict "
                    "input validator. Never concatenate user input into SQL."
                ),
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            ))
        return findings
