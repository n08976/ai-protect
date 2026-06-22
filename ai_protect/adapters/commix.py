"""commix adapter — confirm OS command injection.

Where Nuclei/ZAP flag *probable* command injection, commix takes a URL and
tries to confirm exploitability (results-based, blind time-based, file-based).
Command injection around an LLM app is high-impact: prompt-driven tool calls
that shell out are a classic sink.

Like sqlmap, this adapter REQUIRES `target.allow_mutation = True`: even
detection mode issues many crafted-payload requests and may execute commands
on the target.

Repo: https://github.com/commixproject/commix
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..core.dast_config import DastConfig
from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable

log = logging.getLogger("ai-protect.commix")


class CommixAdapter(Adapter):
    name = "commix"
    description = "commix — OS command injection confirmation (DAST exploitation)"
    requires_mutation = True

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("commix"):
            raise AdapterUnavailable(
                "commix not on PATH. Install: apt install commix "
                "(or clone https://github.com/commixproject/commix)"
            )
        if not self.manifest.target.base_url:
            raise AdapterUnavailable("Manifest has no target.base_url to test.")

    def run(self):
        self.preflight()
        dc = DastConfig.from_manifest(self.manifest)
        target = self.manifest.target.base_url
        timeout = dc.subprocess_timeout(override=900)
        with tempfile.TemporaryDirectory() as td:
            cmd = [
                "commix",
                "--url", target,
                "--batch",                       # never prompt
                "--output-dir", str(Path(td)),
                "--level", str(self.config.get("level", 1)),
                "--timeout", str(self.config.get("timeout_s_per_request", 15)),
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable(f"commix exceeded timebox ({timeout}s)")
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")

        tier = classify(self.manifest).tier
        findings = []
        low = output.lower()
        # commix has no stable machine output; key off its confirmation lines.
        confirmed = "is vulnerable" in low or "appears to be injectable" in low
        if confirmed:
            findings.append(self.make_finding(
                tier=tier,
                category=Category.INFRA_VULN,
                severity=Severity.CRITICAL,
                title="commix: OS command injection confirmed",
                description=(
                    "commix detected an injectable parameter allowing OS command "
                    "execution. Inspect the captured stdout for the parameter and "
                    "injection technique."
                ),
                evidence={"target": target, "stdout_tail": output[-3000:]},
                affected={"target": target},
                remediation=(
                    "Never pass user input to a shell. Use exec-style APIs with an "
                    "argument vector (no shell=True), strict allow-list validation, "
                    "and drop the privileges of any subprocess."
                ),
                references=["https://owasp.org/www-community/attacks/Command_Injection"],
            ))
        return findings
