"""Nuclei adapter — template-driven web vulnerability scanning.

Nuclei is the lightweight scanner Burp's heavier active scan complements.
We run Nuclei in build/preprod against the API surface around the LLM —
exposed admin endpoints, prompt-template injection in URL params, debug
endpoints leaking model config, etc.

Repo: https://github.com/projectdiscovery/nuclei (in RedTeam-Tools list)
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.LOW,
}


class NucleiAdapter(Adapter):
    name = "nuclei"
    description = "ProjectDiscovery Nuclei — template-driven vulnerability scanning"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("nuclei"):
            raise AdapterUnavailable(
                "nuclei CLI not on PATH. Install: "
                "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )
        if not self.manifest.target.base_url:
            raise AdapterUnavailable("Manifest has no target.base_url to scan.")

    def run(self):
        self.preflight()
        target = self.manifest.target.base_url
        templates = self.config.get("templates", "exposures,misconfiguration,vulnerabilities")
        cmd = [
            "nuclei", "-u", target, "-t", templates,
            "-j", "-silent", "-no-color", "-rate-limit", str(self.config.get("rate_limit", 50)),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1200, check=False)
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable("nuclei timed out")

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
            info = rec.get("info", {})
            template = rec.get("template-id") or info.get("name", "unknown")
            severity = SEVERITY_MAP.get((info.get("severity") or "").lower(), Severity.LOW)
            findings.append(self.make_finding(
                tier=tier,
                category=Category.INFRA_VULN,
                severity=severity,
                title=f"Nuclei: {info.get('name', template)}",
                description=(info.get("description") or "")[:1500],
                evidence={
                    "template": template,
                    "matched_at": rec.get("matched-at"),
                    "matcher_name": rec.get("matcher-name"),
                    "tags": info.get("tags"),
                },
                affected={"target": target},
                remediation=info.get("remediation"),
                references=info.get("reference", []) if isinstance(info.get("reference"), list) else [],
            ))
        return findings
