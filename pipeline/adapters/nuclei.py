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

from ..core.dast_config import DastConfig
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
        # Nuclei templates walk the URL tree — bare-origin refusal applies per
        # the global DAST safety policy. Bypass by setting a scoped manifest
        # target.base_url (e.g. https://target/app/) or unchecking
        # 'Require scope prefix for crawlers' on /settings → DAST defaults.
        from ..core.dast_config import DastConfig
        dc = DastConfig.from_manifest(self.manifest)
        refusal = dc.refuse_bare_origin_for(self.name)
        if refusal:
            raise AdapterUnavailable(refusal)

    def run(self):
        self.preflight()
        target = self.manifest.target.base_url
        templates = self.config.get("templates", "exposures,misconfiguration,vulnerabilities")
        # DAST defaults: max_rps -> -rate-limit, max_concurrency -> -c, timebox
        # -> subprocess.run(timeout=...). Per-call config overrides win.
        dc = DastConfig.from_manifest(self.manifest)
        rate_limit = int(self.config.get("rate_limit", dc.max_rps))
        concurrency = int(self.config.get("concurrency", dc.max_concurrency))
        cmd = [
            "nuclei", "-u", target, "-t", templates,
            "-j", "-silent", "-no-color",
            "-rate-limit", str(rate_limit),
            "-c", str(concurrency),
        ]
        timeout = dc.subprocess_timeout(override=1200)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable(f"nuclei exceeded timebox ({timeout}s)")

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
