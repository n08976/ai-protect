"""Dalfox adapter — fast XSS scanning with DOM/parameter analysis.

Nuclei flags template-matchable XSS; Dalfox does the focused work — parameter
mining, reflection/DOM analysis, and payload verification — to confirm
cross-site scripting. Complements Nuclei on the reflected/DOM XSS class that
matters for any LLM front-end rendering model output into a page.

Reflection testing doesn't change server state, so it follows the Nuclei
safety model: no mutation gate, bare-origin refusal per the DAST policy.

Repo: https://github.com/hahwul/dalfox
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
}

# dalfox v3 FindingType codes (the JSON "type" field) -> human label.
FINDING_TYPE = {
    "V": "verified XSS",
    "R": "reflected XSS",
    "A": "DOM XSS (AST)",
}


class DalfoxAdapter(Adapter):
    name = "dalfox"
    description = "Dalfox — XSS scanning with parameter mining + DOM analysis"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("dalfox"):
            raise AdapterUnavailable(
                "dalfox not on PATH. Install the v3 prebuilt binary from "
                "https://github.com/hahwul/dalfox/releases (linux-x86_64.tar.gz) "
                "to /usr/local/bin/dalfox."
            )
        if not self.manifest.target.base_url:
            raise AdapterUnavailable("Manifest has no target.base_url to scan.")
        dc = DastConfig.from_manifest(self.manifest)
        refusal = dc.refuse_bare_origin_for(self.name)
        if refusal:
            raise AdapterUnavailable(refusal)

    def run(self):
        self.preflight()
        dc = DastConfig.from_manifest(self.manifest)
        target = self.manifest.target.base_url
        workers = int(self.config.get("workers", dc.max_concurrency))
        # dalfox v3 --delay is milliseconds between requests; derive from max_rps.
        delay_ms = int(1000 / dc.max_rps) if dc.max_rps else 0
        timeout = dc.subprocess_timeout(override=900)
        # --scan-timeout is dalfox's own per-target wall-clock cap (seconds); set
        # it just under our subprocess timebox so dalfox stops cleanly and still
        # emits the JSON wrapper instead of being killed mid-write.
        cmd = [
            "dalfox", "url", "-u", target,
            "--format", "json",
            "--silence",
            "--no-color",
            "--workers", str(workers),
            "--scan-timeout", str(max(30, timeout - 30)),
        ]
        if delay_ms:
            cmd += ["--delay", str(delay_ms)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable(f"dalfox exceeded timebox ({timeout}s)")

        out = (proc.stdout or "").strip()
        if not out:
            return []
        # dalfox v3 --format json emits a single wrapper object:
        #   {"meta": {...}, "findings": [ {type, param, payload, evidence,
        #    cwe, severity, message_str, data, inject_type, method, location} ]}
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        records = data.get("findings", []) if isinstance(data, dict) else []

        tier = classify(self.manifest).tier
        findings = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            xss_type = FINDING_TYPE.get(rec.get("type"), rec.get("type") or "XSS")
            param = rec.get("param") or rec.get("inject_type")
            severity = SEVERITY_MAP.get((rec.get("severity") or "").lower(), Severity.HIGH)
            findings.append(self.make_finding(
                tier=tier,
                category=Category.INFRA_VULN,
                severity=severity,
                title=f"Dalfox: {xss_type} on parameter '{param}'" if param else f"Dalfox: {xss_type}",
                description=(rec.get("message_str") or rec.get("data") or "Cross-site scripting detected.")[:1500],
                evidence={
                    "type": xss_type,
                    "param": param,
                    "payload": rec.get("payload"),
                    "poc": rec.get("data"),
                    "evidence": rec.get("evidence"),
                    "cwe": rec.get("cwe"),
                    "method": rec.get("method"),
                    "location": rec.get("location"),
                },
                affected={"target": target, "url": rec.get("data") or target},
                remediation=(
                    "Context-encode all user-influenced output (HTML, attribute, JS, URL), "
                    "set a strict Content-Security-Policy, and prefer framework auto-escaping."
                ),
                references=["https://owasp.org/www-community/attacks/xss/"],
            ))
        return self.filter_findings(findings)
