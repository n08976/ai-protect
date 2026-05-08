"""OWASP Noir adapter — attack-surface enumeration via static analysis.

Noir reads source code and pulls out HTTP / RPC endpoints, methods, and
parameters without running the app. This is the static-analysis counterpart
to the runtime `recon` chain (subfinder/httpx/naabu/katana).

Used here at intake / build to enumerate the actual API surface of an AI
gateway, MCP server, or agent runtime so downstream DAST adapters (ZAP,
Burp, Nuclei, Ride) get a complete URL list rather than a guessed one.

Repo: https://github.com/owasp-noir/noir
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


# Noir output is informational by design — every endpoint is a finding at INFO
# severity unless it's exposed without auth in a Tier 1/2 manifest, in which
# case it gets flagged.
def _severity_for(endpoint: dict, tier: int) -> Severity:
    method = (endpoint.get("method") or "").upper()
    has_auth = bool(endpoint.get("authentication") or endpoint.get("auth"))
    if not has_auth and method in ("POST", "PUT", "DELETE", "PATCH") and tier <= 2:
        return Severity.MEDIUM
    return Severity.INFO


class OWASPNoirAdapter(Adapter):
    name = "owasp_noir"
    description = "OWASP Noir — attack surface enumeration via static analysis"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("noir"):
            raise AdapterUnavailable(
                "noir not on PATH. Install per https://github.com/owasp-noir/noir"
            )

    def run(self):
        self.preflight()
        path = self.config.get("path", self.manifest.raw.get("source_path", "."))
        cmd = ["noir", "-b", path, "-f", "json"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get("timeout_s", 300),
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable("noir timed out")

        # Noir prints JSON to stdout. Empty output = no endpoints discovered.
        out = (proc.stdout or "").strip()
        if not out:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            raise AdapterUnavailable(
                f"noir produced non-JSON output: {(proc.stderr or '')[:500]}"
            )

        endpoints = data if isinstance(data, list) else data.get("endpoints", [])
        tier = classify(self.manifest).tier
        findings = []
        for ep in endpoints:
            method = (ep.get("method") or "?").upper()
            url = ep.get("url") or ep.get("path") or "/"
            severity = _severity_for(ep, tier)
            unauth = severity == Severity.MEDIUM
            title = (
                f"Noir: unauthenticated {method} {url}" if unauth
                else f"Noir: discovered {method} {url}"
            )
            description = (
                "Static analysis surfaced a state-changing endpoint with no apparent "
                "authentication on a Tier 1/2 application — confirm via threat model."
                if unauth
                else "Endpoint enumerated by static analysis. Use as input to ZAP/Burp/Nuclei."
            )
            findings.append(self.make_finding(
                tier=tier,
                category=Category.AUTH if unauth else Category.INFRA_VULN,
                severity=severity,
                title=title,
                description=description,
                evidence={
                    "method": method,
                    "url": url,
                    "params": ep.get("params") or ep.get("parameters"),
                    "file": ep.get("file"),
                    "line": ep.get("line"),
                    "authentication": ep.get("authentication") or ep.get("auth"),
                },
                affected={"endpoint": f"{method} {url}", "file": ep.get("file")},
                remediation=(
                    "Wire authentication and per-endpoint authorization, then "
                    "re-run downstream DAST against the now-authoritative URL list."
                    if unauth else None
                ),
                references=["https://github.com/owasp-noir/noir"],
            ))
        return findings
