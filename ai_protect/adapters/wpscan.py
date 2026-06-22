"""WPScan adapter — WordPress version / plugin / theme vulnerability scan.

Only relevant when a target fronts WordPress (marketing site, docs portal, a
WP-hosted chat widget). WPScan enumerates the core version, plugins, themes,
users, and known-vulnerable components from its WPVulnDB feed.

A vuln-feed API token (free tier available) materially improves results; pass
it via config['api_token']. Without one, WPScan still does version/component
enumeration but reports fewer CVEs.

Enumeration-class probing, so it follows the Nuclei safety model: no mutation
gate, bare-origin refusal per the global DAST policy.

Repo: https://github.com/wpscanteam/wpscan
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..core.dast_config import DastConfig
from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


class WPScanAdapter(Adapter):
    name = "wpscan"
    description = "WPScan — WordPress core/plugin/theme vulnerability enumeration"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("wpscan"):
            raise AdapterUnavailable(
                "wpscan not on PATH. Install: gem install wpscan "
                "(requires Ruby)."
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
        cmd = [
            "wpscan",
            "--url", target,
            "--format", "json",
            "--no-banner",
            "--disable-tls-checks",
            # vp = vulnerable plugins, vt = vulnerable themes, u = users.
            "--enumerate", str(self.config.get("enumerate", "vp,vt,u")),
            "--request-timeout", str(self.config.get("timeout_s_per_request", 15)),
            "--max-threads", str(int(dc.max_concurrency)),
        ]
        api_token = self.config.get("api_token")
        if api_token:
            cmd += ["--api-token", str(api_token)]
        timeout = dc.subprocess_timeout(override=900)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable(f"wpscan exceeded timebox ({timeout}s)")

        out = (proc.stdout or "").strip()
        if not out:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []

        tier = classify(self.manifest).tier
        findings = []

        def emit(component: str, name: str, vuln: dict):
            title = vuln.get("title") or f"{component}: known vulnerability"
            refs = vuln.get("references", {}) or {}
            ref_urls = []
            if isinstance(refs.get("url"), list):
                ref_urls += refs["url"]
            for cve in refs.get("cve", []) or []:
                ref_urls.append(f"https://nvd.nist.gov/vuln/detail/CVE-{cve}")
            findings.append(self.make_finding(
                tier=tier,
                category=Category.INFRA_VULN,
                severity=Severity.HIGH if ref_urls else Severity.MEDIUM,
                title=f"WPScan: {title[:120]}",
                description=(
                    f"{component} '{name}' has a known vulnerability reported by WPVulnDB. "
                    f"Fixed in: {vuln.get('fixed_in') or 'unknown'}."
                ),
                evidence={"component": component, "name": name, "fixed_in": vuln.get("fixed_in")},
                affected={"target": target, "component": f"{component}:{name}"},
                remediation=(
                    f"Update {component} '{name}' to {vuln.get('fixed_in') or 'the latest patched release'}, "
                    "or remove it if unused."
                ),
                references=ref_urls,
            ))

        # Core version vulns.
        version = data.get("version") or {}
        for v in version.get("vulnerabilities", []) or []:
            emit("wordpress-core", version.get("number") or "core", v)
        # Plugin + theme vulns.
        for bucket, label in (("plugins", "plugin"), ("themes", "theme")):
            for name, info in (data.get(bucket) or {}).items():
                for v in (info or {}).get("vulnerabilities", []) or []:
                    emit(label, name, v)
        # Interesting findings (exposed config, debug logs, etc.).
        for itm in data.get("interesting_findings", []) or []:
            to_s = itm.get("to_s") or itm.get("type") or ""
            if not to_s:
                continue
            findings.append(self.make_finding(
                tier=tier,
                category=Category.INFRA_VULN,
                severity=Severity.LOW,
                title=f"WPScan: {to_s[:120]}",
                description=to_s[:1500],
                evidence={"type": itm.get("type"), "url": itm.get("url")},
                affected={"target": target, "url": itm.get("url") or target},
                remediation="Review the exposed resource; restrict or remove if not required.",
                references=[],
            ))
        return self.filter_findings(findings)
