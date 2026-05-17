"""pip-audit adapter — Python dependency CVE scanner.

Critical complement to SAST: pip-audit catches known-vulnerable transitive
deps (Python Packaging Advisory Database + OSV). Especially relevant for
LLM-glue code, which tends to pull in fast-moving packages (langchain,
openai, anthropic, transformers, etc.) where new CVEs land regularly.

Repo: https://github.com/pypa/pip-audit
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


class PipAuditAdapter(Adapter):
    name = "pip_audit"
    description = "pip-audit — Python dependency CVE scanner (PyPA Advisory DB + OSV)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("pip-audit"):
            raise AdapterUnavailable("pip-audit not on PATH. Install: pip install pip-audit")

    def run(self):
        self.preflight()
        findings: list = []
        for path in self.scan_paths():
            findings.extend(self._scan_one(path))
        return self.filter_findings(findings)

    def _scan_one(self, path: str) -> list:
        # Two modes: scan a requirements.txt if present, else audit the current env.
        req = os.path.join(path, "requirements.txt")
        cmd = ["pip-audit", "-f", "json", "--progress-spinner", "off"]
        if os.path.isfile(req):
            cmd.extend(["-r", req])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable("pip-audit timed out")
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            raise AdapterUnavailable(f"pip-audit produced non-JSON: {proc.stderr[:500]}")

        tier = classify(self.manifest).tier
        findings = []
        deps = data.get("dependencies", []) if isinstance(data, dict) else data
        for d in deps:
            name = d.get("name") or d.get("package")
            version = d.get("version", "?")
            for v in d.get("vulns", []) or []:
                vid = v.get("id", "VULN")
                severity = self._severity_for(v)
                findings.append(self.make_finding(
                    tier=tier,
                    category=Category.SUPPLY_CHAIN,
                    severity=severity,
                    title=f"{vid}: {name} {version} vulnerable",
                    description=(v.get("description") or "")[:1500],
                    evidence={
                        "vuln_id": vid,
                        "package": name,
                        "version": version,
                        "fixed_in": v.get("fix_versions") or [],
                        "aliases": v.get("aliases") or [],
                    },
                    affected={"package": name, "version": version},
                    remediation=(
                        f"Upgrade {name} to {', '.join(v.get('fix_versions') or ['a fixed version'])} "
                        "and re-pin in requirements.txt."
                    ),
                    references=[f"https://osv.dev/vulnerability/{vid}"],
                ))
        return findings

    @staticmethod
    def _severity_for(v: dict) -> Severity:
        # pip-audit doesn't always include CVSS; conservative default.
        for alias in v.get("aliases", []) or []:
            if alias.startswith("CVE-"):
                # Heuristic: presence of fix_versions usually means actively maintained, treat as HIGH.
                if v.get("fix_versions"):
                    return Severity.HIGH
                return Severity.MEDIUM
        return Severity.MEDIUM
