"""CodeQL adapter — semantic SAST with full taint / data-flow analysis.

CodeQL builds a database from the source tree, then runs query suites against
it. We use the standard 'security-extended' suite by default and parse the
SARIF output. Different class than Semgrep — catches injection sinks Semgrep's
pattern rules can't reach via static patterns alone.

Install:
    Download CodeQL CLI bundle from
    https://github.com/github/codeql-cli-binaries/releases (about 200MB).
    Extract somewhere on PATH (e.g. ~/codeql/codeql).

Repo: https://github.com/github/codeql-cli-binaries
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


SARIF_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


# CodeQL's "security-severity" floats more accurately reflect impact.
def _map_security_severity(score) -> Severity:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return Severity.LOW
    if s >= 9: return Severity.CRITICAL
    if s >= 7: return Severity.HIGH
    if s >= 4: return Severity.MEDIUM
    return Severity.LOW


class CodeQLAdapter(Adapter):
    name = "codeql"
    description = "GitHub CodeQL — semantic SAST with full taint / data-flow analysis"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("codeql"):
            raise AdapterUnavailable(
                "codeql not on PATH. Install the CodeQL CLI bundle from "
                "https://github.com/github/codeql-cli-binaries/releases (extract somewhere on PATH)."
            )

    def run(self):
        self.preflight()
        path = self.config.get("path", self.manifest.raw.get("source_path", "."))
        language = self.config.get("language", "python")
        suite = self.config.get("suite", "python-security-extended")
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "db"
            sarif = Path(td) / "results.sarif"
            try:
                subprocess.run(
                    ["codeql", "database", "create", str(db),
                     "--language", language, "--source-root", path, "--quiet"],
                    capture_output=True, text=True, timeout=900, check=True,
                )
                subprocess.run(
                    ["codeql", "database", "analyze", str(db),
                     "--format", "sarif-latest", "--output", str(sarif),
                     "--quiet", suite],
                    capture_output=True, text=True, timeout=1800, check=True,
                )
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("codeql timed out")
            except subprocess.CalledProcessError as e:
                raise AdapterUnavailable(f"codeql exited non-zero: {e.stderr[:500]}")
            if not sarif.exists():
                return []
            try:
                data = json.loads(sarif.read_text())
            except json.JSONDecodeError:
                return []

        tier = classify(self.manifest).tier
        findings = []
        for run in data.get("runs", []) or []:
            rules = {r["id"]: r for r in (run.get("tool", {}).get("driver", {}).get("rules") or [])}
            for r in run.get("results", []) or []:
                rule_id = r.get("ruleId") or "codeql-rule"
                rule = rules.get(rule_id, {})
                level = r.get("level", rule.get("defaultConfiguration", {}).get("level", "warning"))
                # Prefer security-severity if present
                sec_sev = (rule.get("properties", {}) or {}).get("security-severity")
                severity = _map_security_severity(sec_sev) if sec_sev else SARIF_SEVERITY.get(level, Severity.MEDIUM)
                msg = (r.get("message") or {}).get("text", "")
                loc = ((r.get("locations") or [{}])[0]
                       .get("physicalLocation", {}) or {})
                file = loc.get("artifactLocation", {}).get("uri", "")
                line = (loc.get("region") or {}).get("startLine")
                # Categorize by tags / CWE
                tags = (rule.get("properties", {}) or {}).get("tags", [])
                cat = _categorize_codeql(rule_id, tags)
                findings.append(self.make_finding(
                    tier=tier,
                    category=cat,
                    severity=severity,
                    title=f"CodeQL: {rule.get('shortDescription', {}).get('text', rule_id)}",
                    description=(msg or rule.get("fullDescription", {}).get("text", ""))[:1500],
                    evidence={
                        "rule_id": rule_id,
                        "file": file,
                        "line": line,
                        "tags": tags,
                        "security_severity": sec_sev,
                    },
                    affected={"file": file},
                    remediation=(rule.get("help", {}) or {}).get("text", "")[:1500] or None,
                    references=[
                        h.get("uri") for h in (rule.get("helpUri", []) or [])
                        if isinstance(h, dict)
                    ][:5],
                ))
        return findings


def _categorize_codeql(rule_id: str, tags) -> Category:
    s = " ".join([rule_id] + (tags or [])).lower()
    if "injection" in s or "sqli" in s or "xss" in s or "ssrf" in s:
        return Category.INFRA_VULN
    if "secret" in s or "credential" in s or "hardcoded" in s:
        return Category.SECRETS
    if "auth" in s or "session" in s:
        return Category.AUTH
    if "phi" in s or "pii" in s or "leak" in s or "exfil" in s:
        return Category.DATA_LEAKAGE
    return Category.INFRA_VULN
