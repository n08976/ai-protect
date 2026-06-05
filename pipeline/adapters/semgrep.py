"""Semgrep adapter — SAST patterns for AI-glue code.

Semgrep covers the static-analysis territory Burp can't (Burp scans live
HTTP). Useful here because LLM-glue scripts often: pass user input directly
into prompts, exec/eval generated code, write tokens to logs, build SQL
strings, swallow exceptions on PHI paths.

Repo: https://github.com/semgrep/semgrep
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


# Semgrep rule id keyword → finding category. Best-effort categorization.
def _categorize(rule_id: str, message: str) -> Category:
    rid = rule_id.lower()
    msg = message.lower()
    if any(k in rid or k in msg for k in ("hardcoded", "secret", "api-key", "token", "password")):
        return Category.SECRETS
    if any(k in rid or k in msg for k in ("sql-injection", "ssrf", "xxe", "deserialization", "xss")):
        return Category.INFRA_VULN
    if any(k in rid or k in msg for k in ("auth", "jwt", "session")):
        return Category.AUTH
    if any(k in rid or k in msg for k in ("prompt", "llm", "openai", "anthropic")):
        return Category.PROMPT_INJECTION
    if "subprocess" in rid or "command-injection" in rid:
        return Category.INFRA_VULN
    return Category.INFRA_VULN


class SemgrepAdapter(Adapter):
    name = "semgrep"
    description = "Semgrep — static analysis for AI-glue code (auto config + custom AI rules)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("semgrep"):
            raise AdapterUnavailable(
                "semgrep CLI not on PATH. Install: pip install semgrep"
            )

    def run(self):
        self.preflight()
        findings: list = []
        for path in self.scan_paths():
            findings.extend(self._scan_one(path))
        return self.filter_findings(findings)

    def _scan_one(self, path: str) -> list:
        # Default to a focused, registry-free set: python, security-audit, secrets.
        # Caller can override with config: ['p/owasp-top-ten'] etc.
        configs = self.config.get("configs", ["p/python", "p/security-audit", "p/secrets"])
        cmd = ["semgrep", "scan", "--json", "--quiet", "--no-git-ignore", "--metrics=off"]
        for c in configs:
            cmd.extend(["--config", c])
        cmd.append(path)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get("timeout_s", 600),
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable("semgrep timed out")

        # Semgrep prints JSON to stdout; non-zero exit means findings exist (not an error).
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            raise AdapterUnavailable(f"semgrep produced non-JSON output: {proc.stderr[:500]}")

        tier = classify(self.manifest).tier
        findings = []
        for r in data.get("results", []):
            rid = r.get("check_id", "unknown-rule")
            extra = r.get("extra", {}) or {}
            message = extra.get("message", "") or ""
            severity = SEVERITY_MAP.get(extra.get("severity", "INFO"), Severity.LOW)
            findings.append(self.make_finding(
                tier=tier,
                category=_categorize(rid, message),
                severity=severity,
                title=f"Semgrep: {rid.split('.')[-1]}",
                description=message[:1500] or rid,
                evidence={
                    "rule_id": rid,
                    "file": r.get("path"),
                    "start_line": (r.get("start") or {}).get("line"),
                    "end_line": (r.get("end") or {}).get("line"),
                    # Byte offsets + rule-authored fix let the semgrep_autofix
                    # remediator apply Semgrep's own suggested replacement.
                    "start_offset": (r.get("start") or {}).get("offset"),
                    "end_offset": (r.get("end") or {}).get("offset"),
                    "fix": extra.get("fix"),
                    "snippet": (extra.get("lines") or "")[:1000],
                },
                affected={"file": r.get("path")},
                remediation=(extra.get("fix") or extra.get("metadata", {}).get("fix"))[:1000] if extra.get("fix") or extra.get("metadata", {}).get("fix") else None,
                references=extra.get("metadata", {}).get("references", []),
            ))
        return findings
