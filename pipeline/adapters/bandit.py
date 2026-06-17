"""Bandit adapter — Python-specific SAST.

Complements Semgrep with a different (more Python-aware) ruleset. Bandit
catches a different slice of issues — exec/eval, weak crypto, weak SSL,
hardcoded passwords, subprocess shell=True, etc.

Default skip-list — all bandit LOW-severity, high-volume informational checks
that drown the signal-rich findings. The signal checks (B324 weak crypto,
B105/B106/B107 hardcoded passwords, B602/B604 shell=True, B301 pickle, B608
SQLi, the B5xx SSL/TLS family) are all kept.

    B113  request_without_timeout — reliability anti-pattern, not security.
    B101  assert_used — asserts are normal, especially in tests.
    B110/B112  try_except_pass / try_except_continue — best-effort error
        handling; flags intent, not a vulnerability.
    B404  import subprocess — purely informational ("you imported subprocess").
    B603/B607  subprocess_without_shell_equals_true / partial-path — these fire
        on EVERY list-form CLI invocation. For a tool-orchestrator (and any app
        that shells out by design) that's categorical noise; the real risk is
        shell=True (B602) and shell-metachar use (B604/B605/B606), which stay.

    Override via config: pass skip_tests=[] or a custom list to re-enable any.

Repo: https://github.com/PyCQA/bandit
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _categorize(test_id: str, message: str) -> Category:
    msg = (message or "").lower()
    tid = (test_id or "").upper()
    # B105/B106/B107 = hardcoded passwords; B321 = ftplib; B324 = weak hash; B501-B507 = SSL/TLS
    if tid in ("B105", "B106", "B107") or "hardcoded" in msg or "password" in msg:
        return Category.SECRETS
    if tid.startswith("B5") or "ssl" in msg or "tls" in msg or "weak" in msg:
        return Category.AUTH
    if tid in ("B602", "B603", "B604", "B605", "B606", "B607") or "subprocess" in msg or "shell=True" in msg:
        return Category.INFRA_VULN
    if tid in ("B301", "B302", "B303") or "deserialization" in msg or "pickle" in msg:
        return Category.INFRA_VULN
    return Category.INFRA_VULN


class BanditAdapter(Adapter):
    name = "bandit"
    description = "Bandit — Python-native SAST (exec/eval, weak crypto, hardcoded creds, subprocess)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("bandit"):
            raise AdapterUnavailable("bandit not on PATH. Install: pip install bandit")

    def run(self):
        self.preflight()
        findings: list = []
        for path in self.scan_paths():
            findings.extend(self._scan_one(path))
        return self.filter_findings(findings)

    def _scan_one(self, path: str) -> list:
        skip_tests = self.config.get(
            "skip_tests",
            ["B113", "B101", "B110", "B112", "B404", "B603", "B607"],
        )
        cmd = ["bandit", "-r", "-f", "json", "-q", path]
        if skip_tests:
            cmd += ["-s", ",".join(skip_tests)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable("bandit timed out")
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            raise AdapterUnavailable(f"bandit produced non-JSON output: {proc.stderr[:500]}")

        tier = classify(self.manifest).tier
        findings = []
        for r in data.get("results", []):
            tid = r.get("test_id", "")
            test_name = r.get("test_name", tid)
            severity = SEVERITY_MAP.get(r.get("issue_severity", "LOW"), Severity.LOW)
            confidence = r.get("issue_confidence", "MEDIUM")
            message = r.get("issue_text", "")
            findings.append(self.make_finding(
                tier=tier,
                category=_categorize(tid, message),
                severity=severity,
                title=f"Bandit {tid}: {test_name}",
                description=f"{message} (confidence: {confidence}).",
                evidence={
                    "test_id": tid,
                    "file": r.get("filename"),
                    "line": r.get("line_number"),
                    "code": (r.get("code") or "")[:1000],
                    "confidence": confidence,
                    "cwe": (r.get("issue_cwe") or {}).get("id"),
                },
                affected={"file": r.get("filename")},
                remediation=r.get("more_info"),
                references=[r.get("more_info")] if r.get("more_info") else [],
            ))
        return findings
