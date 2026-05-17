"""gosec adapter — Go-native SAST.

Some MCP server reference implementations and platform tooling are written
in Go. gosec covers the Go-specific issue classes the polyglot scanners
(semgrep, codeql) handle less precisely: G101 hardcoded credentials,
G201/G202 SQL string formatting, G304 file path traversal, G401-G405 weak
crypto, G501-G505 weak hashes, G601 implicit memory aliasing in for-range,
G602 slice access out of bounds.

Adapter degrades gracefully when no Go files are present in the source tree.

Repo: https://github.com/securego/gosec
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _categorize(rule_id: str, message: str) -> Category:
    rid = (rule_id or "").upper()
    msg = (message or "").lower()
    if rid == "G101" or "hardcoded" in msg or "credential" in msg:
        return Category.SECRETS
    if rid in ("G201", "G202") or "sql" in msg or "injection" in msg:
        return Category.INFRA_VULN
    if rid.startswith("G4") or rid.startswith("G5") or "weak" in msg or "tls" in msg or "crypto" in msg:
        return Category.AUTH
    if rid == "G304" or "path traversal" in msg or "file inclusion" in msg:
        return Category.INFRA_VULN
    return Category.INFRA_VULN


class GosecAdapter(Adapter):
    name = "gosec"
    description = "gosec — Go-native SAST (G101/G201/G304/G4xx/G5xx rule families)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("gosec"):
            raise AdapterUnavailable(
                "gosec not on PATH. Install: go install github.com/securego/gosec/v2/cmd/gosec@latest"
            )

    def run(self):
        self.preflight()
        findings: list = []
        for path in self.scan_paths():
            findings.extend(self._scan_one(path))
        return self.filter_findings(findings)

    def _scan_one(self, path: str) -> list:
        # Graceful degrade: nothing to scan if no Go source.
        if not any(Path(path).rglob("*.go")):
            return []

        cmd = ["gosec", "-fmt", "json", "-quiet", "-no-fail", "./..."]
        try:
            proc = subprocess.run(
                cmd,
                cwd=path,
                capture_output=True,
                text=True,
                timeout=self.config.get("timeout_s", 600),
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable("gosec timed out")

        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            raise AdapterUnavailable(
                f"gosec produced non-JSON output: {(proc.stderr or '')[:500]}"
            )

        tier = classify(self.manifest).tier
        findings = []
        for issue in data.get("Issues", []) or []:
            rid = issue.get("rule_id") or issue.get("rule") or "unknown"
            severity = SEVERITY_MAP.get(str(issue.get("severity", "LOW")).upper(), Severity.LOW)
            confidence = issue.get("confidence", "MEDIUM")
            details = issue.get("details") or ""
            findings.append(self.make_finding(
                tier=tier,
                category=_categorize(rid, details),
                severity=severity,
                title=f"gosec {rid}: {details[:80]}",
                description=f"{details} (confidence: {confidence}).",
                evidence={
                    "rule_id": rid,
                    "file": issue.get("file"),
                    "line": issue.get("line"),
                    "code": (issue.get("code") or "")[:1000],
                    "confidence": confidence,
                    "cwe": (issue.get("cwe") or {}).get("id"),
                },
                affected={"file": issue.get("file")},
                remediation=None,
                references=[
                    "https://github.com/securego/gosec",
                    f"https://securego.io/docs/rules/{rid.lower()}.html" if rid.startswith("G") else "",
                ],
            ))
        return findings
