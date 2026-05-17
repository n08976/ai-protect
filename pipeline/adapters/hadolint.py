"""hadolint — Dockerfile linter (best practices + CIS rules).

Pairs with Trivy/Checkov when containers enter scope. Different focus:
hadolint catches build-time bad practices (LATEST tag, no USER directive,
ADD instead of COPY, etc.) before they become runtime problems.

Repo: https://github.com/hadolint/hadolint
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
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "style": Severity.INFO,
}


class HadolintAdapter(Adapter):
    name = "hadolint"
    description = "hadolint — Dockerfile linter (build-time best practices)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("hadolint"):
            raise AdapterUnavailable(
                "hadolint not on PATH. Install: "
                "https://github.com/hadolint/hadolint/releases"
            )

    def run(self):
        self.preflight()
        findings: list = []
        for path in self.scan_paths():
            findings.extend(self._scan_one(Path(path)))
        return self.filter_findings(findings)

    def _scan_one(self, path: Path) -> list:
        # Find every Dockerfile-like file in the tree.
        candidates = list(path.rglob("Dockerfile*")) + list(path.rglob("*.Dockerfile"))
        if not candidates:
            return []

        tier = classify(self.manifest).tier
        findings = []
        for df in candidates:
            try:
                proc = subprocess.run(
                    ["hadolint", "-f", "json", str(df)],
                    capture_output=True, text=True, timeout=120, check=False,
                )
            except subprocess.TimeoutExpired:
                continue
            try:
                items = json.loads(proc.stdout or "[]")
            except json.JSONDecodeError:
                continue
            for item in items:
                level = (item.get("level") or "info").lower()
                severity = SEVERITY_MAP.get(level, Severity.LOW)
                code = item.get("code", "DL????")
                findings.append(self.make_finding(
                    tier=tier,
                    category=Category.INFRA_VULN,
                    severity=severity,
                    title=f"hadolint {code}: {item.get('message', '')}",
                    description=(item.get("message") or "")[:1500],
                    evidence={
                        "rule": code,
                        "file": str(df),
                        "line": item.get("line"),
                        "column": item.get("column"),
                    },
                    affected={"file": str(df)},
                    remediation=f"See hadolint docs for {code}.",
                    references=[f"https://github.com/hadolint/hadolint/wiki/{code}"],
                ))
        return findings
