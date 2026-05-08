"""dockle adapter — container image best-practices.

Different focus than Trivy (which scans for CVEs). Dockle checks image
hygiene: root user, secret files in layers, sensitive dirs world-writable,
proper HEALTHCHECK, distroless preference, etc.

Configure via manifest.raw['container_image'] (e.g. registry.example/foo:tag)
or manifest.raw['source_path'] containing a built image.

Repo: https://github.com/goodwithtech/dockle
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


SEVERITY_MAP = {
    "FATAL": Severity.CRITICAL,
    "WARN": Severity.HIGH,
    "INFO": Severity.MEDIUM,
    "SKIP": Severity.LOW,
    "PASS": Severity.INFO,
}


class DockleAdapter(Adapter):
    name = "dockle"
    description = "dockle — container image hygiene scanner (CIS-aligned best practices)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("dockle"):
            raise AdapterUnavailable(
                "dockle not on PATH. Install: "
                "https://github.com/goodwithtech/dockle/releases"
            )
        image = self.config.get("image") or self.manifest.raw.get("container_image")
        if not image:
            raise AdapterUnavailable(
                "No container_image declared. Set adapter config 'image' or manifest 'container_image'."
            )

    def run(self):
        self.preflight()
        image = self.config.get("image") or self.manifest.raw.get("container_image")
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "dockle.json"
            cmd = ["dockle", "-f", "json", "-o", str(report), "--exit-code", "0", image]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("dockle timed out")
            if not report.exists():
                return []
            try:
                data = json.loads(report.read_text())
            except json.JSONDecodeError:
                return []

        tier = classify(self.manifest).tier
        findings = []
        for s in data.get("summary", {}) and []:
            pass  # summary is for stats; details come from 'details' below
        for d in data.get("details", []) or []:
            level = (d.get("level") or "INFO").upper()
            if level == "PASS":
                continue
            severity = SEVERITY_MAP.get(level, Severity.LOW)
            code = d.get("code", "CIS-?")
            findings.append(self.make_finding(
                tier=tier,
                category=Category.INFRA_VULN,
                severity=severity,
                title=f"dockle {code}: {d.get('title', '')}",
                description="; ".join((d.get("alerts") or []))[:1500],
                evidence={
                    "rule": code,
                    "image": image,
                    "alerts": d.get("alerts"),
                    "title": d.get("title"),
                },
                affected={"image": image},
                remediation=f"See dockle docs for {code}.",
                references=[f"https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#{code.lower()}"],
            ))
        return findings
