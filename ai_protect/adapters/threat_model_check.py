"""Design-stage check: confirms threat model artifact exists.

Tier 1 / Tier 2 require a signed-off threat model + data flow diagram before
build (per v2.1 §AI-Aware SDLC §Stage 2). This adapter doesn't author the
threat model — AppSec leads do — but it verifies the artifact is on file and
structurally complete.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter


REQUIRED_KEYS = ("assets", "actors", "trust_boundaries", "threats", "mitigations", "approver", "approved_at")


class ThreatModelCheckAdapter(Adapter):
    name = "threat_model_check"
    description = "Verify a signed-off threat model exists for Tier 1/2 apps"

    def run(self):
        tier = classify(self.manifest).tier
        findings = []
        tm_path = self.manifest.raw.get("threat_model_path")
        if not tm_path:
            findings.append(self.make_finding(
                tier=tier,
                category=Category.POLICY_BYPASS,
                severity=Severity.HIGH,
                title="Threat model path not declared in manifest",
                description=(
                    f"Tier {tier} requires a signed-off threat model before build. "
                    "Add threat_model_path: <relative or absolute path> to the manifest."
                ),
                evidence={},
                affected={"app": self.manifest.name},
                remediation="Author the threat model with AppSec; commit and reference it.",
            ))
            return findings
        path = Path(tm_path)
        if not path.exists():
            findings.append(self.make_finding(
                tier=tier,
                category=Category.POLICY_BYPASS,
                severity=Severity.HIGH,
                title=f"Threat model file not found at {tm_path}",
                description="The manifest references a threat model that does not exist on disk.",
                evidence={"path": str(path)},
                affected={"app": self.manifest.name},
                remediation="Restore or re-author the threat model artifact.",
            ))
            return findings
        try:
            data = yaml.safe_load(path.read_text())
        except yaml.YAMLError as e:
            findings.append(self.make_finding(
                tier=tier,
                category=Category.POLICY_BYPASS,
                severity=Severity.MEDIUM,
                title=f"Threat model not valid YAML",
                description=f"Could not parse the threat model file: {e}",
                evidence={"path": str(path)},
                affected={"app": self.manifest.name},
                remediation="Fix the YAML syntax and re-submit.",
            ))
            return findings
        for key in REQUIRED_KEYS:
            if key not in (data or {}):
                findings.append(self.make_finding(
                    tier=tier,
                    category=Category.POLICY_BYPASS,
                    severity=Severity.MEDIUM,
                    title=f"Threat model missing required section: {key}",
                    description=(
                        f"Required section {key!r} not found. A signed-off threat model "
                        f"must include: {', '.join(REQUIRED_KEYS)}."
                    ),
                    evidence={"path": str(path), "missing": key},
                    affected={"app": self.manifest.name},
                    remediation=f"Add the {key!r} section and re-submit.",
                ))
        return findings
