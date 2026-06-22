"""Intake gate — validates the manifest itself.

This is the first thing that runs at the intake stage. Failures here block
the application from advancing — without a valid, consistent manifest the
rest of the pipeline can't make any decisions.
"""
from __future__ import annotations

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter


class ManifestValidatorAdapter(Adapter):
    name = "manifest_validator"
    description = "Validate the manifest at intake — schema and policy checks"

    def run(self):
        tier = classify(self.manifest).tier
        findings = []
        for err in self.manifest.validate():
            findings.append(self.make_finding(
                tier=tier,
                category=Category.POLICY_BYPASS,
                severity=Severity.CRITICAL,
                title="Manifest violates sanctioned infrastructure policy",
                description=err,
                evidence={"manifest_app": self.manifest.name},
                affected={"app": self.manifest.name},
                remediation="Fix the manifest and re-submit through intake.",
            ))
        # Owner-on-call must be set
        if not self.manifest.owner:
            findings.append(self.make_finding(
                tier=tier,
                category=Category.POLICY_BYPASS,
                severity=Severity.HIGH,
                title="Manifest missing accountable owner",
                description="Every AI app must have an accountable owner of record.",
                evidence={},
                affected={"app": self.manifest.name},
                remediation="Add owner: <email> to the manifest.",
            ))
        return findings
