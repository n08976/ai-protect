"""Production-stage adapter — drift on unified AI telemetry.

The companion doc names six telemetry streams (prompts, completions, tool
calls, retrievals, agent decisions, policy events). This adapter compares a
recent window against a baseline window and surfaces drifts that warrant
re-validation:

  - tool-call distribution shift (new tools, sudden frequency change)
  - prompt length distribution shift (encoding-attack signature)
  - policy-event rate (DLP redactions, blocks, step-ups)
  - cost / token velocity (budget kill-switch precursor)

The adapter expects a TELEMETRY_QUERY_URL — typically the SCV correlation API
in front of SIEM. If unset, it logs and returns no findings (production
adapters are non-blocking).
"""
from __future__ import annotations

import logging
import os
from typing import Any

import requests

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable

log = logging.getLogger("ai-protect.telemetry_drift")


class TelemetryDriftAdapter(Adapter):
    name = "telemetry_drift"
    description = "Drift detection over unified AI telemetry (prompts, tool calls, policy events)"

    def run(self):
        tier = classify(self.manifest).tier
        url = os.environ.get("TELEMETRY_QUERY_URL")
        if not url:
            log.info("TELEMETRY_QUERY_URL not set; skipping drift adapter (non-blocking)")
            return []
        try:
            r = requests.post(
                url.rstrip("/") + "/drift",
                json={
                    "app_name": self.manifest.name,
                    "windows": self.config.get("windows", {"baseline": "7d", "recent": "1d"}),
                    "metrics": self.config.get("metrics", [
                        "tool_call_distribution",
                        "prompt_length",
                        "policy_event_rate",
                        "token_velocity",
                    ]),
                },
                timeout=30,
            )
            r.raise_for_status()
            payload = r.json()
        except requests.RequestException as e:
            log.warning("telemetry drift query failed: %s", e)
            return []

        findings = []
        for metric, data in payload.get("metrics", {}).items():
            if not data.get("drifted"):
                continue
            severity = Severity.HIGH if data.get("severity") == "high" else Severity.MEDIUM
            findings.append(self.make_finding(
                tier=tier,
                category=Category.OTHER,
                severity=severity,
                title=f"Telemetry drift detected on {metric}",
                description=(
                    f"Metric {metric!r} drifted between baseline and recent windows. "
                    f"baseline={data.get('baseline')}, recent={data.get('recent')}. "
                    "Re-validation recommended; consider re-triggering Stage 3 (Validate)."
                ),
                evidence=data,
                affected={"app": self.manifest.name},
                remediation=(
                    "Investigate via the technical dashboard. If the drift correlates with "
                    "a deployment or prompt change, re-run preprod gates."
                ),
            ))
        return findings


# Aliases — referenced by policy table.
class AnomalyDetectorAdapter(TelemetryDriftAdapter):
    name = "anomaly_detector"
    description = "Lightweight anomaly detection over telemetry (production-stage)"
