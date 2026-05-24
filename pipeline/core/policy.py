"""Policy table: which adapters run at which tier × stage.

Encodes the v2.1 engagement model directly. The orchestrator reads this table
to decide what to execute — change the table to change the operating model.
"""
from __future__ import annotations

from dataclasses import dataclass


# Stages from the AI-aware SDLC (v2.1 §AI Infrastructure Control Plan §4)
STAGES = ("intake", "design", "build", "preprod", "production")


@dataclass(frozen=True)
class AdapterCall:
    adapter: str           # adapter module name under pipeline.adapters
    blocking: bool = False  # True = a high-severity finding fails the gate
    config: dict | None = None


# adapter_name → set of (tier, stage) pairs where it should run.
# Read top-down by tier; gates are calibrated per the companion doc.
POLICY: dict[int, dict[str, list[AdapterCall]]] = {
    # Tier 1: PHI / clinical / external-facing — full depth, manual red team also kicks in
    1: {
        "intake":     [
            AdapterCall("manifest_validator", blocking=True),
            AdapterCall("owasp_noir"),
            AdapterCall("recon"),
        ],
        "design":     [
            AdapterCall("threat_model_check", blocking=True),
            AdapterCall("guardrails"),
            AdapterCall("checkov"),
        ],
        "build": [
            AdapterCall("trufflehog", blocking=True),
            AdapterCall("gitleaks", blocking=True),
            AdapterCall("detect_secrets"),
            AdapterCall("semgrep"),
            AdapterCall("bandit"),
            AdapterCall("gosec"),
            AdapterCall("bearer"),
            AdapterCall("codeql"),
            AdapterCall("njsscan"),
            AdapterCall("hadolint"),
            AdapterCall("pip_audit"),
            AdapterCall("dependency_check"),
            AdapterCall("trivy", config={"mode": "filesystem"}),
            AdapterCall("syft"),
            AdapterCall("grype"),
            AdapterCall("osv_scanner"),
            AdapterCall("modelscan"),
            AdapterCall("presidio", blocking=True),
            AdapterCall("checkov"),
            AdapterCall("nuclei"),
            AdapterCall("garak", config={"probes": "all"}),
            AdapterCall("pyrit", config={"strategies": ["multiturn", "encoding", "injection"]}),
            AdapterCall("agentic_radar"),
            AdapterCall("intel_match"),
        ],
        "preprod": [
            AdapterCall("garak", config={"probes": "all"}, blocking=True),
            AdapterCall("pyrit", config={"strategies": ["multiturn", "encoding", "injection", "crescendo"]}, blocking=True),
            AdapterCall("mcp_scope", blocking=True),
            AdapterCall("burp", config={"scan": "active"}),
            AdapterCall("zap", config={"mode": "full"}),
            AdapterCall("zap", config={"mode": "api"}),
            AdapterCall("sqlmap"),
            AdapterCall("dockle"),
            AdapterCall("metasploit"),  # auxiliary scanners by default; exploits opt-in per adapter config
            AdapterCall("ride"),  # configurable Ride suite hook
            AdapterCall("atomic", config={"techniques": ["T1059", "T1567", "T1071"]}),
            AdapterCall("caldera"),  # config.adversary_id required at orchestrator dispatch
            AdapterCall("guardrails", blocking=True),
            AdapterCall("promptfoo"),
            AdapterCall("eval_suite", config={"hallucination": True, "bias": True, "jailbreak": True}, blocking=True),
        ],
        "production": [
            AdapterCall("telemetry_drift"),
            AdapterCall("anomaly_detector"),
        ],
    },
    # Tier 2: Sensitive internal action / write-back
    2: {
        "intake":     [
            AdapterCall("manifest_validator", blocking=True),
            AdapterCall("owasp_noir"),
        ],
        "design":     [
            AdapterCall("threat_model_check"),
            AdapterCall("guardrails"),
            AdapterCall("checkov"),
        ],
        "build": [
            AdapterCall("trufflehog", blocking=True),
            AdapterCall("gitleaks", blocking=True),
            AdapterCall("detect_secrets"),
            AdapterCall("semgrep"),
            AdapterCall("bandit"),
            AdapterCall("gosec"),
            AdapterCall("bearer"),
            AdapterCall("codeql"),
            AdapterCall("njsscan"),
            AdapterCall("hadolint"),
            AdapterCall("pip_audit"),
            AdapterCall("dependency_check"),
            AdapterCall("trivy", config={"mode": "filesystem"}),
            AdapterCall("syft"),
            AdapterCall("grype"),
            AdapterCall("osv_scanner"),
            AdapterCall("modelscan"),
            AdapterCall("presidio"),
            AdapterCall("checkov"),
            AdapterCall("nuclei"),
            AdapterCall("garak", config={"probes": "promptinject,leakage,encoding"}),
            AdapterCall("pyrit", config={"strategies": ["injection"]}),
            AdapterCall("agentic_radar"),
            AdapterCall("intel_match"),
        ],
        "preprod": [
            AdapterCall("garak", config={"probes": "promptinject,leakage,encoding"}, blocking=True),
            AdapterCall("mcp_scope", blocking=True),
            AdapterCall("zap", config={"mode": "baseline"}),
            AdapterCall("ride"),  # configurable Ride suite hook
            AdapterCall("caldera"),  # config.adversary_id required at orchestrator dispatch
            AdapterCall("guardrails"),
            AdapterCall("promptfoo"),
            AdapterCall("eval_suite", config={"jailbreak": True}),
        ],
        "production": [
            AdapterCall("telemetry_drift"),
        ],
    },
    # Tier 3: Internal advisory with broad reach — automated only
    3: {
        "intake":     [
            AdapterCall("manifest_validator", blocking=True),
            AdapterCall("owasp_noir"),
        ],
        "design":     [],
        "build": [
            AdapterCall("trufflehog", blocking=True),
            AdapterCall("gitleaks", blocking=True),
            AdapterCall("detect_secrets"),
            AdapterCall("semgrep"),
            AdapterCall("bandit"),
            AdapterCall("gosec"),
            AdapterCall("bearer"),
            AdapterCall("codeql"),
            AdapterCall("njsscan"),
            AdapterCall("hadolint"),
            AdapterCall("pip_audit"),
            AdapterCall("dependency_check"),
            AdapterCall("trivy", config={"mode": "filesystem"}),
            AdapterCall("syft"),
            AdapterCall("grype"),
            AdapterCall("osv_scanner"),
            AdapterCall("modelscan"),
            AdapterCall("checkov"),
            AdapterCall("nuclei"),
            AdapterCall("garak", config={"probes": "promptinject,leakage"}),
            AdapterCall("agentic_radar"),
            AdapterCall("intel_match"),
        ],
        "preprod": [
            AdapterCall("nuclei"),
            AdapterCall("zap", config={"mode": "baseline"}),
            AdapterCall("garak", config={"probes": "promptinject,leakage"}),
            AdapterCall("mcp_scope"),
        ],
        "production": [
            AdapterCall("telemetry_drift"),
        ],
    },
    # Tier 4: Low-impact assistive — paved-road template only, baseline scanning
    4: {
        "intake":     [AdapterCall("manifest_validator", blocking=True)],
        "design":     [],
        "build": [
            AdapterCall("trufflehog", blocking=True),
            AdapterCall("gitleaks", blocking=True),
            AdapterCall("detect_secrets"),
            AdapterCall("semgrep"),
            AdapterCall("bandit"),
            AdapterCall("gosec"),
            AdapterCall("bearer"),
            AdapterCall("codeql"),
            AdapterCall("njsscan"),
            AdapterCall("hadolint"),
            AdapterCall("pip_audit"),
            AdapterCall("dependency_check"),
            AdapterCall("trivy", config={"mode": "filesystem"}),
            AdapterCall("syft"),
            AdapterCall("grype"),
            AdapterCall("osv_scanner"),
            AdapterCall("modelscan"),
        ],
        "preprod":    [],
        "production": [
            AdapterCall("telemetry_drift"),
        ],
    },
}


def adapters_for(tier: int, stage: str) -> list[AdapterCall]:
    """Return the ordered list of adapter calls for this tier × stage."""
    if tier not in POLICY:
        raise ValueError(f"Unknown tier {tier}; must be 1-4")
    if stage not in STAGES:
        raise ValueError(f"Unknown stage {stage!r}; must be one of {STAGES}")
    return POLICY[tier].get(stage, [])
