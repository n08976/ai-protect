"""Scan-mode taxonomy: SAST (source code) vs DAST (live target) + policy.

Built on top of `ai_protect/ui/catalog.py`'s `kind` field (static / dynamic / ai
/ policy) — that field already classifies every wired-in adapter. This
module maps it to the operator-facing scan modes and corrects a handful of
catalog miscategorizations explicitly so the about-page text (which also
reads from `kind`) doesn't have to change.

Modes:
  SAST     — reads source code on disk. Never probes a live target.
             Bandit, Semgrep, gosec, pip_audit, trivy, etc.
  DAST     — probes a live target over the network (HTTP, MCP, the model
             endpoint, the agent runtime). ZAP, Burp, sqlmap, garak,
             pyrit, metasploit, etc.
  POLICY   — pre-flight / always-run policy gates (manifest_validator,
             threat_model_check). Surfaced alongside both modes so an
             operator can see what runs regardless of which scan kind
             they chose. Audit-explainable, not orchestrator-internal.
  TELEMETRY — production observation (telemetry_drift, anomaly_detector).
              Not normally launched ad-hoc from /scan; the production
              stage runs them.
"""
from __future__ import annotations

from typing import Iterable

from ..ui.catalog import CATALOG


# Mode constants — strings so they're serializable to JSON / URL params.
MODE_SAST = "sast"
MODE_DAST = "dast"
MODE_POLICY = "policy"
MODE_TELEMETRY = "telemetry"
SCAN_MODES = (MODE_SAST, MODE_DAST)   # the two operator-facing modes

# Operator-facing labels — kept here so /scan and /docs read the same text.
MODE_LABELS = {
    MODE_SAST:      "Source code (SAST)",
    MODE_DAST:      "Live target (DAST)",
    MODE_POLICY:    "Pre-flight policy",
    MODE_TELEMETRY: "Production telemetry",
}
MODE_DESCRIPTIONS = {
    MODE_SAST: "Read source code on disk. No live target is contacted. "
               "Bandit, Semgrep, secret scanners, dependency CVE checks, IaC scans, etc.",
    MODE_DAST: "Probe a live system — HTTP endpoints, the model gateway, MCP servers, "
               "agent runtimes. ZAP, Burp, garak, PyRIT, sqlmap, MCP scope, etc. "
               "Sends real network requests; verify the target is yours.",
}


# Explicit overrides for adapters whose catalog `kind` doesn't fit the
# scan-mode bucket cleanly. Kept tiny on purpose — every entry is a
# documented divergence, not a stylistic preference.
_KIND_OVERRIDES: dict[str, str] = {
    # agentic_radar reads agent source code (LangChain / LlamaIndex / etc.) —
    # it's SAST in shape even though the catalog flags it 'ai' because it
    # covers AI-shaped artifacts.
    "agentic_radar": MODE_SAST,
    # dockle inspects container image configuration, not a running container.
    # Classified 'dynamic' in catalog because it's grouped with container-runtime
    # adapters, but it's static analysis.
    "dockle":        MODE_SAST,
    # guardrails: verifies config (SAST-shaped) and can smoke a live prompt;
    # default to SAST since the config-only mode is the dashboard default.
    "guardrails":    MODE_SAST,
    # mcp_scope probes the live MCP endpoint when test_user_token_env is set.
    # Catalog calls it 'policy' for organizational reasons; for scan-mode
    # purposes it's DAST.
    "mcp_scope":     MODE_DAST,
    # owasp_noir is an attack-surface enumerator that walks the codebase;
    # SAST despite producing endpoint URLs that downstream DAST runs use.
    "owasp_noir":    MODE_SAST,
    # intel_match cross-references manifest assets against the intel store —
    # no source code read and no network probe to a target. Lives in the
    # always-run policy bucket regardless of which scan kind was chosen.
    "intel_match":   MODE_POLICY,
}


_CATALOG_KIND_TO_MODE: dict[str, str] = {
    "static":  MODE_SAST,
    "dynamic": MODE_DAST,
    "ai":      MODE_DAST,
    "policy":  MODE_POLICY,
}


def mode_for(adapter: str) -> str:
    """Return the scan-mode bucket this adapter belongs to.

    Falls back to MODE_SAST for adapters not in the catalog (defensive —
    a new adapter without metadata shouldn't auto-appear in the DAST list
    where it might surprise an operator who just pasted a URL)."""
    if adapter in _KIND_OVERRIDES:
        return _KIND_OVERRIDES[adapter]
    meta = CATALOG.get(adapter, {})
    kind = meta.get("kind", "static")
    # telemetry_drift / anomaly_detector are kind='policy' in catalog but
    # they run only at the production stage — surface them separately.
    if adapter in ("telemetry_drift", "anomaly_detector"):
        return MODE_TELEMETRY
    return _CATALOG_KIND_TO_MODE.get(kind, MODE_SAST)


def adapters_for_mode(mode: str, registry_names: Iterable[str]) -> list[str]:
    """Filter a list of adapter names down to those that belong in `mode`.

    `registry_names` is typically `REGISTRY.keys()` from adapters.registry.
    Sorted for stable UI rendering.
    """
    return sorted(n for n in registry_names if mode_for(n) == mode)


def pre_flight_adapters(registry_names: Iterable[str]) -> list[str]:
    """Adapters that should always run alongside SAST/DAST as policy gates.

    Operator-visible: shown on /scan in a small 'Always-run policy checks'
    section so the audit story is honest (these aren't orchestrator-internal).
    """
    # Manifest validation + threat-model check are the universal pre-flight
    # set. intel_match is enrichment that runs alongside whatever scan
    # kind was chosen (cross-references manifest assets against intel feeds,
    # not the code or the target). mcp_scope is policy-class but DAST-scoped
    # so it stays out of pre-flight (it doesn't apply to a code-only scan).
    pre = ("manifest_validator", "threat_model_check", "intel_match")
    return [n for n in pre if n in set(registry_names)]


def is_dast_adapter(adapter: str) -> bool:
    return mode_for(adapter) == MODE_DAST


def is_sast_adapter(adapter: str) -> bool:
    return mode_for(adapter) == MODE_SAST
