"""Adapter registry — name → class. Used by the orchestrator to dispatch."""
from __future__ import annotations

from .agentic_radar import AgenticRadarAdapter
from .atomic import AtomicRedTeamAdapter
from .bandit import BanditAdapter
from .base import Adapter
from .bearer import BearerAdapter
from .burp import BurpAdapter
from .caldera import CalderaAdapter
from .checkov import CheckovAdapter
from .codeql import CodeQLAdapter
from .commix import CommixAdapter
from .dalfox import DalfoxAdapter
from .dependency_check import DependencyCheckAdapter
from .detect_secrets import DetectSecretsAdapter
from .dockle import DockleAdapter
from .eval_suite import EvalSuiteAdapter
from .garak import GarakAdapter
from .gitleaks import GitleaksAdapter
from .gosec import GosecAdapter
from .grype import GrypeAdapter
from .guardrails import GuardrailsAdapter
from .hadolint import HadolintAdapter
from .intel_match import IntelMatchAdapter
from .manifest_validator import ManifestValidatorAdapter
from .mcp_scope import MCPScopeAdapter
from .metasploit import MetasploitAdapter
from .modelscan import ModelScanAdapter
from .nikto import NiktoAdapter
from .njsscan import NjsscanAdapter
from .nosqli import NosqliAdapter
from .nuclei import NucleiAdapter
from .osv_scanner import OSVScannerAdapter
from .owasp_noir import OWASPNoirAdapter
from .pip_audit import PipAuditAdapter
from .presidio import PresidioAdapter
from .promptfoo import PromptfooAdapter
from .pyrit import PyRITAdapter
from .recon import ReconAdapter
from .ride import RideAdapter
from .semgrep import SemgrepAdapter
from .sqlmap import SqlmapAdapter
from .syft import SyftAdapter
from .telemetry_drift import AnomalyDetectorAdapter, TelemetryDriftAdapter
from .threat_model_check import ThreatModelCheckAdapter
from .tplmap import TplmapAdapter
from .trivy import TrivyAdapter
from .trufflehog import TruffleHogAdapter
from .wpscan import WPScanAdapter
from .zap import ZAPAdapter


REGISTRY: dict[str, type[Adapter]] = {
    "manifest_validator": ManifestValidatorAdapter,
    "threat_model_check": ThreatModelCheckAdapter,
    "garak": GarakAdapter,
    "pyrit": PyRITAdapter,
    "atomic": AtomicRedTeamAdapter,
    "caldera": CalderaAdapter,
    "burp": BurpAdapter,
    "metasploit": MetasploitAdapter,
    "mcp_scope": MCPScopeAdapter,
    "nuclei": NucleiAdapter,
    "trufflehog": TruffleHogAdapter,
    "gitleaks": GitleaksAdapter,
    "detect_secrets": DetectSecretsAdapter,
    "semgrep": SemgrepAdapter,
    "bandit": BanditAdapter,
    "gosec": GosecAdapter,
    "bearer": BearerAdapter,
    "codeql": CodeQLAdapter,
    "njsscan": NjsscanAdapter,
    "pip_audit": PipAuditAdapter,
    "dependency_check": DependencyCheckAdapter,
    "trivy": TrivyAdapter,
    "checkov": CheckovAdapter,
    "syft": SyftAdapter,
    "grype": GrypeAdapter,
    "osv_scanner": OSVScannerAdapter,
    "modelscan": ModelScanAdapter,
    "presidio": PresidioAdapter,
    "hadolint": HadolintAdapter,
    "dockle": DockleAdapter,
    "sqlmap": SqlmapAdapter,
    "zap": ZAPAdapter,
    "nikto": NiktoAdapter,
    "dalfox": DalfoxAdapter,
    "wpscan": WPScanAdapter,
    "commix": CommixAdapter,
    "nosqli": NosqliAdapter,
    "tplmap": TplmapAdapter,
    "recon": ReconAdapter,
    "promptfoo": PromptfooAdapter,
    "agentic_radar": AgenticRadarAdapter,
    "owasp_noir": OWASPNoirAdapter,
    "ride": RideAdapter,
    "guardrails": GuardrailsAdapter,
    "eval_suite": EvalSuiteAdapter,
    "telemetry_drift": TelemetryDriftAdapter,
    "anomaly_detector": AnomalyDetectorAdapter,
    "intel_match": IntelMatchAdapter,
}


def get_adapter_class(name: str) -> type[Adapter]:
    if name not in REGISTRY:
        raise KeyError(f"Unknown adapter {name!r}. Registered: {sorted(REGISTRY)}")
    return REGISTRY[name]
