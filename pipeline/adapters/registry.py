"""Adapter registry — name → class. Used by the orchestrator to dispatch."""
from __future__ import annotations

from .atomic import AtomicRedTeamAdapter
from .base import Adapter
from .burp import BurpAdapter
from .eval_suite import EvalSuiteAdapter
from .garak import GarakAdapter
from .manifest_validator import ManifestValidatorAdapter
from .mcp_scope import MCPScopeAdapter
from .metasploit import MetasploitAdapter
from .nuclei import NucleiAdapter
from .pyrit import PyRITAdapter
from .telemetry_drift import AnomalyDetectorAdapter, TelemetryDriftAdapter
from .threat_model_check import ThreatModelCheckAdapter
from .trufflehog import TruffleHogAdapter


REGISTRY: dict[str, type[Adapter]] = {
    "manifest_validator": ManifestValidatorAdapter,
    "threat_model_check": ThreatModelCheckAdapter,
    "garak": GarakAdapter,
    "pyrit": PyRITAdapter,
    "atomic": AtomicRedTeamAdapter,
    "burp": BurpAdapter,
    "metasploit": MetasploitAdapter,
    "mcp_scope": MCPScopeAdapter,
    "nuclei": NucleiAdapter,
    "trufflehog": TruffleHogAdapter,
    "eval_suite": EvalSuiteAdapter,
    "telemetry_drift": TelemetryDriftAdapter,
    "anomaly_detector": AnomalyDetectorAdapter,
}


def get_adapter_class(name: str) -> type[Adapter]:
    if name not in REGISTRY:
        raise KeyError(f"Unknown adapter {name!r}. Registered: {sorted(REGISTRY)}")
    return REGISTRY[name]
