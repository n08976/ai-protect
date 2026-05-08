"""AI application manifest — the input to the pipeline.

Every AI app, agent, or RAG system that flows through this pipeline declares
itself with a manifest. The manifest drives risk-tiering, adapter selection,
and compliance evidence generation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


DataSensitivity = str  # "phi" | "pii" | "financial" | "confidential" | "public"
DecisionImpact = str   # "advisory" | "automated_action" | "clinical_influence" | "irreversible"
Integration = str      # "read_only" | "write_back" | "agent_tool_use" | "external_action"
UserPopulation = str   # "single_user" | "team" | "enterprise" | "external"


@dataclass
class ModelEndpoint:
    name: str                         # display name
    provider: str                     # "anthropic" | "openai" | "internal" | ...
    model: str                        # model id (e.g. "claude-sonnet-4-6")
    via_gateway: bool = True          # must be true for sanctioned access
    baa_covered: bool = False         # required for PHI handling
    endpoint_url: str | None = None   # only set for non-gateway access (rare)
    auth_env: str | None = None       # env var name holding the API key


@dataclass
class MCPServer:
    name: str
    tier: int                         # 1-4; flows to calling agent (highest wins)
    data_scope: str                   # "phi" | "pii" | "internal" | "public"
    actions: list[str] = field(default_factory=list)  # tool names exposed
    side_effects: str = "read_only"   # "read_only" | "mutating" | "irreversible"
    third_party: bool = False


@dataclass
class AgentSurface:
    """Inputs an attacker could control."""
    has_user_chat: bool = False
    has_email_intake: bool = False
    has_document_ingest: bool = False
    has_webhook: bool = False
    has_voice: bool = False


@dataclass
class TargetEnvironment:
    """Where adapters can probe — explicit authorization scope."""
    base_url: str | None = None
    api_url: str | None = None
    test_user_token_env: str | None = None
    allow_mutation: bool = False      # adapters that modify state require this
    network_allowed_zones: list[str] = field(default_factory=list)


@dataclass
class Manifest:
    name: str
    owner: str                        # email of accountable owner
    on_call: str                      # email or PagerDuty schedule
    description: str

    data_sensitivity: DataSensitivity
    decision_impact: DecisionImpact
    integration_footprint: Integration
    user_population: UserPopulation

    models: list[ModelEndpoint] = field(default_factory=list)
    mcp_servers: list[MCPServer] = field(default_factory=list)
    surfaces: AgentSurface = field(default_factory=AgentSurface)
    target: TargetEnvironment = field(default_factory=TargetEnvironment)

    expected_actions: list[str] = field(default_factory=list)  # ground truth for misuse tests
    expected_data_scopes: list[str] = field(default_factory=list)

    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Manifest":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Manifest":
        models = [ModelEndpoint(**m) for m in data.get("models", [])]
        mcps = [MCPServer(**m) for m in data.get("mcp_servers", [])]
        surfaces = AgentSurface(**data.get("surfaces", {}))
        target = TargetEnvironment(**data.get("target", {}))
        return cls(
            name=data["name"],
            owner=data["owner"],
            on_call=data.get("on_call", data["owner"]),
            description=data.get("description", ""),
            data_sensitivity=data["data_sensitivity"],
            decision_impact=data["decision_impact"],
            integration_footprint=data["integration_footprint"],
            user_population=data["user_population"],
            models=models,
            mcp_servers=mcps,
            surfaces=surfaces,
            target=target,
            expected_actions=data.get("expected_actions", []),
            expected_data_scopes=data.get("expected_data_scopes", []),
            raw=data,
        )

    def validate(self) -> list[str]:
        """Return a list of validation errors. Empty list means valid."""
        errors: list[str] = []
        if self.data_sensitivity == "phi":
            for m in self.models:
                if not m.baa_covered:
                    errors.append(
                        f"Model {m.name!r} is used with PHI data but baa_covered=False. "
                        "PHI may only be sent to BAA-covered endpoints."
                    )
                if not m.via_gateway:
                    errors.append(
                        f"Model {m.name!r} is configured with via_gateway=False. "
                        "Direct API access is prohibited; route through the sanctioned AI gateway."
                    )
        for m in self.models:
            if not m.via_gateway and not m.endpoint_url:
                errors.append(f"Model {m.name!r}: via_gateway=False requires endpoint_url.")
        return errors
