"""AI application manifest — the input to the pipeline.

Every AI app, agent, or RAG system that flows through this pipeline declares
itself with a manifest. The manifest drives risk-tiering, adapter selection,
and compliance evidence generation.
"""
from __future__ import annotations

import fnmatch
import os
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

    # --- scan scope ---
    # `source_paths` is the canonical list. `source_path` (singular) is kept
    # for backward compatibility with existing manifests — if both are set,
    # source_paths wins. scan_targets() folds them together.
    source_path: str | None = None
    source_paths: list[str] = field(default_factory=list)
    # source_excludes: each entry is either an absolute path (prefix-match)
    # or a glob pattern (fnmatch against the full path AND the basename).
    # Adapters use is_excluded(path) to drop findings post-hoc; tools whose
    # CLIs accept native --exclude flags can also wire these.
    source_excludes: list[str] = field(default_factory=list)

    # --- app aliases (Option A from session 2026-05-18) ---
    # Past app_names this manifest inherits resolution history from. When a
    # finding's underlying (adapter, category, title) match a resolved Change
    # under an aliased app, the dashboard treats this app's same logical
    # finding as resolved too. Useful when a manifest is renamed/relocated
    # but the source under it is the same as the old app.
    app_aliases: list[str] = field(default_factory=list)

    # --- source provider (added 2026-05-24) ---
    # Where the orchestrator fetches code from before adapter dispatch.
    # Default '' falls back to settings.default_provider at scan time, so an
    # operator can pin every existing manifest to local OR to github via one
    # central setting.
    source_provider: str = ""                    # '' | 'local' | 'github'
    # GitHub-specific. github_repo accepts 'owner/name', a full HTTPS URL,
    # or git@github.com:owner/name.git (the provider normalizes them).
    github_repo: str = ""
    github_ref: str = ""                         # branch / tag / SHA; '' uses settings default
    github_clone_depth: int | None = None        # None uses settings default (typically 1, shallow)
    # Monorepo support: scan only this subdirectory of the cloned repo. '' scans
    # the whole repo. e.g. github_subdir: commercial → scan <clone>/commercial.
    github_subdir: str = ""

    # --- findings-sink integrations (added 2026-06-11) ---
    # Per-app overrides for where findings are shipped after a scan, e.g.
    #   integrations:
    #     defectdojo: { product: "Commercial Ads MCP", engagement: "ai-protect preprod" }
    # Sinks (pipeline/integrations/) read this via manifest.integration(name);
    # missing keys fall back to settings defaults, then the app name / stage.
    integrations: dict[str, Any] = field(default_factory=dict)

    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def integration(self, name: str) -> dict[str, Any]:
        """Per-app config dict for a findings sink (empty dict if unset)."""
        val = self.integrations.get(name)
        return dict(val) if isinstance(val, dict) else {}

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
            source_path=data.get("source_path"),
            source_paths=list(data.get("source_paths") or []),
            source_excludes=list(data.get("source_excludes") or []),
            app_aliases=list(data.get("app_aliases") or []),
            source_provider=str(data.get("source_provider") or "").strip(),
            github_repo=str(data.get("github_repo") or "").strip(),
            github_ref=str(data.get("github_ref") or "").strip(),
            github_clone_depth=data.get("github_clone_depth"),
            github_subdir=str(data.get("github_subdir") or "").strip().strip("/"),
            integrations=dict(data.get("integrations") or {}),
            raw=data,
        )

    def scan_targets(self) -> list[str]:
        """Resolve the list of directories/files to scan.

        Precedence:
            1. source_paths (list) — canonical, supports multi-path manifests
            2. source_path  (str)  — back-compat single-path manifests
            3. []                  — no source scope declared; adapters should
                                     treat as "no work to do" rather than
                                     defaulting to '.' and walking the whole repo.

        Paths are returned as-is (no expansion / normalization beyond `~`).
        Non-existent paths are NOT pruned here — the adapter that uses them
        decides what to do (raise AdapterUnavailable, skip, etc.).
        """
        out: list[str] = []
        if self.source_paths:
            out.extend(self.source_paths)
        if self.source_path:
            if self.source_path not in out:
                out.append(self.source_path)
        return [os.path.expanduser(p) for p in out]

    def is_excluded(self, path: str | None) -> bool:
        """True if `path` matches any source_excludes entry.

        Match rules per exclude entry:
          - Starts with '/': absolute prefix match against `path`.
          - Contains a glob char (*, ?, [): fnmatch against the full path AND
            the basename. Useful for patterns like '*.pyc' or 'node_modules/'.
          - Otherwise: substring match against `path` (so `__pycache__` matches
            anywhere in the tree without the operator having to write a glob).

        Returns False on empty/None input — adapters call this defensively.
        """
        if not path or not self.source_excludes:
            return False
        p = os.path.expanduser(str(path))
        base = os.path.basename(p)
        for pat in self.source_excludes:
            pat = os.path.expanduser(pat)
            if pat.startswith("/"):
                # Strip a trailing slash so '/foo/' matches '/foo/bar' too.
                stripped = pat.rstrip("/")
                if p == stripped or p.startswith(stripped + "/"):
                    return True
                continue
            if any(ch in pat for ch in ("*", "?", "[")):
                if fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(base, pat):
                    return True
                # Also try matching the pattern with leading '*/' to allow
                # bare patterns like 'node_modules/' to hit anywhere in path.
                if fnmatch.fnmatch(p, "*/" + pat.rstrip("/") + "/*") or \
                   fnmatch.fnmatch(p, "*/" + pat.rstrip("/")):
                    return True
                continue
            # Plain string — substring match. Catches '__pycache__', '.git'.
            if pat in p:
                return True
        return False

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
