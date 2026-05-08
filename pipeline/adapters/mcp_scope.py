"""MCP scope validator — the highest-leverage single control in the v2.1 plan.

What this validates:

  1. Tier inheritance: if the agent uses any MCP server tier T_min, the agent
     itself should be classified at least T_min. (Tier inheritance flows from
     MCP to calling agent.)

  2. Action allow-list: the agent should only be capable of invoking actions
     declared in the manifest's expected_actions. Anything beyond that is a
     scope violation.

  3. Side-effect classification: any mutating or irreversible action on a
     Tier 1 / Tier 2 MCP must require step-up auth or human-in-the-loop, per
     v2.1 §Agent Runtime Stage 2.

  4. Token scope: if the manifest provides a test agent token, attempt a probe
     call to a forbidden-by-scope action and confirm the broker rejects it.

This is a "policy as code" check — it does not need to call out to a LLM. It
reads the manifest, applies the rules, and emits findings. It IS the gate the
v2.1 doc names "highest-leverage" — agent registration scope.
"""
from __future__ import annotations

import logging
import os
import requests

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable

log = logging.getLogger("ai-protect.mcp_scope")


class MCPScopeAdapter(Adapter):
    name = "mcp_scope"
    description = "MCP scope validator — tier inheritance, action allow-list, side-effect, token scope"

    def preflight(self) -> None:
        super().preflight()
        # Always runs — no external tool dependency. Only requires manifest.

    def run(self):
        self.manifest_tier = classify(self.manifest).tier
        findings = []

        findings += self._check_tier_inheritance()
        findings += self._check_action_allowlist()
        findings += self._check_side_effects()
        findings += self._probe_token_scope()
        return findings

    def _check_tier_inheritance(self):
        """Agent tier must be ≤ min(MCP tiers used). (Tier 1 is most restrictive = lowest #.)"""
        out = []
        for mcp in self.manifest.mcp_servers:
            if self.manifest_tier > mcp.tier:
                out.append(self.make_finding(
                    tier=self.manifest_tier,
                    category=Category.SCOPE_VIOLATION,
                    severity=Severity.HIGH,
                    title=f"Tier inheritance violated for MCP {mcp.name!r}",
                    description=(
                        f"Agent classified Tier {self.manifest_tier} but uses MCP {mcp.name!r} "
                        f"which is Tier {mcp.tier}. Tier inheritance requires the agent to be "
                        f"at least as restrictive (Tier {mcp.tier}). Re-tier the agent."
                    ),
                    evidence={
                        "agent_tier": self.manifest_tier,
                        "mcp": mcp.name,
                        "mcp_tier": mcp.tier,
                    },
                    affected={"agent": self.manifest.name, "mcp": mcp.name},
                    remediation=(
                        "Either re-tier the agent to match the highest-tier MCP it consumes, "
                        "or remove the lower-tier MCP from the agent's allow-list."
                    ),
                ))
        return out

    def _check_action_allowlist(self):
        """Every MCP-exposed action used by the agent must appear in expected_actions."""
        out = []
        if not self.manifest.expected_actions:
            return out
        expected = set(self.manifest.expected_actions)
        exposed = {a for mcp in self.manifest.mcp_servers for a in mcp.actions}
        unexpected = exposed - expected
        for action in sorted(unexpected):
            mcp_owner = next((m.name for m in self.manifest.mcp_servers if action in m.actions), "unknown")
            out.append(self.make_finding(
                tier=self.manifest_tier,
                category=Category.SCOPE_VIOLATION,
                severity=Severity.MEDIUM,
                title=f"MCP action {action!r} exposed to agent but not in expected_actions",
                description=(
                    f"MCP {mcp_owner!r} exposes action {action!r} to the agent, but the "
                    "manifest does not declare it as an expected action. Either add it to "
                    "expected_actions (with justification), or restrict the MCP allow-list "
                    "for this agent."
                ),
                evidence={"action": action, "mcp": mcp_owner},
                affected={"mcp": mcp_owner},
                remediation=(
                    "Tighten the agent's MCP tool allow-list at registration. "
                    "Default-deny: agents should only see the tools they need."
                ),
            ))
        return out

    def _check_side_effects(self):
        """Tier 1 / Tier 2 mutating or irreversible actions need step-up / HITL."""
        out = []
        for mcp in self.manifest.mcp_servers:
            if mcp.tier > 2:
                continue
            if mcp.side_effects in ("mutating", "irreversible"):
                # Look for step-up auth declaration in the manifest's raw config.
                step_up = self.manifest.raw.get("step_up_auth", {})
                if mcp.name not in step_up.get("required_for", []):
                    out.append(self.make_finding(
                        tier=self.manifest_tier,
                        category=Category.SCOPE_VIOLATION,
                        severity=Severity.HIGH,
                        title=f"MCP {mcp.name!r} ({mcp.side_effects}) lacks step-up auth declaration",
                        description=(
                            f"MCP {mcp.name!r} is Tier {mcp.tier} with {mcp.side_effects} side "
                            "effects, but the manifest does not declare it under step_up_auth.required_for. "
                            "Per v2.1 §Agent Runtime Stage 2, mutating/irreversible actions on "
                            "Tier 1/2 MCPs must require step-up auth or human-in-the-loop."
                        ),
                        evidence={"mcp": mcp.name, "side_effects": mcp.side_effects, "mcp_tier": mcp.tier},
                        affected={"mcp": mcp.name},
                        remediation=(
                            "Add the MCP to step_up_auth.required_for in the manifest, and ensure "
                            "the agent runtime enforces step-up via the gateway."
                        ),
                    ))
        return out

    def _probe_token_scope(self):
        """If a test token + agent runtime URL is configured, attempt a forbidden call."""
        out = []
        token_env = self.manifest.target.test_user_token_env
        api_url = self.manifest.target.api_url
        if not (token_env and api_url):
            return out
        token = os.environ.get(token_env)
        if not token:
            log.info("MCP scope probe: %s not set in env, skipping live token test", token_env)
            return out
        # Pick an action NOT in expected_actions (forbidden by scope).
        expected = set(self.manifest.expected_actions)
        forbidden_candidates = [
            a for mcp in self.manifest.mcp_servers
            for a in mcp.actions
            if a not in expected
        ]
        if not forbidden_candidates:
            return out
        target_action = forbidden_candidates[0]
        try:
            r = requests.post(
                f"{api_url.rstrip('/')}/tool/{target_action}",
                headers={"Authorization": f"Bearer {token}"},
                json={"_probe": "ai-protect mcp_scope"},
                timeout=15,
            )
        except requests.RequestException as e:
            log.warning("MCP scope probe network error: %s", e)
            return out
        if r.status_code in (401, 403):
            # Correctly rejected — record as control validation evidence.
            out.append(self.make_finding(
                tier=self.manifest_tier,
                category=Category.SCOPE_VIOLATION,
                severity=Severity.INFO,
                title=f"Token scope correctly rejected forbidden action {target_action!r}",
                description=(
                    f"Test token attempted {target_action!r} (not in expected_actions); "
                    f"broker returned {r.status_code}. Scope enforcement validated."
                ),
                evidence={"action": target_action, "status_code": r.status_code},
                affected={"agent": self.manifest.name},
            ))
        else:
            out.append(self.make_finding(
                tier=self.manifest_tier,
                category=Category.SCOPE_VIOLATION,
                severity=Severity.CRITICAL,
                title=f"Token scope FAILED to reject forbidden action {target_action!r}",
                description=(
                    f"Test token successfully invoked {target_action!r} which is NOT declared "
                    "in expected_actions. Scope enforcement is broken — any compromised agent "
                    "or token can reach this action. This is the bypass v2.1 names as the "
                    "highest-leverage failure mode."
                ),
                evidence={
                    "action": target_action,
                    "status_code": r.status_code,
                    "response_excerpt": r.text[:500],
                },
                affected={"agent": self.manifest.name, "broker": api_url},
                remediation=(
                    "Fix the agent runtime broker's scope enforcement immediately. "
                    "Verify token claims contain the action allow-list and that the broker "
                    "checks claims before forwarding to the MCP server."
                ),
            ))
        return out
