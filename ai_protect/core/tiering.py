"""Risk-tier classifier.

Implements the v2.1 four-tier framework. Scores four dimensions and returns
the resulting tier. The tier drives engagement pattern, adapter selection,
and the depth of human review.

Tier 1 — PHI / clinical / external-facing. Embedded review, manual red team.
Tier 2 — Sensitive internal action / write-back. Embedded review.
Tier 3 — Internal advisory with broad reach. Async checklist + automated red team.
Tier 4 — Low-impact assistive. Paved-road template + automated scanning only.
"""
from __future__ import annotations

from dataclasses import dataclass

from .manifest import Manifest


# Per-dimension scores. Higher = riskier.
DATA_SENSITIVITY_SCORES = {
    "phi": 4,
    "pii": 3,
    "financial": 3,
    "confidential": 2,
    "public": 1,
}

DECISION_IMPACT_SCORES = {
    "irreversible": 4,
    "clinical_influence": 4,
    "automated_action": 3,
    "advisory": 1,
}

INTEGRATION_SCORES = {
    "external_action": 4,
    "agent_tool_use": 3,
    "write_back": 3,
    "read_only": 1,
}

USER_POPULATION_SCORES = {
    "external": 4,
    "enterprise": 2,
    "team": 2,
    "single_user": 1,
}


@dataclass
class TierDecision:
    tier: int
    score: int
    dimensions: dict[str, int]
    rationale: list[str]
    forced_to_tier_1: bool = False
    forced_reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "tier": self.tier,
            "score": self.score,
            "dimensions": self.dimensions,
            "rationale": self.rationale,
            "forced_to_tier_1": self.forced_to_tier_1,
            "forced_reason": self.forced_reason,
        }


def _resolve_all(value: str | None, scores: dict[str, int]) -> str:
    """If the operator declared 'all' (the meta-option meaning 'this dimension
    spans every value'), resolve to the highest-risk concrete value so the
    forced-Tier-1 rules and the score arithmetic see something meaningful.
    Any other value passes through unchanged."""
    if value != "all":
        return value or ""
    # Highest-scoring value in this dim — i.e. the most-restrictive label.
    return max(scores.items(), key=lambda kv: kv[1])[0]


def classify(manifest: Manifest) -> TierDecision:
    """Classify a manifest into a tier 1-4. Force to Tier 1 on PHI or clinical impact.

    'all' on any dimension is resolved to that dimension's most-restrictive
    value before scoring — it means 'this app spans every value here; tier
    conservatively at the top'.
    """
    ds = _resolve_all(manifest.data_sensitivity, DATA_SENSITIVITY_SCORES)
    di = _resolve_all(manifest.decision_impact, DECISION_IMPACT_SCORES)
    fp = _resolve_all(manifest.integration_footprint, INTEGRATION_SCORES)
    up = _resolve_all(manifest.user_population, USER_POPULATION_SCORES)

    dims = {
        "data_sensitivity": DATA_SENSITIVITY_SCORES.get(ds, 2),
        "decision_impact": DECISION_IMPACT_SCORES.get(di, 2),
        "integration_footprint": INTEGRATION_SCORES.get(fp, 2),
        "user_population": USER_POPULATION_SCORES.get(up, 2),
    }
    score = sum(dims.values())

    rationale: list[str] = []
    # Show the resolved value alongside 'all' so the audit trail explains the
    # tier without referencing the meta-option.
    def _label(declared: str | None, resolved: str) -> str:
        return f"{declared} (→ {resolved})" if declared == "all" else (declared or "")
    rationale.append(
        f"data_sensitivity={_label(manifest.data_sensitivity, ds)} "
        f"({dims['data_sensitivity']}/4)"
    )
    rationale.append(
        f"decision_impact={_label(manifest.decision_impact, di)} "
        f"({dims['decision_impact']}/4)"
    )
    rationale.append(
        f"integration_footprint={_label(manifest.integration_footprint, fp)} "
        f"({dims['integration_footprint']}/4)"
    )
    rationale.append(
        f"user_population={_label(manifest.user_population, up)} "
        f"({dims['user_population']}/4)"
    )

    forced = False
    forced_reason = None
    if ds == "phi":
        forced = True
        forced_reason = "PHI handling forces Tier 1 regardless of score (HIPAA/HITRUST baseline)."
    elif di == "clinical_influence":
        forced = True
        forced_reason = "Clinical decision influence forces Tier 1 (FDA SaMD reclassification risk)."
    elif up == "external" and di != "advisory":
        forced = True
        forced_reason = "External-facing with non-advisory impact forces Tier 1."

    if forced:
        tier = 1
    else:
        # Score-based bucketing
        if score >= 13:
            tier = 1
        elif score >= 9:
            tier = 2
        elif score >= 6:
            tier = 3
        else:
            tier = 4

    # Tier inheritance from MCP servers — highest wins
    if manifest.mcp_servers:
        max_mcp_tier = min(m.tier for m in manifest.mcp_servers)  # tier 1 is most restrictive
        if max_mcp_tier < tier:
            rationale.append(
                f"Tier inheritance from MCP servers: lifted to Tier {max_mcp_tier} "
                f"(MCP {min(manifest.mcp_servers, key=lambda m: m.tier).name!r})"
            )
            tier = max_mcp_tier

    return TierDecision(
        tier=tier,
        score=score,
        dimensions=dims,
        rationale=rationale,
        forced_to_tier_1=forced,
        forced_reason=forced_reason,
    )
