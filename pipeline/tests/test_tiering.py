from pipeline.core.manifest import Manifest
from pipeline.core.tiering import classify


def _m(**overrides) -> Manifest:
    base = {
        "name": "test-app",
        "owner": "owner@example.com",
        "on_call": "oncall@example.com",
        "description": "test",
        "data_sensitivity": "confidential",
        "decision_impact": "advisory",
        "integration_footprint": "read_only",
        "user_population": "team",
    }
    base.update(overrides)
    return Manifest.from_dict(base)


def test_phi_forces_tier_1():
    m = _m(data_sensitivity="phi")
    d = classify(m)
    assert d.tier == 1
    assert d.forced_to_tier_1
    assert "PHI" in d.forced_reason


def test_clinical_influence_forces_tier_1():
    m = _m(decision_impact="clinical_influence")
    d = classify(m)
    assert d.tier == 1
    assert d.forced_to_tier_1


def test_external_non_advisory_forces_tier_1():
    m = _m(user_population="external", decision_impact="automated_action")
    d = classify(m)
    assert d.tier == 1


def test_low_risk_lands_tier_4():
    m = _m(
        data_sensitivity="public",
        decision_impact="advisory",
        integration_footprint="read_only",
        user_population="single_user",
    )
    d = classify(m)
    assert d.tier == 4
    assert not d.forced_to_tier_1


def test_internal_advisory_team_is_tier_3_or_4():
    m = _m(
        data_sensitivity="confidential",
        decision_impact="advisory",
        integration_footprint="read_only",
        user_population="team",
    )
    d = classify(m)
    assert d.tier in (3, 4)


def test_mcp_tier_inheritance_lifts_tier():
    m = _m(
        data_sensitivity="confidential",
        decision_impact="advisory",
        integration_footprint="read_only",
        user_population="single_user",
        mcp_servers=[{
            "name": "phi-mcp",
            "tier": 1,
            "data_scope": "phi",
            "actions": ["read_chart"],
            "side_effects": "read_only",
        }],
    )
    d = classify(m)
    assert d.tier == 1
