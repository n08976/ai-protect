from ai_protect.core.policy import POLICY, STAGES, adapters_for


def test_every_tier_has_intake():
    for tier in (1, 2, 3, 4):
        calls = adapters_for(tier, "intake")
        assert any(c.adapter == "manifest_validator" and c.blocking for c in calls), (
            f"Tier {tier} must have a blocking manifest_validator at intake"
        )


def test_tier_1_preprod_has_mcp_scope_blocking():
    calls = adapters_for(1, "preprod")
    by_name = {c.adapter: c for c in calls}
    assert "mcp_scope" in by_name
    assert by_name["mcp_scope"].blocking


def test_tier_4_has_no_red_team_in_build():
    """Tier 4 should be paved-road template + secret scanning only."""
    calls = adapters_for(4, "build")
    names = {c.adapter for c in calls}
    assert "garak" not in names
    assert "pyrit" not in names
    assert "atomic" not in names


def test_unknown_stage_raises():
    import pytest
    with pytest.raises(ValueError):
        adapters_for(1, "deploy-someday")


def test_all_stages_covered_in_each_tier():
    for tier in (1, 2, 3, 4):
        for stage in STAGES:
            # Should not raise; empty list is fine for stages where no adapters run.
            adapters_for(tier, stage)
