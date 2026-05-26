"""Tests for the extended ZAP adapter modes (baseline, full, api)."""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.adapters.base import AdapterAuthorizationRequired, AdapterUnavailable
from pipeline.adapters.zap import MUTATING_MODES, SUPPORTED_MODES, ZAPAdapter
from pipeline.core.manifest import Manifest


REPO = Path(__file__).resolve().parent.parent.parent
MANIFESTS = REPO / "pipeline" / "manifests"


def _clinical(allow_mutation: bool = False) -> Manifest:
    m = Manifest.from_yaml(MANIFESTS / "SAMPLE-clinical-assistant-prototype.yml")
    m.target.allow_mutation = allow_mutation
    # Give the test target a non-root path so the bare-origin refusal added
    # in ZAP's preflight (crawlers refuse to walk a whole origin without an
    # explicit scope prefix) doesn't fire. These tests exercise the
    # requires_mutation / mode-validity gates, not crawler scope policy.
    if m.target.base_url:
        from urllib.parse import urlparse
        if urlparse(m.target.base_url).path in ("", "/"):
            m.target.base_url = m.target.base_url.rstrip("/") + "/app/"
    return m


@pytest.mark.parametrize("mode", ["spider", "baseline"])
def test_zap_passive_modes_dont_require_mutation(monkeypatch, mode):
    monkeypatch.setenv("ZAP_API_URL", "http://zap.example:8090")
    m = _clinical(allow_mutation=False)
    adapter = ZAPAdapter(m, stage="preprod", config={"mode": mode})
    # Should not trip the mutation gate; preflight should reach env-var check.
    adapter.preflight()


@pytest.mark.parametrize("mode", MUTATING_MODES)
def test_zap_mutating_modes_require_mutation(monkeypatch, mode):
    monkeypatch.setenv("ZAP_API_URL", "http://zap.example:8090")
    m = _clinical(allow_mutation=False)
    adapter = ZAPAdapter(m, stage="preprod", config={"mode": mode})
    with pytest.raises(AdapterAuthorizationRequired):
        adapter.preflight()


def test_zap_unknown_mode_rejected(monkeypatch):
    monkeypatch.setenv("ZAP_API_URL", "http://zap.example:8090")
    m = _clinical(allow_mutation=True)
    adapter = ZAPAdapter(m, stage="preprod", config={"mode": "no-such-mode"})
    with pytest.raises(AdapterUnavailable, match="Unknown ZAP mode"):
        adapter.preflight()


def test_zap_supported_modes_complete():
    """Every documented mode is listed in SUPPORTED_MODES."""
    for mode in ("spider", "baseline", "active", "ascan", "full", "api"):
        assert mode in SUPPORTED_MODES


def test_zap_api_mode_resolves_spec_url(monkeypatch):
    """In api mode without an explicit api_spec_url config, adapter falls back
    to <target.api_url>/openapi.json."""
    monkeypatch.setenv("ZAP_API_URL", "http://zap.example:8090")
    m = _clinical(allow_mutation=True)
    adapter = ZAPAdapter(m, stage="preprod", config={"mode": "api"})
    # Clinical manifest has target.api_url set.
    resolved = adapter._resolve_api_spec_url()
    assert resolved is not None
    assert resolved.endswith("/openapi.json")


def test_zap_api_mode_explicit_spec_wins(monkeypatch):
    monkeypatch.setenv("ZAP_API_URL", "http://zap.example:8090")
    m = _clinical(allow_mutation=True)
    explicit = "https://specs.example/v1/openapi.json"
    adapter = ZAPAdapter(
        m, stage="preprod",
        config={"mode": "api", "api_spec_url": explicit},
    )
    assert adapter._resolve_api_spec_url() == explicit


def test_zap_policy_includes_api_mode_at_tier_1():
    """Policy table — Tier 1 preprod runs zap in both full and api modes."""
    from pipeline.core.policy import adapters_for
    calls = adapters_for(1, "preprod")
    zap_modes = [c.config.get("mode") for c in calls if c.adapter == "zap"]
    assert "full" in zap_modes
    assert "api" in zap_modes


def test_zap_policy_baseline_for_low_tiers():
    """Policy table — Tier 2 / 3 preprod uses baseline (passive vuln scan), not just spider."""
    from pipeline.core.policy import adapters_for
    for tier in (2, 3):
        calls = adapters_for(tier, "preprod")
        zap_calls = [c for c in calls if c.adapter == "zap"]
        if zap_calls:
            assert any(c.config.get("mode") == "baseline" for c in zap_calls)
