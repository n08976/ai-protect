"""Adapter-level tests for the Caldera integration.

These tests stay offline — no Caldera server required. They verify registry
wiring, the mutation/authorization gate, the env-var preflight, and the
adversary_id requirement.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.adapters.base import AdapterAuthorizationRequired, AdapterUnavailable
from pipeline.adapters.caldera import CalderaAdapter
from pipeline.adapters.registry import REGISTRY
from pipeline.core.manifest import Manifest


REPO = Path(__file__).resolve().parent.parent.parent
MANIFESTS = REPO / "pipeline" / "manifests"


def _clinical_manifest(allow_mutation: bool = True) -> Manifest:
    m = Manifest.from_yaml(MANIFESTS / "SAMPLE-clinical-assistant-prototype.yml")
    m.target.allow_mutation = allow_mutation
    return m


def test_caldera_is_registered():
    assert "caldera" in REGISTRY
    assert REGISTRY["caldera"] is CalderaAdapter


def test_caldera_requires_mutation(monkeypatch):
    """Manifest without allow_mutation must trip the authorization gate."""
    monkeypatch.setenv("CALDERA_API_URL", "http://caldera.example:8888")
    monkeypatch.setenv("CALDERA_API_KEY", "test")
    m = _clinical_manifest(allow_mutation=False)
    adapter = CalderaAdapter(m, stage="preprod", config={"adversary_id": "abc"})
    with pytest.raises(AdapterAuthorizationRequired):
        adapter.preflight()


def test_caldera_requires_api_url(monkeypatch):
    monkeypatch.delenv("CALDERA_API_URL", raising=False)
    monkeypatch.setenv("CALDERA_API_KEY", "test")
    m = _clinical_manifest(allow_mutation=True)
    adapter = CalderaAdapter(m, stage="preprod", config={"adversary_id": "abc"})
    with pytest.raises(AdapterUnavailable, match="CALDERA_API_URL"):
        adapter.preflight()


def test_caldera_requires_api_key(monkeypatch):
    monkeypatch.setenv("CALDERA_API_URL", "http://caldera.example:8888")
    monkeypatch.delenv("CALDERA_API_KEY", raising=False)
    m = _clinical_manifest(allow_mutation=True)
    adapter = CalderaAdapter(m, stage="preprod", config={"adversary_id": "abc"})
    with pytest.raises(AdapterUnavailable, match="CALDERA_API_KEY"):
        adapter.preflight()


def test_caldera_requires_adversary_id(monkeypatch):
    monkeypatch.setenv("CALDERA_API_URL", "http://caldera.example:8888")
    monkeypatch.setenv("CALDERA_API_KEY", "test")
    m = _clinical_manifest(allow_mutation=True)
    adapter = CalderaAdapter(m, stage="preprod", config={})
    with pytest.raises(AdapterUnavailable, match="adversary_id"):
        adapter.preflight()


def test_caldera_in_tier_1_and_2_preprod_only():
    """Caldera is SCV-shape; only Tier 1 / 2 preprod should run it."""
    from pipeline.core.policy import adapters_for
    t1 = {c.adapter for c in adapters_for(1, "preprod")}
    t2 = {c.adapter for c in adapters_for(2, "preprod")}
    t3 = {c.adapter for c in adapters_for(3, "preprod")}
    t4 = {c.adapter for c in adapters_for(4, "preprod")}
    assert "caldera" in t1
    assert "caldera" in t2
    assert "caldera" not in t3
    assert "caldera" not in t4
