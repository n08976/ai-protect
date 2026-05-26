"""Adapter-level tests for the OWASP-list / DAST-list batch wires.

Offline tests: registry wiring, preflight gates, mutation gate where applicable.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from pipeline.adapters.agentic_radar import AgenticRadarAdapter
from pipeline.adapters.base import AdapterAuthorizationRequired, AdapterUnavailable
from pipeline.adapters.gosec import GosecAdapter
from pipeline.adapters.owasp_noir import OWASPNoirAdapter
from pipeline.adapters.registry import REGISTRY
from pipeline.adapters.ride import RideAdapter
from pipeline.core.manifest import Manifest


REPO = Path(__file__).resolve().parent.parent.parent
MANIFESTS = REPO / "pipeline" / "manifests"


def _clinical(allow_mutation: bool = True) -> Manifest:
    m = Manifest.from_yaml(MANIFESTS / "SAMPLE-clinical-assistant-prototype.yml")
    m.target.allow_mutation = allow_mutation
    return m


@pytest.mark.parametrize("name,cls", [
    ("agentic_radar", AgenticRadarAdapter),
    ("owasp_noir", OWASPNoirAdapter),
    ("gosec", GosecAdapter),
    ("ride", RideAdapter),
])
def test_adapter_registered(name, cls):
    assert name in REGISTRY
    assert REGISTRY[name] is cls


@pytest.mark.parametrize("cls,bin_name", [
    (AgenticRadarAdapter, "agentic-radar"),
    (OWASPNoirAdapter, "noir"),
    (GosecAdapter, "gosec"),
])
def test_sast_adapters_unavailable_when_cli_missing(cls, bin_name, monkeypatch):
    """Without the CLI binary on PATH, adapter must raise AdapterUnavailable."""
    if shutil.which(bin_name):
        pytest.skip(f"{bin_name} present on PATH; skipping unavailable check")
    m = _clinical(allow_mutation=False)
    adapter = cls(m, stage="build", config={})
    with pytest.raises(AdapterUnavailable):
        adapter.preflight()


def test_ride_requires_mutation(monkeypatch):
    monkeypatch.setenv("RIDE_TEST_PATH", "/tmp/no-such-suite")
    m = _clinical(allow_mutation=False)
    adapter = RideAdapter(m, stage="preprod", config={})
    with pytest.raises(AdapterAuthorizationRequired):
        adapter.preflight()


def test_ride_requires_test_path(monkeypatch):
    if not shutil.which("mvn"):
        pytest.skip("mvn not on PATH; ride preflight tripped earlier than test_path check")
    monkeypatch.delenv("RIDE_TEST_PATH", raising=False)
    m = _clinical(allow_mutation=True)
    adapter = RideAdapter(m, stage="preprod", config={})
    with pytest.raises(AdapterUnavailable, match="RIDE_TEST_PATH"):
        adapter.preflight()


def test_gosec_no_go_files_returns_empty(tmp_path, monkeypatch):
    """gosec must graceful-degrade when source tree has zero .go files."""
    if not shutil.which("gosec"):
        pytest.skip("gosec not installed")
    (tmp_path / "main.py").write_text("print('hello')\n")
    m = _clinical(allow_mutation=False)
    m.raw["source_path"] = str(tmp_path)
    adapter = GosecAdapter(m, stage="build", config={"path": str(tmp_path)})
    assert adapter.run() == []


def test_new_adapters_in_policy():
    """Confirm policy table includes new adapters where intended."""
    from pipeline.core.policy import adapters_for
    t1_intake = {c.adapter for c in adapters_for(1, "intake")}
    t1_build = {c.adapter for c in adapters_for(1, "build")}
    t1_preprod = {c.adapter for c in adapters_for(1, "preprod")}
    assert "owasp_noir" in t1_intake
    assert "gosec" in t1_build
    assert "agentic_radar" in t1_build
    assert "ride" in t1_preprod
