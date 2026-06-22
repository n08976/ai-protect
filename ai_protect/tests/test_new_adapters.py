"""Adapter-level tests for the OWASP-list / DAST-list batch wires.

Offline tests: registry wiring, preflight gates, mutation gate where applicable.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from ai_protect.adapters.agentic_radar import AgenticRadarAdapter
from ai_protect.adapters.base import AdapterAuthorizationRequired, AdapterUnavailable
from ai_protect.adapters.gosec import GosecAdapter
from ai_protect.adapters.owasp_noir import OWASPNoirAdapter
from ai_protect.adapters.registry import REGISTRY
from ai_protect.adapters.ride import RideAdapter
from ai_protect.core.manifest import Manifest


REPO = Path(__file__).resolve().parent.parent.parent
MANIFESTS = REPO / "ai_protect" / "manifests"


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
    monkeypatch.setenv("RIDE_TEST_PATH", "/tmp/no-such-suite")  # nosec B108 — test stub path, never created
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
    from ai_protect.core.policy import adapters_for
    t1_intake = {c.adapter for c in adapters_for(1, "intake")}
    t1_build = {c.adapter for c in adapters_for(1, "build")}
    t1_preprod = {c.adapter for c in adapters_for(1, "preprod")}
    assert "owasp_noir" in t1_intake
    assert "gosec" in t1_build
    assert "agentic_radar" in t1_build
    assert "ride" in t1_preprod


# ---- HexStrike-list DAST batch: nikto / dalfox / wpscan / commix / nosqlmap / tplmap ----

from ai_protect.adapters.commix import CommixAdapter
from ai_protect.adapters.dalfox import DalfoxAdapter
from ai_protect.adapters.nikto import NiktoAdapter
from ai_protect.adapters.nosqli import NosqliAdapter
from ai_protect.adapters.tplmap import TplmapAdapter
from ai_protect.adapters.wpscan import WPScanAdapter


@pytest.mark.parametrize("name,cls", [
    ("nikto", NiktoAdapter),
    ("dalfox", DalfoxAdapter),
    ("wpscan", WPScanAdapter),
    ("commix", CommixAdapter),
    ("nosqli", NosqliAdapter),
    ("tplmap", TplmapAdapter),
])
def test_dast_batch_registered(name, cls):
    assert name in REGISTRY
    assert REGISTRY[name] is cls


@pytest.mark.parametrize("cls,bin_name", [
    (NiktoAdapter, "nikto"),
    (DalfoxAdapter, "dalfox"),
    (WPScanAdapter, "wpscan"),
])
def test_dast_scanners_unavailable_when_cli_missing(cls, bin_name):
    """Non-mutating scanners must raise AdapterUnavailable when the CLI is absent."""
    if shutil.which(bin_name):
        pytest.skip(f"{bin_name} present on PATH; skipping unavailable check")
    m = _clinical(allow_mutation=True)
    adapter = cls(m, stage="preprod", config={})
    with pytest.raises(AdapterUnavailable):
        adapter.preflight()


@pytest.mark.parametrize("cls", [CommixAdapter, NosqliAdapter, TplmapAdapter])
def test_injectors_require_mutation(cls):
    """Active injectors must refuse before touching the target when mutation is off.

    The mutation gate lives in base.preflight() and fires regardless of whether
    the CLI binary is installed."""
    assert cls.requires_mutation is True
    m = _clinical(allow_mutation=False)
    adapter = cls(m, stage="preprod", config={})
    with pytest.raises(AdapterAuthorizationRequired):
        adapter.preflight()


def test_dast_batch_in_tier1_preprod_policy():
    from ai_protect.core.policy import adapters_for
    t1_preprod = {c.adapter for c in adapters_for(1, "preprod")}
    for name in ("nikto", "dalfox", "wpscan", "commix", "nosqli", "tplmap"):
        assert name in t1_preprod


def test_every_registered_adapter_has_catalog_entry():
    """Registry and UI catalog must not drift: a missing catalog entry makes
    mode_for() fall back to SAST, silently misclassifying the adapter in the
    /scan SAST/DAST split."""
    from ai_protect.adapters.registry import REGISTRY
    from ai_protect.ui.catalog import CATALOG
    missing = sorted(set(REGISTRY) - set(CATALOG))
    assert not missing, f"adapters missing from ai_protect/ui/catalog.py: {missing}"


def test_dast_batch_classified_as_dast():
    """The HexStrike-mined web/injection adapters must classify as DAST, not SAST."""
    from ai_protect.core import scan_modes as sm
    for name in ("nikto", "dalfox", "wpscan", "commix", "nosqli", "tplmap"):
        assert sm.is_dast_adapter(name), f"{name} should be DAST, got {sm.mode_for(name)}"
        assert not sm.is_sast_adapter(name)


# ---- Parser contract tests: pin the tool output schemas these adapters rely on ----

def _scoped_mut() -> Manifest:
    m = _clinical(allow_mutation=True)
    m.target.base_url = "http://127.0.0.1:9/app/?id=1"  # scoped so bare-origin policy passes
    return m


def test_dalfox_v3_wrapper_parses(monkeypatch):
    """dalfox v3 emits {"meta":..., "findings":[...]} — confirm we read the wrapper."""
    import shutil as _sh
    import subprocess
    # Parser test, not a preflight test: make the CLI look installed so preflight
    # passes whether or not dalfox is actually on PATH (e.g. CI runners).
    monkeypatch.setattr(_sh, "which", lambda name, *a, **k: "/usr/local/bin/" + name)
    sample = (
        '{"meta": {"dalfox_version": "3.0.2", "findings_count": 1}, "findings": ['
        '{"type": "V", "inject_type": "inHTML", "method": "GET", '
        '"data": "http://127.0.0.1:9/app/?id=1", "param": "id", '
        '"payload": "<script>alert(1)</script>", "evidence": "12 line", '
        '"cwe": "CWE-79", "severity": "High", "message_id": 1, '
        '"message_str": "reflected XSS", "location": "Query"}]}'
    )

    class P:
        stdout, stderr = sample, ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())
    adapter = DalfoxAdapter(_scoped_mut(), stage="preprod", config={})
    findings = adapter.run()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity.name == "HIGH"
    assert "id" in f.title
    assert f.evidence["cwe"] == "CWE-79"
    assert "verified XSS" in f.title  # FindingType "V" decoded


def test_nosqli_block_parses(monkeypatch):
    """nosqli prints 'Found <type>:\\n\\tURL:..\\n\\tparam:..\\n\\tInjection:..' per hit."""
    import shutil as _sh
    import subprocess
    monkeypatch.setattr(_sh, "which", lambda name, *a, **k: "/usr/local/bin/" + name)
    sample = (
        "Running Error based scan...\n"
        "Running GET parameter scan...\n"
        "Found Error based NoSQL Injection:\n"
        "\tURL: http://127.0.0.1:9/app/?id=1\n"
        "\tparam: id\n"
        "\tInjection: id=1'\n\n"
    )

    class P:
        stdout, stderr = sample, ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())
    adapter = NosqliAdapter(_scoped_mut(), stage="preprod", config={})
    findings = adapter.run()
    assert len(findings) == 1
    assert "Error based NoSQL Injection" in findings[0].title
    assert findings[0].evidence["param"] == "id"
    # The 'Running ... scan...' progress lines must NOT produce findings.
