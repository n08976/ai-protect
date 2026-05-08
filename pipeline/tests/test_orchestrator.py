from pathlib import Path

import pytest

from pipeline.core.findings import FindingStore
from pipeline.core.manifest import Manifest
from pipeline.core.orchestrator import Orchestrator


REPO = Path(__file__).resolve().parent.parent.parent
MANIFESTS = REPO / "pipeline" / "manifests"


def test_dry_run_clinical_all_stages(tmp_path):
    m = Manifest.from_yaml(MANIFESTS / "example_clinical_assistant.yml")
    store = FindingStore(tmp_path / "f.jsonl")
    orc = Orchestrator(m, store, dry_run=True)
    results = orc.run_all_stages()
    # Tier 1 has adapters at every stage -> 5 stage results, all dry-run skipped.
    assert len(results) == 5
    for r in results:
        assert r.gate_passed
        for ar in r.adapter_results:
            assert ar.status == "skipped"


def test_intake_validates_phi_without_baa_blocks(tmp_path):
    """A manifest declaring PHI but a non-BAA model should fail intake."""
    m = Manifest.from_yaml(MANIFESTS / "example_clinical_assistant.yml")
    # Strip BAA coverage to force the manifest_validator to fail.
    m.models[0].baa_covered = False
    store = FindingStore(tmp_path / "f.jsonl")
    orc = Orchestrator(m, store, dry_run=False)
    result = orc.run_stage("intake")
    assert not result.gate_passed
    assert "manifest_validator" in (result.gate_reason or "")


def test_mcp_scope_runs_without_external_tools(tmp_path):
    """MCP scope adapter is policy-as-code; should always run."""
    m = Manifest.from_yaml(MANIFESTS / "example_clinical_assistant.yml")
    store = FindingStore(tmp_path / "f.jsonl")
    orc = Orchestrator(m, store, dry_run=False)
    result = orc.run_stage("preprod")
    # mcp_scope is in the Tier 1 preprod policy.
    by_name = {ar.adapter: ar for ar in result.adapter_results}
    assert "mcp_scope" in by_name
    assert by_name["mcp_scope"].status in ("ok",)


def test_low_risk_tier_4_minimal_pipeline(tmp_path):
    m = Manifest.from_yaml(MANIFESTS / "example_low_risk_assistive.yml")
    store = FindingStore(tmp_path / "f.jsonl")
    orc = Orchestrator(m, store, dry_run=True)
    result = orc.run_stage("build")
    # Tier 4 build has just trufflehog
    names = [ar.adapter for ar in result.adapter_results]
    assert names == ["trufflehog"]
