"""Tests for the `cli remediate` headless fix→verify loop.

Covers the CI-facing behavior without external scanners:
  - candidate selection (severity threshold + has-a-remediator filter)
  - the tier fork: Tier 1-2 never auto-applies (propose-only), even with --auto
  - propose does not mutate the working tree
"""
from __future__ import annotations

import json

import pytest

from ai_protect import cli
from ai_protect.core.findings import Category, FindingStore, Severity, new_finding


def _manifest(tmp_path, sensitivity: str) -> str:
    """Write a minimal manifest; data_sensitivity drives the tier
    (phi → Tier 1, public → Tier 4)."""
    p = tmp_path / "manifest.yml"
    p.write_text(
        "name: test-remediate-app\n"
        "owner: test@example.com\n"
        "on_call: test@example.com\n"
        f"data_sensitivity: {sensitivity}\n"
        "decision_impact: advisory\n"
        "integration_footprint: read_only\n"
        "user_population: single_user\n"
        f"source_path: {tmp_path}\n"
    )
    return str(p)


def _supply_chain_finding(severity=Severity.HIGH):
    return new_finding(
        app_name="test-remediate-app", tier=1, stage="build", adapter="pip_audit",
        category=Category.SUPPLY_CHAIN, severity=severity,
        title="urllib3 1.0.0 affected by CVE-TEST-0001",
        description="Vulnerable dependency.",
        evidence={"package": "urllib3", "fixed_in": ["2.0.0"],
                  "installed": "1.0.0", "vuln_id": "CVE-TEST-0001"},
    )


def _run(argv, capsys):
    try:
        cli.main(argv)
    except SystemExit:
        pass
    return json.loads(capsys.readouterr().out)


def test_tier1_proposes_only_even_with_auto(tmp_path, capsys):
    """Tier 1 (PHI) must NOT auto-apply even when --auto is passed — the fork."""
    (tmp_path / "requirements.txt").write_text("urllib3==1.0.0\n")
    manifest = _manifest(tmp_path, "phi")           # → Tier 1
    findings = tmp_path / "findings.jsonl"
    FindingStore(findings).append(_supply_chain_finding())

    out = _run(["--findings", str(findings), "remediate", manifest,
                "--auto", "--format", "json"], capsys)

    assert out["tier"] == 1
    assert out["auto_apply"] is False               # forced off for Tier 1-2
    assert out["candidates"] == 1
    assert out["outcomes"].get("proposed_awaiting_human") == 1
    # propose must not touch the working tree
    assert (tmp_path / "requirements.txt").read_text() == "urllib3==1.0.0\n"


def test_severity_threshold_filters(tmp_path, capsys):
    """A HIGH finding is excluded when the threshold is critical."""
    (tmp_path / "requirements.txt").write_text("urllib3==1.0.0\n")
    manifest = _manifest(tmp_path, "phi")
    findings = tmp_path / "findings.jsonl"
    FindingStore(findings).append(_supply_chain_finding(Severity.HIGH))

    out = _run(["--findings", str(findings), "remediate", manifest,
                "--severity", "critical", "--format", "json"], capsys)
    assert out["candidates"] == 0


def test_no_remediator_finding_is_skipped(tmp_path, capsys):
    """A finding no strategy handles is not a candidate (no crash)."""
    manifest = _manifest(tmp_path, "phi")
    findings = tmp_path / "findings.jsonl"
    FindingStore(findings).append(new_finding(
        app_name="test-remediate-app", tier=1, stage="build", adapter="garak",
        category=Category.JAILBREAK, severity=Severity.HIGH,
        title="jailbreak", description="no auto-fix for this class"))

    out = _run(["--findings", str(findings), "remediate", manifest,
                "--format", "json"], capsys)
    assert out["candidates"] == 0


# ---- CI deploy gate: --fail-on-severity (independent of per-adapter blocking) ----

import shutil  # noqa: E402


def test_fail_on_severity_high_exits_2(tmp_path):
    """A HIGH bandit finding fails the gate with --fail-on-severity high, even
    though bandit is NOT a `blocking` adapter in the policy table."""
    if not shutil.which("bandit"):
        pytest.skip("bandit not installed")
    (tmp_path / "v.py").write_text("import requests\nr = requests.get(u, verify=False)\n")
    manifest = _manifest(tmp_path, "public")          # → Tier 4
    findings = tmp_path / "f.jsonl"
    with pytest.raises(SystemExit) as ei:
        cli.main(["--findings", str(findings), "run", manifest, "--stage", "build",
                  "--adapter", "bandit", "--fail-on-severity", "high"])
    assert ei.value.code == 2


def test_no_flag_passes_gate_for_nonblocking_high(tmp_path):
    """Without --fail-on-severity, the same HIGH bandit finding does NOT fail the
    gate (bandit isn't blocking) — documents why the CI flag exists."""
    if not shutil.which("bandit"):
        pytest.skip("bandit not installed")
    (tmp_path / "v.py").write_text("import requests\nr = requests.get(u, verify=False)\n")
    manifest = _manifest(tmp_path, "public")
    findings = tmp_path / "f.jsonl"
    # no SystemExit (exit 0) expected
    cli.main(["--findings", str(findings), "run", manifest, "--stage", "build",
              "--adapter", "bandit"])
