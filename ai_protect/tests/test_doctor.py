"""Tests for `ai-protect doctor` — the environment + capability report.

Offline: every probe runs against a bundled stub manifest with timeouts, so
this never reaches the network and never hangs.
"""
from __future__ import annotations

from ai_protect.adapters.registry import REGISTRY
from ai_protect.core import doctor


def test_diagnose_structure_and_totals():
    report = doctor.diagnose()
    assert set(report) == {"environment", "adapters", "summary"}

    # one row per registered adapter, statuses partition cleanly
    assert report["summary"]["total"] == len(REGISTRY)
    assert len(report["adapters"]) == len(REGISTRY)
    s = report["summary"]
    assert s["live"] + s["needs_setup"] + s["mutation_gated"] == len(REGISTRY)

    env = report["environment"]
    for key in ("python", "data_home", "findings_path", "source_provider"):
        assert key in env


def test_builtin_adapters_are_live_with_zero_setup():
    # The pure-python policy/AI checks must work on a bare machine — that's the
    # whole "it just works out of the box" promise.
    report = doctor.diagnose()
    status = {a["name"]: a["status"] for a in report["adapters"]}
    for name in ("manifest_validator", "threat_model_check", "mcp_scope",
                 "intel_match", "eval_suite", "telemetry_drift"):
        assert status[name] == doctor.LIVE, f"{name} should be live, got {status[name]}"


def test_render_text_runs():
    report = doctor.diagnose()
    text = doctor.render_text(report)
    assert "ai-protect doctor" in text
    assert "Summary" in text
