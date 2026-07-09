"""Tests for `ai-protect doctor` — the environment + capability report.

Offline: every probe runs against a bundled stub manifest with timeouts, so
this never reaches the network and never hangs.
"""
from __future__ import annotations

import time

from ai_protect.adapters.registry import REGISTRY
from ai_protect.core import doctor
from ai_protect.core.manifest import Manifest


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


def test_probe_honors_per_adapter_timeout():
    # An adapter whose preflight runs longer than the default cap but under its
    # declared budget must still probe to completion (not flap to "timed out").
    # presidio is the real case — its model load overruns the 6 s default.
    class SlowAdapter:
        doctor_probe_timeout = doctor._PROBE_TIMEOUT + 3.0

        def __init__(self, *a, **kw):
            pass

        def preflight(self):
            time.sleep(doctor._PROBE_TIMEOUT + 1.0)

    manifest = doctor._stub_manifest() or Manifest.from_yaml(doctor._SAMPLE)
    status = doctor._probe("slow-probe", SlowAdapter, manifest)
    assert status.status == doctor.LIVE

    # And the tight default still applies when no override is declared.
    class HangingAdapter(SlowAdapter):
        doctor_probe_timeout = None

    status = doctor._probe("hanging-probe", HangingAdapter, manifest)
    assert status.status == doctor.NEEDS_SETUP
    assert "timed out" in status.detail


def test_presidio_declares_a_longer_probe_budget():
    from ai_protect.adapters.presidio import PresidioAdapter
    assert getattr(PresidioAdapter, "doctor_probe_timeout", 0) > doctor._PROBE_TIMEOUT


def test_render_text_runs():
    report = doctor.diagnose()
    text = doctor.render_text(report)
    assert "ai-protect doctor" in text
    assert "Summary" in text
