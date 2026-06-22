"""Regression test for engine.rescan verification.

Pilot caught the bug: `cleared` compared the original finding's fingerprint
against the *accumulated* append-only findings store (which always still
contains the original row), so a fix could never verify and was always reverted.
The correct check is whether the FRESH re-scan re-emits the finding.
"""
from __future__ import annotations

from ai_protect.core.findings import Category, FindingStore, Severity, new_finding
from ai_protect.core.manifest import Manifest
from ai_protect.remediate import engine as eng_mod
from ai_protect.remediate.engine import Engine
from ai_protect.remediate.state import (
    Change, ChangeState, ChangeStore, EventStore, new_change_id,
)


def _engine(tmp_path, store, monkeypatch, run_returns):
    m = tmp_path / "m.yml"
    m.write_text(
        "name: app\nowner: a@b.c\non_call: a@b.c\n"
        "data_sensitivity: public\ndecision_impact: advisory\n"
        "integration_footprint: read_only\nuser_population: single_user\n"
        f"source_path: {tmp_path}\n")

    class FakeAdapter:
        def __init__(self, *a, **k):
            pass

        def run(self):
            return run_returns

    monkeypatch.setattr(eng_mod, "get_adapter_class", lambda name: FakeAdapter)
    return Engine(Manifest.from_yaml(m), store,
                  change_store=ChangeStore(tmp_path / "c.jsonl"),
                  event_store=EventStore(tmp_path / "e.jsonl"))


def _finding():
    return new_finding(app_name="app", tier=4, stage="build", adapter="fake",
                       category=Category.INFRA_VULN, severity=Severity.HIGH,
                       title="X", description="")


def _applied_change(finding):
    return Change(change_id=new_change_id(), finding_id=finding.finding_id,
                  finding_fingerprint=finding.fingerprint, app_name="app", tier=4,
                  strategy="t", state=ChangeState.APPLIED, confidence=0.9,
                  summary="s", rescan_adapter="fake")


def test_rescan_verifies_when_finding_gone(tmp_path, monkeypatch):
    store = FindingStore(tmp_path / "f.jsonl")
    f = _finding()
    store.append(f)
    eng = _engine(tmp_path, store, monkeypatch, run_returns=[])   # vuln gone
    ch = _applied_change(f)
    eng.changes.write(ch)
    out, summary = eng.rescan(ch.change_id, actor="auto")
    assert summary["original_cleared"] is True
    assert out.state == ChangeState.VALIDATED


def test_rescan_does_not_verify_when_finding_persists(tmp_path, monkeypatch):
    store = FindingStore(tmp_path / "f.jsonl")
    f = _finding()
    store.append(f)
    # re-scan still finds the same vuln (identical fingerprint)
    eng = _engine(tmp_path, store, monkeypatch, run_returns=[_finding()])
    ch = _applied_change(f)
    eng.changes.write(ch)
    out, summary = eng.rescan(ch.change_id, actor="auto")
    assert summary["original_cleared"] is False
    assert out.state == ChangeState.APPLIED       # stays applied, not validated
