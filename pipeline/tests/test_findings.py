import json

import pytest

from pipeline.core.findings import Category, FindingStore, Severity, new_finding


def _make(**kw):
    return new_finding(
        app_name=kw.get("app_name", "app"),
        tier=kw.get("tier", 1),
        stage=kw.get("stage", "build"),
        adapter=kw.get("adapter", "garak"),
        category=kw.get("category", Category.PROMPT_INJECTION),
        severity=kw.get("severity", Severity.HIGH),
        title=kw.get("title", "T"),
        description=kw.get("description", "D"),
    )


def test_finding_has_stable_fingerprint():
    a = _make(title="same")
    b = _make(title="same")
    assert a.fingerprint == b.fingerprint


def test_finding_severity_score():
    f = _make(severity=Severity.CRITICAL)
    assert f.severity_score == 10


def test_store_roundtrip(tmp_path):
    p = tmp_path / "f.jsonl"
    store = FindingStore(p)
    store.append(_make(title="A"))
    store.append(_make(title="B"))
    rows = store.all()
    assert len(rows) == 2
    assert {r.title for r in rows} == {"A", "B"}


def test_store_serializes_categories(tmp_path):
    p = tmp_path / "f.jsonl"
    store = FindingStore(p)
    store.append(_make(category=Category.DATA_LEAKAGE))
    line = p.read_text().strip()
    payload = json.loads(line)
    assert payload["category"] == "data_leakage"
    assert payload["severity"] == "high"


def test_compliance_auto_tag(tmp_path):
    from pipeline.core.compliance import controls_for
    f = _make(category=Category.DATA_LEAKAGE)
    f.compliance = controls_for(f.category)
    assert any(c.startswith("HIPAA") for c in f.compliance)
    assert any(c.startswith("MITRE-ATLAS") for c in f.compliance)
