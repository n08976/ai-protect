"""Tests for the semgrep_autofix remediation strategy."""
from __future__ import annotations

from pipeline.core.findings import Category, Severity, new_finding
from pipeline.remediate.registry import remediators_for
from pipeline.remediate.strategies.semgrep_autofix import SemgrepAutofixRemediator


def _semgrep_finding(file, start, end, fix, adapter="semgrep"):
    return new_finding(
        app_name="x", tier=4, stage="build", adapter=adapter,
        category=Category.INFRA_VULN, severity=Severity.HIGH,
        title="Semgrep: dangerous-eval", description="",
        evidence={"rule_id": "python.lang.security.eval",
                  "file": str(file), "start_offset": start, "end_offset": end, "fix": fix})


def test_applies_rule_fix_at_span(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("x = eval(data)\n")              # 'eval(data)' is bytes [4,14)
    prop = SemgrepAutofixRemediator().propose(
        _semgrep_finding(f, 4, 14, "ast.literal_eval(data)"), {"source_path": str(tmp_path)})
    assert prop is not None
    assert prop.file_changes[0].new_content == "x = ast.literal_eval(data)\n"
    assert prop.rescan_adapter == "semgrep"


def test_no_fix_field_declines(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("x = eval(data)\n")
    finding = new_finding(app_name="x", tier=4, stage="build", adapter="semgrep",
                          category=Category.INFRA_VULN, severity=Severity.HIGH,
                          title="t", description="",
                          evidence={"file": str(f), "start_offset": 4, "end_offset": 14})
    assert SemgrepAutofixRemediator().can_fix(finding, {"source_path": str(tmp_path)}) is False


def test_non_semgrep_adapter_declines(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("x = eval(data)\n")
    finding = _semgrep_finding(f, 4, 14, "safe(data)", adapter="bandit")
    assert SemgrepAutofixRemediator().can_fix(finding, {"source_path": str(tmp_path)}) is False


def test_out_of_range_offsets_decline(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("short\n")
    prop = SemgrepAutofixRemediator().propose(
        _semgrep_finding(f, 4, 9999, "x"), {"source_path": str(tmp_path)})
    assert prop is None


def test_semgrep_finding_routes_to_autofix(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("x = eval(data)\n")
    rs = remediators_for(_semgrep_finding(f, 4, 14, "ast.literal_eval(data)"),
                         {"source_path": str(tmp_path)})
    assert rs and rs[0].name == "semgrep_autofix"
