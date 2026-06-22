"""Tests for the insecure_pattern_fix remediation strategy."""
from __future__ import annotations

from ai_protect.core.findings import Category, Severity, new_finding
from ai_protect.remediate.strategies.insecure_pattern_fix import InsecurePatternFixRemediator


def _finding(file, line, adapter="bandit", category=Category.AUTH):
    return new_finding(
        app_name="x", tier=4, stage="build", adapter=adapter,
        category=category, severity=Severity.HIGH,
        title="insecure call", description="",
        evidence={"file": str(file), "line": line})


def test_yaml_load_swapped(tmp_path):
    f = tmp_path / "cfg.py"
    f.write_text("import yaml\n\ncfg = yaml.load(open('c.yml'))\n")
    prop = InsecurePatternFixRemediator().propose(_finding(f, 3), {"source_path": str(tmp_path)})
    assert prop is not None
    assert "yaml.safe_load(open('c.yml'))" in prop.file_changes[0].new_content
    assert "yaml.load(" not in prop.file_changes[0].new_content


def test_verify_false_swapped(tmp_path):
    f = tmp_path / "net.py"
    f.write_text("import requests\nr = requests.get(u, verify=False)\n")
    prop = InsecurePatternFixRemediator().propose(_finding(f, 2), {"source_path": str(tmp_path)})
    assert "verify=True" in prop.file_changes[0].new_content


def test_yaml_load_with_loader_is_left_alone(tmp_path):
    f = tmp_path / "cfg.py"
    f.write_text("import yaml\ncfg = yaml.load(s, Loader=yaml.FullLoader)\n")
    assert InsecurePatternFixRemediator().propose(_finding(f, 2), {"source_path": str(tmp_path)}) is None


def test_line_drift_is_safe(tmp_path):
    """Finding points at the wrong line → no edit (don't guess)."""
    f = tmp_path / "cfg.py"
    f.write_text("import yaml\n\ncfg = yaml.load(x)\n")
    # point at line 1 (the import), not the yaml.load on line 3
    assert InsecurePatternFixRemediator().propose(_finding(f, 1), {"source_path": str(tmp_path)}) is None


def test_only_the_flagged_line_is_touched(tmp_path):
    f = tmp_path / "cfg.py"
    f.write_text("a = yaml.load(p)\nb = yaml.load(q)\n")  # two occurrences
    prop = InsecurePatternFixRemediator().propose(_finding(f, 1), {"source_path": str(tmp_path)})
    out = prop.file_changes[0].new_content
    assert out == "a = yaml.safe_load(p)\nb = yaml.load(q)\n"   # only line 1 changed


def test_explicit_unsafe_loader_swapped(tmp_path):
    f = tmp_path / "cfg.py"
    f.write_text("cfg = yaml.load(s, Loader=yaml.Loader)\n")
    prop = InsecurePatternFixRemediator().propose(_finding(f, 1), {"source_path": str(tmp_path)})
    assert prop is not None
    out = prop.file_changes[0].new_content
    assert "Loader=yaml.SafeLoader" in out
    assert "Loader=yaml.Loader" not in out


def test_flask_debug_swapped(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("app.run(host='0.0.0.0', debug=True)\n")
    prop = InsecurePatternFixRemediator().propose(
        _finding(f, 1, category=Category.INFRA_VULN), {"source_path": str(tmp_path)})
    assert "debug=False" in prop.file_changes[0].new_content


def test_semgrep_line_range(tmp_path):
    f = tmp_path / "net.py"
    f.write_text("x = 1\nr = requests.get(u, verify=False)\n")
    finding = new_finding(
        app_name="x", tier=4, stage="build", adapter="semgrep",
        category=Category.INFRA_VULN, severity=Severity.HIGH,
        title="tls", description="",
        evidence={"file": str(f), "start_line": 2, "end_line": 2})
    prop = InsecurePatternFixRemediator().propose(finding, {"source_path": str(tmp_path)})
    assert "verify=True" in prop.file_changes[0].new_content
