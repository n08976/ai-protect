"""Tests for the npm_bump remediation strategy + ecosystem isolation vs pip_bump."""
from __future__ import annotations

import json

from ai_protect.core.findings import Category, Severity, new_finding
from ai_protect.remediate.registry import remediators_for
from ai_protect.remediate.strategies.npm_bump import NpmBumpRemediator, _version_key


def _finding(pkg="lodash", fixed=("4.17.21",), ecosystem="npm", adapter="osv_scanner"):
    return new_finding(
        app_name="x", tier=4, stage="build", adapter=adapter,
        category=Category.SUPPLY_CHAIN, severity=Severity.HIGH,
        title=f"{pkg} vulnerable", description="",
        evidence={"package": pkg, "fixed_in": list(fixed),
                  "ecosystem": ecosystem, "version": "4.0.0"})


def test_version_key_sort():
    assert sorted(["4.17.21", "4.2.0", "4.17.5"], key=_version_key) == \
        ["4.2.0", "4.17.5", "4.17.21"]


def test_bumps_vulnerable_dependency(tmp_path):
    pj = tmp_path / "package.json"
    pj.write_text(json.dumps({"name": "app", "dependencies": {"lodash": "^4.0.0"}}))
    prop = NpmBumpRemediator().propose(_finding(), {"source_path": str(tmp_path)})
    assert prop is not None
    new = json.loads(prop.file_changes[0].new_content)
    assert new["dependencies"]["lodash"] == "^4.17.21"
    assert prop.rescan_adapter == "osv_scanner"


def test_no_bump_when_already_satisfied(tmp_path):
    pj = tmp_path / "package.json"
    pj.write_text(json.dumps({"dependencies": {"lodash": "^4.18.0"}}))
    assert NpmBumpRemediator().propose(_finding(), {"source_path": str(tmp_path)}) is None


def test_devdependency_bucket(tmp_path):
    pj = tmp_path / "package.json"
    pj.write_text(json.dumps({"devDependencies": {"lodash": "4.0.0"}}))
    prop = NpmBumpRemediator().propose(_finding(), {"source_path": str(tmp_path)})
    assert json.loads(prop.file_changes[0].new_content)["devDependencies"]["lodash"] == "^4.17.21"


def test_npm_finding_routed_to_npm_bump(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.0.0"}}))
    rs = remediators_for(_finding(ecosystem="npm"), {"source_path": str(tmp_path)})
    assert rs and rs[0].name == "npm_bump"


def test_pypi_finding_not_claimed_by_npm_bump(tmp_path):
    (tmp_path / "requirements.txt").write_text("urllib3==1.0.0\n")
    f = new_finding(app_name="x", tier=4, stage="build", adapter="osv_scanner",
                    category=Category.SUPPLY_CHAIN, severity=Severity.HIGH,
                    title="urllib3 vulnerable", description="",
                    evidence={"package": "urllib3", "fixed_in": ["2.0.0"],
                              "ecosystem": "PyPI", "version": "1.0.0"})
    rs = remediators_for(f, {"source_path": str(tmp_path)})
    names = [r.name for r in rs]
    assert "npm_bump" not in names
    assert "pip_bump" in names
