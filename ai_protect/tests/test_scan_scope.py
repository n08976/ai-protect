"""Tests for the multi-path source + source_excludes schema work.

Covers:
  - Manifest.scan_targets() back-compat (legacy source_path only)
  - Manifest.scan_targets() new shape (source_paths list)
  - Manifest.is_excluded() pattern matching (absolute path, glob, substring)
  - Adapter.scan_paths() resolution precedence (config.paths > config.path > manifest)
  - Adapter.filter_findings() post-hoc exclude filtering
  - An adapter actually scans every declared path (loop integration)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ai_protect.adapters.base import Adapter
from ai_protect.core.findings import Category, Severity
from ai_protect.core.manifest import Manifest


def _base_manifest_kwargs(**overrides) -> dict:
    base = dict(
        name="scope-test",
        owner="test@example.com",
        on_call="test@example.com",
        description="scope test",
        data_sensitivity="confidential",
        decision_impact="advisory",
        integration_footprint="read_only",
        user_population="single_user",
    )
    base.update(overrides)
    return base


# ---- Manifest.scan_targets() ----

def test_scan_targets_legacy_single_path():
    """A manifest with only the old source_path field still works."""
    m = Manifest(**_base_manifest_kwargs(), source_path="/opt/legacy")
    assert m.scan_targets() == ["/opt/legacy"]


def test_scan_targets_new_list():
    m = Manifest(**_base_manifest_kwargs(), source_paths=["/a", "/b", "/c"])
    assert m.scan_targets() == ["/a", "/b", "/c"]


def test_scan_targets_both_set_merges_without_duplicate():
    m = Manifest(
        **_base_manifest_kwargs(),
        source_path="/shared",
        source_paths=["/a", "/shared"],
    )
    # /shared dedupe — list wins for ordering, single path appended only if novel.
    assert m.scan_targets() == ["/a", "/shared"]


def test_scan_targets_empty_returns_empty():
    m = Manifest(**_base_manifest_kwargs())
    assert m.scan_targets() == []


def test_scan_targets_expands_tilde():
    m = Manifest(**_base_manifest_kwargs(), source_paths=["~/some/place"])
    out = m.scan_targets()
    assert len(out) == 1
    assert not out[0].startswith("~"), "tilde must be expanded"
    assert out[0].endswith("/some/place")


# ---- Manifest.is_excluded() ----

class TestIsExcluded:
    def test_no_excludes_returns_false(self):
        m = Manifest(**_base_manifest_kwargs())
        assert m.is_excluded("/anything") is False

    def test_empty_path_returns_false(self):
        m = Manifest(**_base_manifest_kwargs(), source_excludes=["*.pyc"])
        assert m.is_excluded(None) is False
        assert m.is_excluded("") is False

    def test_absolute_prefix_match(self):
        m = Manifest(**_base_manifest_kwargs(),
                     source_excludes=["/opt/secrets/", "/etc/shadow"])
        assert m.is_excluded("/opt/secrets/key.pem") is True
        assert m.is_excluded("/opt/secrets") is True           # exact match
        assert m.is_excluded("/etc/shadow") is True
        assert m.is_excluded("/opt/source/foo.py") is False    # different prefix

    def test_glob_pattern(self):
        m = Manifest(**_base_manifest_kwargs(),
                     source_excludes=["*.pyc", "*.so"])
        assert m.is_excluded("/a/b/c.pyc") is True             # basename match
        assert m.is_excluded("c.pyc") is True
        assert m.is_excluded("/a/c.py") is False               # different ext

    def test_substring_dir_name_match(self):
        m = Manifest(**_base_manifest_kwargs(),
                     source_excludes=["__pycache__", "node_modules", ".git"])
        assert m.is_excluded("/repo/src/__pycache__/foo.pyc") is True
        assert m.is_excluded("/repo/frontend/node_modules/lib.js") is True
        assert m.is_excluded("/repo/.git/index") is True
        assert m.is_excluded("/repo/src/main.py") is False


# ---- Manifest.from_yaml round trip ----

def test_from_yaml_reads_new_fields(tmp_path):
    p = tmp_path / "test.yml"
    p.write_text("""
name: yaml-test
owner: x@example.com
on_call: x@example.com
description: t
data_sensitivity: confidential
decision_impact: advisory
integration_footprint: read_only
user_population: single_user
source_paths:
  - /a
  - /b
source_excludes:
  - "*.pyc"
  - /opt/secrets/
""")
    m = Manifest.from_yaml(p)
    assert m.source_paths == ["/a", "/b"]
    assert m.source_excludes == ["*.pyc", "/opt/secrets/"]
    assert m.scan_targets() == ["/a", "/b"]
    assert m.is_excluded("/a/x.pyc") is True
    assert m.is_excluded("/opt/secrets/key") is True


def test_from_yaml_back_compat_source_path_only(tmp_path):
    p = tmp_path / "legacy.yml"
    p.write_text("""
name: legacy
owner: x@example.com
on_call: x@example.com
description: t
data_sensitivity: confidential
decision_impact: advisory
integration_footprint: read_only
user_population: single_user
source_path: /opt/legacy
""")
    m = Manifest.from_yaml(p)
    assert m.source_path == "/opt/legacy"
    assert m.source_paths == []
    assert m.scan_targets() == ["/opt/legacy"]


# ---- Adapter.scan_paths() / filter_findings() ----

class _StubAdapter(Adapter):
    name = "stub"
    description = "test stub"

    def run(self):  # required abstract
        return []


def test_adapter_scan_paths_uses_config_paths_first():
    m = Manifest(**_base_manifest_kwargs(), source_paths=["/from/manifest"])
    a = _StubAdapter(m, stage="build", config={"paths": ["/from/config1", "/from/config2"]})
    assert a.scan_paths() == ["/from/config1", "/from/config2"]


def test_adapter_scan_paths_config_path_second():
    m = Manifest(**_base_manifest_kwargs(), source_paths=["/from/manifest"])
    a = _StubAdapter(m, stage="build", config={"path": "/from/config"})
    assert a.scan_paths() == ["/from/config"]


def test_adapter_scan_paths_manifest_third():
    m = Manifest(**_base_manifest_kwargs(), source_paths=["/from/manifest"])
    a = _StubAdapter(m, stage="build", config={})
    assert a.scan_paths() == ["/from/manifest"]


def test_adapter_scan_paths_fallback_to_dot():
    m = Manifest(**_base_manifest_kwargs())  # no source paths anywhere
    a = _StubAdapter(m, stage="build", config={})
    assert a.scan_paths() == ["."]


def test_adapter_filter_findings_drops_excluded():
    m = Manifest(**_base_manifest_kwargs(),
                 source_excludes=["__pycache__", "*.pyc"])
    a = _StubAdapter(m, stage="build", config={})
    keep = a.make_finding(
        tier=1, category=Category.SECRETS, severity=Severity.HIGH,
        title="keep me", description="d",
        evidence={"file": "/repo/src/main.py"},
    )
    drop_py = a.make_finding(
        tier=1, category=Category.SECRETS, severity=Severity.HIGH,
        title="drop me", description="d",
        evidence={"file": "/repo/src/__pycache__/main.cpython-312.pyc"},
    )
    drop_glob = a.make_finding(
        tier=1, category=Category.SECRETS, severity=Severity.HIGH,
        title="drop too", description="d",
        evidence={"file": "/repo/foo.pyc"},
    )
    out = a.filter_findings([keep, drop_py, drop_glob])
    assert len(out) == 1
    assert out[0].title == "keep me"


def test_adapter_filter_findings_no_excludes_passthrough():
    """When the manifest has no excludes, filter_findings is a no-op."""
    m = Manifest(**_base_manifest_kwargs())
    a = _StubAdapter(m, stage="build", config={})
    f = a.make_finding(
        tier=1, category=Category.SECRETS, severity=Severity.HIGH,
        title="t", description="d", evidence={"file": "/anywhere.pyc"},
    )
    assert a.filter_findings([f]) == [f]


# ---- End-to-end: an adapter actually loops over scan_paths ----

# Realistic-shape fake credentials trufflehog catches deterministically.
# Both are syntactically valid pattern matches but obviously not real secrets.
FAKE_GITHUB_PAT = "ghp_xJ8KqL2mN9pR4tV6wY3zA1bC5dE7fG0hI8jK"  # gitleaks:allow trufflehog:ignore — intentional bait for secret-scanner tests


def test_trufflehog_loops_over_paths(tmp_path):
    """TruffleHog adapter must scan every path in source_paths and
    aggregate findings across all of them."""
    import shutil
    if not shutil.which("trufflehog"):
        pytest.skip("trufflehog CLI not on PATH")

    a = tmp_path / "tree_a"
    b = tmp_path / "tree_b"
    a.mkdir(); b.mkdir()
    (a / "config_a.py").write_text(f"GITHUB_TOKEN = '{FAKE_GITHUB_PAT}'\n")
    (b / "config_b.py").write_text(f"GITHUB_TOKEN = '{FAKE_GITHUB_PAT}'\n")

    m = Manifest(**_base_manifest_kwargs(),
                 source_paths=[str(a), str(b)])

    from ai_protect.adapters.trufflehog import TruffleHogAdapter
    adapter = TruffleHogAdapter(m, stage="build", config={})
    findings = adapter.run()

    files = {f.evidence.get("file") for f in findings if f.evidence.get("file")}
    assert any("tree_a" in f for f in files), \
        f"expected hit in tree_a, got: {files}"
    assert any("tree_b" in f for f in files), \
        f"expected hit in tree_b, got: {files}"


def test_adapter_excludes_drop_findings_from_filesystem_scan(tmp_path):
    """source_excludes must drop matching findings post-hoc, even though
    the underlying tool scans everything under the source path."""
    import shutil
    if not shutil.which("trufflehog"):
        pytest.skip("trufflehog CLI not on PATH")

    root = tmp_path / "tree"
    skip = root / "ignored_subdir"
    keep = root / "kept_subdir"
    root.mkdir(); skip.mkdir(); keep.mkdir()
    (skip / "ignore.py").write_text(f"TOKEN = '{FAKE_GITHUB_PAT}'\n")
    (keep / "keep.py").write_text(f"TOKEN = '{FAKE_GITHUB_PAT}'\n")

    m = Manifest(
        **_base_manifest_kwargs(),
        source_paths=[str(root)],
        source_excludes=["ignored_subdir"],
    )

    from ai_protect.adapters.trufflehog import TruffleHogAdapter
    adapter = TruffleHogAdapter(m, stage="build", config={})
    findings = adapter.run()

    files = {f.evidence.get("file") for f in findings if f.evidence.get("file")}
    assert any("kept_subdir" in f for f in files), \
        f"expected to keep findings from kept_subdir, got: {files}"
    assert not any("ignored_subdir" in f for f in files), \
        f"exclude should have dropped ignored_subdir findings, got: {files}"
