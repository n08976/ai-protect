"""Tests for the weak_hash_fix remediation strategy."""
from __future__ import annotations

from ai_protect.core.findings import Category, Severity, new_finding
from ai_protect.remediate.strategies.weak_hash_fix import WeakHashFixRemediator


def _b324(file, line, test_id="B324"):
    return new_finding(
        app_name="x", tier=4, stage="build", adapter="bandit",
        category=Category.AUTH, severity=Severity.HIGH,
        title=f"Bandit {test_id}: hashlib", description="",
        evidence={"test_id": test_id, "file": str(file), "line": line})


def _fix(tmp_path, src, line):
    f = tmp_path / "h.py"
    f.write_text(src)
    return WeakHashFixRemediator().propose(_b324(f, line), {"source_path": str(tmp_path)})


def test_sha1_chained_call(tmp_path):
    prop = _fix(tmp_path, "import hashlib\nx = hashlib.sha1(k.encode('utf-8')).hexdigest()[:16]\n", 2)
    assert prop is not None
    assert prop.file_changes[0].new_content == \
        "import hashlib\nx = hashlib.sha1(k.encode('utf-8'), usedforsecurity=False).hexdigest()[:16]\n"


def test_md5_simple(tmp_path):
    prop = _fix(tmp_path, "import hashlib\nh = hashlib.md5(data)\n", 2)
    assert "hashlib.md5(data, usedforsecurity=False)" in prop.file_changes[0].new_content


def test_md5_no_args(tmp_path):
    prop = _fix(tmp_path, "import hashlib\nh = hashlib.md5()\n", 2)
    assert "hashlib.md5(usedforsecurity=False)" in prop.file_changes[0].new_content


def test_hashlib_new(tmp_path):
    prop = _fix(tmp_path, "import hashlib\nh = hashlib.new('md5', data)\n", 2)
    assert "hashlib.new('md5', data, usedforsecurity=False)" in prop.file_changes[0].new_content


def test_already_safe_declines(tmp_path):
    f = tmp_path / "h.py"
    f.write_text("import hashlib\nh = hashlib.md5(data, usedforsecurity=False)\n")
    assert WeakHashFixRemediator().can_fix(_b324(f, 2), {"source_path": str(tmp_path)}) is False


def test_non_b324_declines(tmp_path):
    f = tmp_path / "h.py"
    f.write_text("import hashlib\nh = hashlib.md5(data)\n")
    assert WeakHashFixRemediator().can_fix(_b324(f, 2, test_id="B303"),
                                           {"source_path": str(tmp_path)}) is False


def test_strong_hash_untouched(tmp_path):
    """sha256 isn't weak — no plan even if mislabeled B324."""
    f = tmp_path / "h.py"
    f.write_text("import hashlib\nh = hashlib.sha256(data)\n")
    assert WeakHashFixRemediator().can_fix(_b324(f, 2), {"source_path": str(tmp_path)}) is False
