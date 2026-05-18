"""Tests for pipeline/remediate/strategies/pip_bump.py — the regression net.

These tests pin down the bug fixes:
  1. No fix version → propose() returns None (don't pollute requirements.txt)
  2. Existing pin already satisfies fix → propose() returns None (no churn)
  3. Existing pin too low → bump it, preserve inline comment
  4. Package not in file → append a real pin (no tracking comment)
  5. Duplicate package lines → collapsed to one
  6. Inline comment parsed correctly (matches package even when followed by "# ...")
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.core.findings import Category, Severity, new_finding
from pipeline.remediate.strategies.pip_bump import (
    PipBumpRemediator, _patch_requirements, _parse_line, _version_key,
)


# ---- _version_key sort ordering ----

def test_version_key_basic_sort():
    versions = ["44.0.10", "44.0.2", "44.0.9", "44.1.0"]
    assert sorted(versions, key=_version_key) == ["44.0.2", "44.0.9", "44.0.10", "44.1.0"]


# ---- _parse_line ----

class TestParseLine:
    def test_plain_pin(self):
        assert _parse_line("urllib3>=2.7.0") == ("urllib3", ">=", "2.7.0", "")

    def test_pin_with_comment(self):
        head, op, ver, comment = _parse_line("urllib3>=2.7.0  # CVE-2026-44431")
        assert head == "urllib3"
        assert op == ">="
        assert ver == "2.7.0"
        assert comment.lstrip().startswith("#")

    def test_bare_package(self):
        assert _parse_line("requests") == ("requests", "", "", "")

    def test_tracking_comment_line(self):
        """A line like `pillow  # tracking — no fix published` must parse as pillow.
        This is the bug that caused duplicate lines in the original code."""
        head, op, ver, comment = _parse_line("pillow  # tracking — no fix published")
        assert head == "pillow"
        assert ver == ""
        assert "tracking" in comment

    def test_pure_comment(self):
        head, _, _, comment = _parse_line("# this is a comment")
        assert head == ""
        assert comment.startswith("#")

    def test_blank_line(self):
        assert _parse_line("") == ("", "", "", "")

    def test_pip_directive_line(self):
        head, _, _, _ = _parse_line("-r other.txt")
        assert head == ""


# ---- _patch_requirements: the core regression cases ----

class TestPatchRequirements:
    def test_no_existing_file_creates_one(self):
        out, create, changed = _patch_requirements("", "requests", "2.32.0")
        assert create is True and changed is True
        assert "requests>=2.32.0" in out

    def test_package_not_in_existing_file_gets_appended(self):
        existing = "flask>=3.0\n"
        out, create, changed = _patch_requirements(existing, "requests", "2.32.0")
        assert create is False
        assert changed is True
        assert "flask>=3.0" in out
        assert "requests>=2.32.0" in out

    def test_existing_pin_already_satisfies_fix_no_change(self):
        """The big one: if you have `cryptography>=44.0.2` and the fix asks
        for >=44.0.1, we must leave the line ALONE."""
        existing = "cryptography>=44.0.2  # round-2: 44.0.1 still in affected range\n"
        out, create, changed = _patch_requirements(existing, "cryptography", "44.0.1")
        assert changed is False, "must not modify a pin that already satisfies the fix"
        assert out == existing

    def test_existing_pin_below_fix_gets_bumped_preserving_comment(self):
        existing = "urllib3>=2.0.0  # CVE-old\n"
        out, _, changed = _patch_requirements(existing, "urllib3", "2.7.0")
        assert changed is True
        assert "urllib3>=2.7.0" in out
        # Comment must survive.
        assert "# CVE-old" in out

    def test_tracking_comment_line_gets_recognized_and_replaced(self):
        """If a previous (buggy) run left `pillow  # tracking — no fix published`
        in the file, a new fix should recognize and replace it cleanly."""
        existing = "pillow  # tracking — no fix published\n"
        out, _, changed = _patch_requirements(existing, "pillow", "11.4.0")
        assert changed is True
        assert "pillow>=11.4.0" in out
        # The tracking line must NOT survive.
        assert "tracking — no fix published" not in out

    def test_duplicate_lines_for_same_package_collapsed(self):
        """If a buggy prior run left multiple duplicate lines for the same pkg,
        a new fix must collapse them to one."""
        existing = (
            "pillow  # tracking — no fix published\n"
            "pillow  # tracking — no fix published\n"
            "pillow  # tracking — no fix published\n"
        )
        out, _, changed = _patch_requirements(existing, "pillow", "11.4.0")
        assert changed is True
        # Should have exactly one pillow line now.
        pillow_lines = [ln for ln in out.splitlines() if ln.strip().lower().startswith("pillow")]
        assert len(pillow_lines) == 1, f"expected 1 pillow line, got: {pillow_lines}"
        assert pillow_lines[0].startswith("pillow>=11.4.0")

    def test_unrelated_lines_untouched(self):
        existing = (
            "flask>=3.0\n"
            "requests>=2.32.6  # round-2 GHSA-gc5v\n"
            "urllib3>=2.7.0\n"
        )
        out, _, changed = _patch_requirements(existing, "urllib3", "2.7.0")
        # urllib3 already satisfies → no change.
        assert changed is False
        assert out == existing

    def test_case_insensitive_package_match(self):
        existing = "Pillow>=10.0.0\n"
        out, _, changed = _patch_requirements(existing, "pillow", "11.4.0")
        assert changed is True
        assert ">=11.4.0" in out


# ---- propose() — full Remediator path ----

def _osv_finding(pkg: str, fixed_in: list[str] | None = None) -> "Finding":
    return new_finding(
        app_name="test-app",
        tier=2,
        stage="build",
        adapter="osv_scanner",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.HIGH,
        title=f"GHSA-test: {pkg} vulnerable",
        description="",
        evidence={"package": pkg, "version": "1.0.0", "fixed_in": fixed_in or []},
    )


def test_propose_returns_none_when_no_fix_version(tmp_path):
    """The regression: when osv-scanner has no fix_versions, propose() must
    return None — DO NOT touch the requirements file with a tracking line."""
    req = tmp_path / "requirements.txt"
    req.write_text("cryptography>=44.0.2  # round-2 still in affected range\n")
    f = _osv_finding("cryptography", fixed_in=[])  # explicitly no fix
    r = PipBumpRemediator()
    proposal = r.propose(f, {"source_path": str(tmp_path)})
    assert proposal is None, "no fix version → no proposal"
    # File untouched.
    assert req.read_text() == "cryptography>=44.0.2  # round-2 still in affected range\n"


def test_propose_returns_none_when_pin_already_satisfies(tmp_path):
    """Existing pin >= fix → no useful change → return None."""
    req = tmp_path / "requirements.txt"
    req.write_text("cryptography>=44.0.2\n")
    f = _osv_finding("cryptography", fixed_in=["44.0.1"])
    r = PipBumpRemediator()
    proposal = r.propose(f, {"source_path": str(tmp_path)})
    assert proposal is None, (
        "existing pin (44.0.2) already satisfies the fix (44.0.1) → no proposal"
    )


def test_propose_bumps_when_pin_below_fix(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("urllib3>=2.0.0\n")
    f = _osv_finding("urllib3", fixed_in=["2.7.0"])
    r = PipBumpRemediator()
    proposal = r.propose(f, {"source_path": str(tmp_path)})
    assert proposal is not None
    fc = proposal.file_changes[0]
    assert "urllib3>=2.7.0" in fc.new_content
    assert proposal.confidence == 0.9


def test_propose_picks_lowest_fix_version(tmp_path):
    """Multiple fix versions → pick the lowest (least disruptive)."""
    req = tmp_path / "requirements.txt"
    req.write_text("pillow>=10.0.0\n")
    f = _osv_finding("pillow", fixed_in=["11.4.0", "11.5.0", "12.0.0"])
    r = PipBumpRemediator()
    proposal = r.propose(f, {"source_path": str(tmp_path)})
    assert proposal is not None
    assert "pillow>=11.4.0" in proposal.file_changes[0].new_content
    assert "pillow>=11.5.0" not in proposal.file_changes[0].new_content


def test_propose_creates_file_when_missing(tmp_path):
    f = _osv_finding("requests", fixed_in=["2.32.6"])
    r = PipBumpRemediator()
    proposal = r.propose(f, {"source_path": str(tmp_path)})
    assert proposal is not None
    fc = proposal.file_changes[0]
    assert fc.create is True
    assert "requests>=2.32.6" in fc.new_content
    # Header comment present so the file is self-documenting.
    assert "generated by ai-protect" in fc.new_content
