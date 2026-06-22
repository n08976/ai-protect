"""pip_bump — auto-fix pip_audit / grype / osv_scanner SUPPLY_CHAIN findings.

Strategy:
  - Read the manifest's requirements.txt
  - If a fix version is known and the existing pin is < fix → bump it
    (preserving inline comments)
  - If a fix version is known and the package isn't pinned at all → add it
  - In all other cases (no fix version known, or pin already satisfies fix)
    → return None — no Change proposed.

Notes on what this remediator deliberately will NOT do:
  - When osv-scanner reports a CVE with no `fix_versions`, we do NOT modify
    requirements.txt. Earlier versions of this strategy appended a
    `pkg  # tracking — no fix published` line, which destroyed existing
    version pins and CVE-rationale comments. We learned the hard way.
  - We do NOT overwrite an existing version spec when the existing pin
    already satisfies the fix (e.g. existing `cryptography>=44.0.2`,
    finding asks for >=44.0.1). The remediator returns None so the Engine
    skips this finding entirely.

Confidence:
  - 0.9 when a real version bump is generated.
"""
from __future__ import annotations

import re
from pathlib import Path

from ...core.findings import Category, Finding
from ..base import FileChange, Proposal, Remediator


# Tokens we split on to extract the package head from a requirements line.
# Order matters: longer-first so '===' is consumed before '==' etc.
_SPEC_SEPS = ("===", "==", ">=", "<=", "!=", "~=", ">", "<")


class PipBumpRemediator(Remediator):
    name = "pip_bump"
    handles = {Category.SUPPLY_CHAIN}
    description = "Bump a Python dep to a fixed version in requirements.txt; generate a pin-version test."

    def can_fix(self, finding: Finding, manifest_raw: dict) -> bool:
        if finding.category != Category.SUPPLY_CHAIN:
            return False
        if finding.adapter not in ("pip_audit", "grype", "osv_scanner"):
            return False
        return bool((finding.evidence or {}).get("package"))

    def propose(self, finding: Finding, manifest_raw: dict) -> Proposal | None:
        ev = finding.evidence or {}
        pkg = ev.get("package")
        if not pkg:
            return None

        # Pick the lowest published fix version (least disruptive). If none,
        # we have nothing actionable to propose — return None.
        fixed_versions = ev.get("fixed_in") or ev.get("fix_versions") or []
        if isinstance(fixed_versions, str):
            fixed_versions = [fixed_versions]
        fixed_versions = [v for v in fixed_versions if v]
        if not fixed_versions:
            return None
        fix = min(fixed_versions, key=_version_key)

        source = Path(manifest_raw.get("source_path", "."))
        # Honor multi-path manifests: prefer the first source_path that
        # already contains requirements.txt; else fall back to legacy source_path.
        req_path = _resolve_requirements_path(manifest_raw, source)
        existing = req_path.read_text() if req_path.exists() else ""

        new_content, create, changed = _patch_requirements(existing, pkg, fix)
        if not changed and not create:
            # Existing pin already satisfies the fix — nothing to do.
            return None

        summary = (f"Create {req_path} pinning {pkg}>={fix}" if create
                   else f"Bump {pkg}>={fix} in {req_path}")

        return Proposal(
            summary=summary,
            confidence=0.9,
            rescan_adapter=finding.adapter,
            file_changes=[FileChange(
                path=str(req_path.resolve()),
                new_content=new_content,
                create=create,
            )],
            test_plan={
                "kind": "pin_version",
                "package": pkg,
                "min_version": fix,
                "requirements_path": str(req_path.resolve()),
            },
            notes=(
                f"Vuln {ev.get('vuln_id', 'CVE')}; installed "
                f"{ev.get('installed') or ev.get('version')}. Fixed in: "
                f"{', '.join(fixed_versions)}."
            ),
        )


def _resolve_requirements_path(manifest_raw: dict, fallback: Path) -> Path:
    """Pick the requirements.txt under the manifest's scan scope.

    Multi-path manifests: prefer the first source_paths entry that has a
    requirements.txt already; else the first entry; else legacy source_path.
    """
    paths = manifest_raw.get("source_paths") or []
    if isinstance(paths, list):
        # Prefer one that already contains requirements.txt.
        for p in paths:
            cand = Path(p).expanduser() / "requirements.txt"
            if cand.exists():
                return cand
        if paths:
            return Path(paths[0]).expanduser() / "requirements.txt"
    return fallback / "requirements.txt"


def _version_key(v: str) -> tuple:
    """Crude version sort: tuple of ints + suffix strings. Good enough for
    comparing fix versions like '2.7.0', '11.4.0', '0.0.21'."""
    parts: list = []
    cur = ""
    for ch in v:
        if ch.isdigit():
            cur += ch
        else:
            if cur:
                parts.append(int(cur))
                cur = ""
            parts.append(ch)
    if cur:
        parts.append(int(cur))
    return tuple(parts)


def _parse_line(line: str) -> tuple[str, str, str, str]:
    """Decompose a requirements line into (head_lower, op, version, comment_with_hash).

    `head_lower` is the package name lower-cased, with inline comments stripped.
    Returns ('', '', '', '') for lines that don't contain a package spec
    (blank lines, pure comments, -r/-e/-f directives, etc.).
    """
    # Comment is everything from the first '#' onwards (including the hash).
    if "#" in line:
        spec_part, sep, comment = line.partition("#")
        comment = sep + comment
    else:
        spec_part, comment = line, ""
    spec_str = spec_part.rstrip()
    stripped = spec_str.strip()
    if not stripped or stripped.startswith(("-", "+", "/")):
        return "", "", "", comment
    # Find the version operator (if any) and split.
    op = ""
    version = ""
    head = stripped
    for sep in _SPEC_SEPS:
        if sep in head:
            head, _, rest = head.partition(sep)
            op = sep
            version = rest.strip()
            break
    return head.strip().lower(), op, version, comment


def _format_line(pkg: str, fix: str, comment: str) -> str:
    """Render `pkg>=fix   # comment` with sane padding so the column stays tidy."""
    pin = f"{pkg}>={fix}"
    if comment:
        pad_to = 24
        pad = " " * max(2, pad_to - len(pin))
        return f"{pin}{pad}{comment.lstrip()}"
    return pin


def _patch_requirements(existing: str, pkg: str, fix: str) -> tuple[str, bool, bool]:
    """Ensure `pkg` is pinned at >= `fix`. Returns (new_content, created, changed).

    Rules:
      - If an existing line already pins `pkg` at a version >= `fix`, leave
        it alone and report changed=False.
      - If the existing pin is below `fix`, replace the version (preserving
        any inline comment) and report changed=True.
      - If `pkg` isn't in the file, append a new pin line and report changed=True.
      - Duplicate lines for the same `pkg` are collapsed to one.
    """
    create = not existing.strip()
    lines = existing.splitlines() if existing else []
    pkg_lower = pkg.lower()
    fix_key = _version_key(fix)

    new_lines: list[str] = []
    handled = False
    changed = False

    for ln in lines:
        head, op, version, comment = _parse_line(ln)
        if head != pkg_lower:
            new_lines.append(ln)
            continue
        # First occurrence: decide bump-or-keep. Subsequent duplicates: drop.
        if handled:
            # Drop duplicate line; that itself counts as a change.
            changed = True
            continue
        handled = True
        # If the existing pin already meets fix, keep it.
        if version:
            try:
                if _version_key(version) >= fix_key and op in (">=", "==", "===", "~=", ">"):
                    new_lines.append(ln)
                    continue
            except Exception:
                pass  # fall through to bump
        # Need to bump. Preserve the comment if there was one — UNLESS it's a
        # stale "tracking — no fix published" marker from an earlier buggy
        # run. That comment is now wrong (we just found a fix) so we drop it.
        if "tracking — no fix published" in comment or "tracking - no fix published" in comment:
            comment = ""
        new_lines.append(_format_line(pkg, fix, comment))
        changed = True

    if not handled:
        if create:
            new_lines = [
                "# requirements.txt — generated by ai-protect remediation engine.",
                "# Pins are the lowest fixed versions clearing pip_audit / grype / "
                "osv_scanner findings.",
                "# Review and tighten before committing.",
                "",
            ]
        new_lines.append(f"{pkg}>={fix}")
        changed = True

    out = "\n".join(new_lines)
    if not out.endswith("\n"):
        out += "\n"
    return out, create, changed
