"""npm_bump — bump a vulnerable npm dependency to a fixed version in package.json.

The Node analogue of pip_bump. Triggered by SUPPLY_CHAIN findings from
osv_scanner / grype / trivy whose ecosystem is npm. Bumps the offending package
in package.json (dependencies / devDependencies / optional / peer) to `^<fix>`,
choosing the lowest published fix version (least disruptive).

Like pip_bump, this edits the manifest (package.json), not the lockfile — a
`npm install` refresh + the re-scan are what verify the bump. If the re-scan
can't confirm the vuln is gone (e.g. a lockfile still pins the old version),
`cli remediate` reverts the change rather than shipping an unverified fix.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ...core.findings import Category, Finding
from ..base import FileChange, Proposal, Remediator

_DEP_BUCKETS = ("dependencies", "devDependencies",
                "optionalDependencies", "peerDependencies")
_NPM_ECOSYSTEMS = {"npm", "node", "nodejs", "javascript"}


def _version_key(v: str):
    """Sort key for npm-ish versions; strips range operators, pads numerics."""
    core = re.sub(r"^[\^~>=<\s]+", "", str(v)).split("+")[0].split("-")[0]
    parts = []
    for seg in core.split("."):
        parts.append(int(seg) if seg.isdigit() else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _bump_dep(data: dict, pkg: str, fix: str) -> tuple[dict, bool]:
    """Set pkg to ^fix in whichever bucket holds it, only if fix is higher.
    Returns (new_data, changed)."""
    changed = False
    for bucket in _DEP_BUCKETS:
        deps = data.get(bucket)
        if not isinstance(deps, dict) or pkg not in deps:
            continue
        current = deps[pkg]
        if _version_key(current) < _version_key(fix):
            deps[pkg] = f"^{fix}"
            changed = True
    return data, changed


def _find_package_json(manifest_raw: dict, pkg: str) -> Path | None:
    """Find the package.json under scan scope that declares `pkg`."""
    roots: list[str] = []
    if manifest_raw.get("source_paths"):
        roots += [str(p) for p in manifest_raw["source_paths"]]
    if manifest_raw.get("source_path"):
        roots.append(str(manifest_raw["source_path"]))
    if not roots:
        roots = ["."]
    for root in roots:
        pj = Path(root).expanduser() / "package.json"
        if not pj.exists():
            continue
        try:
            data = json.loads(pj.read_text())
        except (ValueError, OSError):
            continue
        if any(pkg in (data.get(b) or {}) for b in _DEP_BUCKETS):
            return pj
    return None


class NpmBumpRemediator(Remediator):
    name = "npm_bump"
    handles = {Category.SUPPLY_CHAIN}
    description = "Bump a vulnerable npm dependency to a fixed version in package.json; re-scan to verify."

    def can_fix(self, finding: Finding, manifest_raw: dict) -> bool:
        if finding.category != Category.SUPPLY_CHAIN:
            return False
        if finding.adapter not in ("osv_scanner", "grype", "trivy"):
            return False
        ev = finding.evidence or {}
        pkg = ev.get("package")
        if not pkg:
            return False
        eco = (ev.get("ecosystem") or "").strip().lower()
        if eco:
            return eco in _NPM_ECOSYSTEMS
        # Ecosystem unknown (grype/trivy don't always set it) → only claim the
        # finding if a package.json under scope actually declares the package,
        # so we never steal a Python finding from pip_bump.
        return _find_package_json(manifest_raw, pkg) is not None

    def propose(self, finding: Finding, manifest_raw: dict) -> Proposal | None:
        ev = finding.evidence or {}
        pkg = ev.get("package")
        fixes = ev.get("fixed_in") or ev.get("fix_versions") or []
        if isinstance(fixes, str):
            fixes = [fixes]
        fixes = [v for v in fixes if v]
        if not pkg or not fixes:
            return None
        fix = min(fixes, key=_version_key)

        pj = _find_package_json(manifest_raw, pkg)
        if pj is None:
            return None
        data = json.loads(pj.read_text())
        data, changed = _bump_dep(data, pkg, fix)
        if not changed:
            return None
        new_content = json.dumps(data, indent=2) + "\n"

        return Proposal(
            summary=f"Bump {pkg} to ^{fix} in {pj}",
            confidence=0.85,
            rescan_adapter=finding.adapter,
            file_changes=[FileChange(path=str(pj.resolve()), new_content=new_content)],
            test_plan={"kind": "npm_pin", "package": pkg, "min_version": fix,
                       "package_json": str(pj.resolve())},
            notes=(
                f"Vuln {ev.get('vuln_id', 'advisory')}; installed "
                f"{ev.get('version') or ev.get('installed')}. Fixed in: "
                f"{', '.join(fixes)}. Run `npm install` to refresh the lockfile; "
                "the re-scan verifies the bump cleared the advisory."
            ),
        )
