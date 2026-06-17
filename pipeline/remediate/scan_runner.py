"""Subprocess wrapper that runs the CLI and writes a completion marker.

Invoked by the UI (not user-facing). Args:
    python -m pipeline.remediate.scan_runner <scan_id> <manifest> <stage> <adapter|->
The wrapper writes a JSON marker next to the log file when done so the UI
poller can read exit_code + findings delta.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from ..core.dashboard import active_count_for_app
from ..core.findings import FindingStore
from ..core.manifest import Manifest
from .scans import SCAN_LOG_DIR, ScanJob, emit_event, get_scan, update_status_from_pid, write_scan


def _active_count(findings_path: str, app_name: str) -> int:
    """Active findings (deduped, resolved-filtered, alias-honored) for `app_name`.

    Falls back to raw row count for the app on any error — the runner mustn't
    crash just because dashboard computation has a hiccup.
    """
    try:
        return active_count_for_app(FindingStore(findings_path), app_name)
    except Exception:
        try:
            return sum(1 for f in FindingStore(findings_path).all() if f.app_name == app_name)
        except Exception:
            return 0


def main():
    scan_id, manifest_path, stage, adapter = sys.argv[1:5]
    findings_path = sys.argv[5]
    if adapter == "-":
        adapter = None
    log_path = SCAN_LOG_DIR / f"{scan_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Detect ad-hoc DAST manifests (synthesized by the UI for arbitrary-URL
    # scans, written to ~/.ai-protect/adhoc-scans/<scan_id>.yml). We always
    # delete these in the finally block — even on crash — so the dir doesn't
    # accumulate cruft. The defense-in-depth janitor on /scan GET handles
    # the leftover from any runner that died before reaching this point.
    adhoc_to_delete: Path | None = None
    try:
        if Path(manifest_path).resolve().parent.name == "adhoc-scans":
            adhoc_to_delete = Path(manifest_path).resolve()
    except OSError:
        pass

    try:
        # Resolve app_name from the manifest — used to scope before/after counts.
        try:
            app_name = Manifest.from_yaml(manifest_path).name
        except Exception:
            app_name = ""

        job = get_scan(scan_id)
        if job:
            job.status = "running"
            # Active count for THIS app (deduped + resolved-filtered), not raw store size.
            # The raw store grows by ~100 rows on every rescan because findings are
            # append-only; reporting raw counts confuses operators about what the
            # scan actually changed.
            job.findings_before = _active_count(findings_path, app_name) if app_name else 0
            job.log_path = str(log_path)
            write_scan(job)

        cmd = [
            sys.executable, "-m", "pipeline.cli",
            "--findings", findings_path,
            "run", manifest_path,
            "--stage", stage,
            "--scan-id", scan_id,
        ]
        if adapter:
            cmd += ["--adapter", adapter]

        # Run the CLI; tee output to log file.
        with open(log_path, "w") as logf:
            # nosec B603 nosemgrep: dangerous-subprocess-use-tainted-env-args
            # — list-form (no shell); scan_id/manifest/stage/adapter are validated
            # by the UI before this runner is spawned.
            proc = subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT)

        findings_after = _active_count(findings_path, app_name) if app_name else 0
        marker = {
            "exit_code": proc.returncode,
            "findings_after": findings_after,
            "ended_at": time.time(),
        }
        Path(str(log_path).replace(".log", ".done")).write_text(json.dumps(marker))

        job = get_scan(scan_id)
        if job:
            job.exit_code = proc.returncode
            job.findings_after = findings_after
            job.status = "done" if proc.returncode in (0, 2) else "failed"
            job.ended_at = time.time()
            write_scan(job)
            emit_event(job, f"scan.{job.status}")
    finally:
        # Best-effort cleanup of the synthetic adhoc YAML. Ignored if the
        # file is already gone (concurrent janitor, manual cleanup, etc.).
        if adhoc_to_delete is not None:
            try:
                adhoc_to_delete.unlink()
            except (FileNotFoundError, OSError):
                pass


if __name__ == "__main__":
    main()
