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

from ..core.findings import FindingStore
from .scans import SCAN_LOG_DIR, ScanJob, get_scan, update_status_from_pid, write_scan


def main():
    scan_id, manifest_path, stage, adapter = sys.argv[1:5]
    findings_path = sys.argv[5]
    if adapter == "-":
        adapter = None
    log_path = SCAN_LOG_DIR / f"{scan_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    job = get_scan(scan_id)
    if job:
        job.status = "running"
        job.findings_before = len(FindingStore(findings_path).all())
        job.log_path = str(log_path)
        write_scan(job)

    cmd = [
        sys.executable, "-m", "pipeline.cli",
        "--findings", findings_path,
        "run", manifest_path,
        "--stage", stage,
    ]
    if adapter:
        cmd += ["--adapter", adapter]

    # Run the CLI; tee output to log file.
    with open(log_path, "w") as logf:
        proc = subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT)

    findings_after = len(FindingStore(findings_path).all())
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


if __name__ == "__main__":
    main()
