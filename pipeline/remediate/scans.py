"""ScanJob — track UI-initiated scans (subprocess-spawned) so we can poll status."""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .state import REMEDIATE_HOME

SCAN_LOG_DIR = REMEDIATE_HOME / "scans"
SCANS_PATH = REMEDIATE_HOME / "scans.jsonl"


@dataclass
class ScanJob:
    scan_id: str
    manifest_path: str
    app_name: str
    stage: str
    adapter: str | None       # None = all adapters at this stage
    status: str               # "pending" | "running" | "done" | "failed"
    pid: int | None = None
    log_path: str = ""
    started_at: float = field(default_factory=time.time)
    ended_at: float | None = None
    exit_code: int | None = None
    findings_before: int = 0
    findings_after: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def new_scan_id() -> str:
    return f"s-{int(time.time())}-{uuid.uuid4().hex[:6]}"


def write_scan(job: ScanJob) -> None:
    SCANS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SCANS_PATH, "a") as f:
        f.write(json.dumps(job.to_dict()) + "\n")


def all_scans() -> list[ScanJob]:
    if not SCANS_PATH.exists():
        return []
    latest: dict[str, ScanJob] = {}
    with open(SCANS_PATH) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                latest[d["scan_id"]] = ScanJob(**d)
            except Exception:
                continue
    return sorted(latest.values(), key=lambda j: -j.started_at)


def get_scan(scan_id: str) -> ScanJob | None:
    for j in all_scans():
        if j.scan_id == scan_id:
            return j
    return None


def update_status_from_pid(job: ScanJob) -> ScanJob:
    """If pid is alive, mark running; if dead, look up exit via wait/log."""
    if job.status in ("done", "failed", "stopped"):
        return job
    if not job.pid:
        return job
    try:
        os.kill(job.pid, 0)
        job.status = "running"
    except OSError:
        # Process gone. Read marker file if present.
        marker = Path(job.log_path).with_suffix(".done")
        if marker.exists():
            try:
                payload = json.loads(marker.read_text())
                job.exit_code = payload.get("exit_code", 0)
                job.findings_after = payload.get("findings_after")
                job.status = "done" if job.exit_code in (0, 2) else "failed"
                job.ended_at = payload.get("ended_at", time.time())
            except Exception:
                job.status = "failed"
                job.ended_at = time.time()
        else:
            job.status = "failed"
            job.ended_at = time.time()
        write_scan(job)
    return job
