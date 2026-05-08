"""Backup + restore primitives.

Every file the engine touches gets a backup at:
    ~/.ai-protect/backups/<change_id>/files/<absolute-original-path>

A manifest.json sits alongside, recording the file list, SHAs, and the
strategy/finding that produced the change. Backups never auto-delete; a
purge job (Phase 2) honors a 365-day retention window.

Restore reads the manifest, copies each .bak back to the original path,
verifies the post-restore SHA matches sha_before. If a file was created
by the engine (created=true), restore deletes it instead.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from dataclasses import asdict
from pathlib import Path

from .state import BACKUPS_DIR, Change, FileEdit


def sha256_file(path: Path) -> str:
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def backup_dir_for(change_id: str) -> Path:
    return BACKUPS_DIR / change_id


def backup_file(change_id: str, original_path: str | Path) -> FileEdit:
    """Snapshot a file before editing. Returns a FileEdit with backup path + sha."""
    orig = Path(original_path).resolve()
    bdir = backup_dir_for(change_id) / "files"
    # Mirror absolute path under bdir; strip leading slash so path joins cleanly.
    rel = str(orig).lstrip("/")
    bpath = bdir / (rel + ".bak")
    bpath.parent.mkdir(parents=True, exist_ok=True)
    if orig.exists():
        shutil.copy2(orig, bpath)
        return FileEdit(
            path=str(orig),
            backup_path=str(bpath),
            sha_before=sha256_file(orig),
            created=False,
        )
    # File doesn't exist → engine will create it. Record an empty-marker backup.
    bpath.write_text("__AIPROTECT_FILE_DID_NOT_EXIST__\n")
    return FileEdit(
        path=str(orig),
        backup_path=str(bpath),
        sha_before="",
        created=True,
    )


def write_change_manifest(change: Change) -> Path:
    """Write the change's manifest.json into the backup dir for audit + restore."""
    bdir = backup_dir_for(change.change_id)
    bdir.mkdir(parents=True, exist_ok=True)
    mpath = bdir / "manifest.json"
    mpath.write_text(json.dumps(change.to_dict(), indent=2, default=str))
    return mpath


def restore_change(change: Change) -> list[str]:
    """Roll back a change. Returns list of files restored or removed."""
    actions: list[str] = []
    for fe in change.files:
        orig = Path(fe.path)
        if fe.created:
            if orig.exists():
                orig.unlink()
                actions.append(f"deleted {orig}")
        else:
            bpath = Path(fe.backup_path)
            if not bpath.exists():
                actions.append(f"WARN backup missing for {orig}")
                continue
            shutil.copy2(bpath, orig)
            new_sha = sha256_file(orig)
            if new_sha == fe.sha_before:
                actions.append(f"restored {orig}")
            else:
                actions.append(f"WARN sha mismatch after restore for {orig}")
    return actions
