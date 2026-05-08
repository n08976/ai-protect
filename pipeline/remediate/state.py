"""Lifecycle state machine + Change / Event dataclasses + append-only stores.

Changes flow through:
    new → triaged → proposed → tests_generated → approved → applied → validated → deployed
                       │             │              │           │           │
                       ▼             ▼              ▼           ▼           ▼
                   rejected   no_test_possible  rejected    reverted    accepted

The state machine is enforced by Engine.transition() — any invalid transition
raises. Every transition emits an event.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


REMEDIATE_HOME = Path(os.path.expanduser("~/.ai-protect"))
BACKUPS_DIR = REMEDIATE_HOME / "backups"
EVENTS_PATH = REMEDIATE_HOME / "events.jsonl"
CHANGES_PATH = REMEDIATE_HOME / "changes.jsonl"


class ChangeState(str, Enum):
    PROPOSED = "proposed"
    TESTS_GENERATED = "tests_generated"
    NO_TEST_POSSIBLE = "no_test_possible"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"
    VALIDATED = "validated"
    REVERTED = "reverted"
    DEPLOYED = "deployed"
    ACCEPTED = "accepted"


# Allowed transitions. State machine; everything else raises.
ALLOWED: dict[ChangeState, set[ChangeState]] = {
    ChangeState.PROPOSED:           {ChangeState.TESTS_GENERATED, ChangeState.NO_TEST_POSSIBLE, ChangeState.REJECTED},
    ChangeState.TESTS_GENERATED:    {ChangeState.APPROVED, ChangeState.REJECTED},
    ChangeState.NO_TEST_POSSIBLE:   {ChangeState.APPROVED, ChangeState.REJECTED},
    ChangeState.APPROVED:           {ChangeState.APPLIED, ChangeState.REJECTED},
    ChangeState.APPLIED:            {ChangeState.VALIDATED, ChangeState.REVERTED},
    ChangeState.VALIDATED:          {ChangeState.DEPLOYED, ChangeState.REVERTED},
    ChangeState.REVERTED:           set(),
    ChangeState.DEPLOYED:           {ChangeState.REVERTED, ChangeState.ACCEPTED},
    ChangeState.REJECTED:           set(),
    ChangeState.ACCEPTED:           set(),
}


@dataclass
class FileEdit:
    """One file touched by a change. Backups + hashes recorded."""
    path: str                    # absolute path to original file
    backup_path: str = ""        # absolute path to backup; "" if file didn't exist before
    sha_before: str = ""         # sha256 of original; "" if file didn't exist
    sha_after: str = ""          # sha256 of patched
    created: bool = False        # true if engine created the file (no original)


@dataclass
class TestRecord:
    name: str                    # e.g. "test_flask_xfo_header"
    path: str                    # absolute path to generated test file
    pre_apply_passed: bool | None = None    # null = not run; expect False (test should fail before fix)
    post_apply_passed: bool | None = None   # null = not run; expect True


@dataclass
class Change:
    change_id: str
    finding_id: str
    finding_fingerprint: str
    app_name: str
    tier: int
    strategy: str               # e.g. "pip_bump" | "header_snippet"
    state: ChangeState
    confidence: float
    summary: str
    diff: str = ""              # unified diff
    files: list[FileEdit] = field(default_factory=list)
    tests: list[TestRecord] = field(default_factory=list)
    test_status: str = "pending"  # pending | generated | not_generatable | passed | failed
    test_status_reason: str = ""
    rescan_adapter: str = ""    # which adapter to re-run after apply
    proposed_at: float = field(default_factory=time.time)
    last_state_at: float = field(default_factory=time.time)
    actor: str = "auto"
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Change":
        d = dict(d)
        d["state"] = ChangeState(d["state"])
        d["files"] = [FileEdit(**f) for f in d.get("files", [])]
        d["tests"] = [TestRecord(**t) for t in d.get("tests", [])]
        return cls(**d)


def new_change_id() -> str:
    """Short, time-prefixed id."""
    return f"c-{int(time.time())}-{uuid.uuid4().hex[:6]}"


# ---------- append-only stores ----------

class EventStore:
    """Append-only event log. Every state transition + scan + rollback is one row."""
    def __init__(self, path: Path = EVENTS_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: str, **payload) -> dict:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **payload}
        with open(self.path, "a") as f:
            f.write(json.dumps(rec) + "\n")
        return rec

    def all(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out


class ChangeStore:
    """Append-only change log. Latest row per change_id wins."""
    def __init__(self, path: Path = CHANGES_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, Change] | None = None

    def write(self, change: Change) -> None:
        change.last_state_at = time.time()
        with open(self.path, "a") as f:
            f.write(json.dumps(change.to_dict()) + "\n")
        self._cache = None

    def all(self) -> list[Change]:
        if not self.path.exists():
            return []
        latest: dict[str, Change] = {}
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    c = Change.from_dict(d)
                    latest[c.change_id] = c
                except Exception:
                    continue
        self._cache = latest
        return sorted(latest.values(), key=lambda c: -c.proposed_at)

    def get(self, change_id: str) -> Change | None:
        if self._cache is None:
            self.all()
        return (self._cache or {}).get(change_id)

    def for_finding(self, finding_id: str) -> list[Change]:
        return [c for c in self.all() if c.finding_id == finding_id]

    def in_states(self, *states: ChangeState) -> list[Change]:
        s = set(states)
        return [c for c in self.all() if c.state in s]
