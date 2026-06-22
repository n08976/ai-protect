"""Normalized finding schema.

Every adapter produces Finding objects with the same shape so the orchestrator
can aggregate, dedupe, score, and feed dashboards from a single store. Findings
carry an explicit compliance mapping so audit evidence is queryable.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Severity → numeric score for deduplication / dashboard rollups.
SEVERITY_SCORE = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 4,
    Severity.HIGH: 7,
    Severity.CRITICAL: 10,
}


class Category(str, Enum):
    """Top-level finding category. Drives dashboard panels."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    HALLUCINATION = "hallucination"
    DATA_LEAKAGE = "data_leakage"            # PHI / secrets / training data
    BIAS = "bias"
    HARMFUL_CONTENT = "harmful_content"
    TOOL_MISUSE = "tool_misuse"              # agent calling tools out of scope
    SCOPE_VIOLATION = "scope_violation"      # MCP / token scope bypass
    POLICY_BYPASS = "policy_bypass"          # gateway DLP bypass etc.
    SUPPLY_CHAIN = "supply_chain"
    INFRA_VULN = "infra_vuln"                # surrounding app / network
    SECRETS = "secrets"
    AUTH = "auth"
    OTHER = "other"


@dataclass
class Finding:
    finding_id: str
    app_name: str
    tier: int
    stage: str                       # "intake" | "design" | "build" | "preprod" | "production"
    adapter: str                     # "garak" | "pyrit" | "atomic" | ...
    category: Category
    severity: Severity
    title: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)  # prompt, response, payload, hash
    affected: dict[str, Any] = field(default_factory=dict)  # {"model": "...", "mcp": "...", ...}
    compliance: list[str] = field(default_factory=list)     # ["HIPAA-164.312(a)(1)", "HITRUST-IS.10", ...]
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    detected_at: float = field(default_factory=time.time)
    fingerprint: str = field(default="", repr=False)

    def __post_init__(self):
        if isinstance(self.category, str):
            self.category = Category(self.category)
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if not self.fingerprint:
            self.fingerprint = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        """Stable hash for dedup across repeated runs."""
        key = f"{self.app_name}|{self.adapter}|{self.category.value}|{self.title}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def severity_score(self) -> int:
        return SEVERITY_SCORE[self.severity]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d


def new_finding(**kwargs) -> Finding:
    """Convenience: auto-assign finding_id."""
    if "finding_id" not in kwargs:
        kwargs["finding_id"] = str(uuid.uuid4())
    return Finding(**kwargs)


class FindingStore:
    """Append-only JSONL store. Adapters write to the same file the dashboard reads from."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cache: list[Finding] | None = None

    def append(self, finding: Finding) -> None:
        with open(self.path, "a") as f:
            f.write(json.dumps(finding.to_dict()) + "\n")
        self._cache = None

    def append_many(self, findings: list[Finding]) -> None:
        with open(self.path, "a") as f:
            for finding in findings:
                f.write(json.dumps(finding.to_dict()) + "\n")
        self._cache = None

    def all(self) -> list[Finding]:
        if self._cache is not None:
            return self._cache
        if not self.path.exists():
            self._cache = []
            return self._cache
        out: list[Finding] = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                out.append(Finding(**d))
        self._cache = out
        return out

    def by_app(self, app_name: str) -> list[Finding]:
        return [f for f in self.all() if f.app_name == app_name]
