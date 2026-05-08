"""SplxAI Agentic Radar adapter — SAST for agentic AI workflows.

Agentic Radar is purpose-built for the artifact class that is exploding inside
the org: agent definitions, tool/MCP wiring, multi-agent orchestrations. It
inspects agent code (LangChain, LlamaIndex, CrewAI, Claude Agent SDK,
OpenAI Assistants, custom shapes) and surfaces:
  - over-broad tool grants and unconstrained tool chaining
  - PII / PHI flow into prompts
  - agent-to-agent privilege escalation paths
  - prompt-injection-prone input handling

This sits alongside Bandit / Semgrep at the build stage but covers the
agent-shape surface the generic Python SAST tools miss.

Repo: https://github.com/splx-ai/agentic-radar
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _categorize(rule: str, message: str) -> Category:
    text = f"{rule} {message}".lower()
    if "prompt" in text or "injection" in text or "jailbreak" in text:
        return Category.PROMPT_INJECTION
    if "pii" in text or "phi" in text or "leak" in text or "secret" in text:
        return Category.DATA_LEAKAGE
    if "tool" in text and ("scope" in text or "permission" in text or "grant" in text):
        return Category.TOOL_MISUSE
    if "scope" in text or "tenant" in text:
        return Category.SCOPE_VIOLATION
    if "policy" in text or "guardrail" in text or "bypass" in text:
        return Category.POLICY_BYPASS
    return Category.OTHER


class AgenticRadarAdapter(Adapter):
    name = "agentic_radar"
    description = "SplxAI Agentic Radar — SAST for agentic AI workflows (LangChain, LlamaIndex, CrewAI, Claude Agent SDK)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("agentic-radar"):
            raise AdapterUnavailable(
                "agentic-radar not on PATH. Install: pipx install agentic-radar"
            )

    def run(self):
        self.preflight()
        path = self.config.get("path", self.manifest.raw.get("source_path", "."))
        cmd = ["agentic-radar", "scan", "--format", "json", path]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get("timeout_s", 600),
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable("agentic-radar timed out")

        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            raise AdapterUnavailable(
                f"agentic-radar produced non-JSON output: {(proc.stderr or '')[:500]}"
            )

        # Tolerate either {"findings": [...]} or a top-level list.
        items = data.get("findings", data) if isinstance(data, dict) else data
        if not isinstance(items, list):
            return []

        tier = classify(self.manifest).tier
        findings = []
        for item in items:
            rule = item.get("rule") or item.get("rule_id") or item.get("id") or "unknown-rule"
            severity = SEVERITY_MAP.get(str(item.get("severity", "low")).lower(), Severity.LOW)
            message = item.get("message") or item.get("description") or rule
            findings.append(self.make_finding(
                tier=tier,
                category=_categorize(rule, message),
                severity=severity,
                title=f"Agentic Radar: {rule}",
                description=message[:1500],
                evidence={
                    "rule": rule,
                    "file": item.get("file") or item.get("path"),
                    "line": item.get("line"),
                    "agent": item.get("agent"),
                    "tool": item.get("tool"),
                    "snippet": (item.get("snippet") or "")[:1000],
                },
                affected={
                    "file": item.get("file") or item.get("path"),
                    "agent": item.get("agent"),
                },
                remediation=item.get("remediation"),
                references=item.get("references", [
                    "https://github.com/splx-ai/agentic-radar",
                ]),
            ))
        return findings
