"""promptfoo + DeepEval adapter — AI eval frameworks.

Both are eval frameworks that complement PyRIT. They run a curated suite of
test cases (e.g. medical-QA correctness, safety refusals, instruction
following) against a model and emit pass/fail per test. We treat their
results as eval_suite-class findings.

This adapter prefers promptfoo (CLI) when available, falls back to DeepEval
(Python) — both are wired here so the pipeline degrades gracefully.

Repos:
  https://github.com/promptfoo/promptfoo
  https://github.com/confident-ai/deepeval
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable

log = logging.getLogger("ai-protect.promptfoo")


class PromptfooAdapter(Adapter):
    name = "promptfoo"
    description = "promptfoo + DeepEval — curated AI eval suites (correctness, safety, refusal)"

    def preflight(self) -> None:
        super().preflight()
        if not (shutil.which("promptfoo") or shutil.which("deepeval")):
            raise AdapterUnavailable(
                "Neither promptfoo nor deepeval on PATH. Install: "
                "npm i -g promptfoo  OR  pip install deepeval"
            )
        if not self.manifest.models:
            raise AdapterUnavailable("Manifest has no model endpoints declared.")

    def run(self):
        self.preflight()
        if shutil.which("promptfoo"):
            return self._run_promptfoo()
        if shutil.which("deepeval"):
            return self._run_deepeval()
        return []

    def _run_promptfoo(self):
        """Run a promptfoo eval. Caller provides the YAML config path via adapter config."""
        config = self.config.get("config_path")
        if not config or not Path(config).exists():
            raise AdapterUnavailable(
                "promptfoo requires config_path in adapter config (path to promptfoo YAML)."
            )
        with tempfile.TemporaryDirectory(prefix="ai-protect-promptfoo-") as td:
            out_path = str(Path(td) / "promptfoo_out.json")
            try:
                proc = subprocess.run(
                    ["promptfoo", "eval", "-c", config, "-o", out_path, "--no-progress-bar"],
                    capture_output=True, text=True, timeout=900, check=False,
                )
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable("promptfoo timed out")
            try:
                data = json.loads(Path(out_path).read_text())
            except Exception:
                return []
        return list(self._parse_promptfoo(data))

    def _parse_promptfoo(self, data: dict):
        from ..core.tiering import classify
        tier = classify(self.manifest).tier
        for r in (data.get("results", {}) or {}).get("results", []) or []:
            if r.get("success"):
                continue
            yield self.make_finding(
                tier=tier,
                category=Category.HALLUCINATION,
                severity=Severity.HIGH if tier <= 2 else Severity.MEDIUM,
                title=f"promptfoo eval failed: {r.get('test', {}).get('description', 'eval')}",
                description=(r.get("error") or r.get("response", {}).get("output", ""))[:1500],
                evidence={
                    "prompt": (r.get("prompt", {}) or {}).get("raw", "")[:1000],
                    "expected": r.get("test", {}).get("assert"),
                    "actual": r.get("response", {}).get("output", "")[:1000],
                },
                affected={"model": self.manifest.models[0].model},
                remediation=(
                    "Review the failing test case. If a prompt change is the right response, "
                    "update the system prompt; if the model is wrong, raise refusal threshold "
                    "or add gateway DLP."
                ),
                references=["https://promptfoo.dev/docs/"],
            )

    def _run_deepeval(self):
        """DeepEval is library-first; this is a thin runner that requires a test file."""
        test_file = self.config.get("test_file")
        if not test_file or not Path(test_file).exists():
            raise AdapterUnavailable(
                "deepeval requires test_file in adapter config (path to pytest-style file)."
            )
        try:
            proc = subprocess.run(
                ["deepeval", "test", "run", test_file, "--quiet"],
                capture_output=True, text=True, timeout=900, check=False,
            )
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable("deepeval timed out")
        # DeepEval emits results to a local cache dir; parse stdout for fail markers.
        # Full integration would parse .deepeval-cache/test_run_*.json.
        from ..core.tiering import classify
        tier = classify(self.manifest).tier
        if "FAILED" in proc.stdout or "Failed" in proc.stdout:
            return [self.make_finding(
                tier=tier,
                category=Category.HALLUCINATION,
                severity=Severity.MEDIUM,
                title="deepeval suite reported failures",
                description="DeepEval test run had failed cases. See artifact for detail.",
                evidence={"stdout_tail": proc.stdout[-2000:]},
                affected={"model": self.manifest.models[0].model},
                remediation="Inspect .deepeval-cache and address failing metrics (faithfulness, hallucination, toxicity).",
                references=["https://docs.confident-ai.com/"],
            )]
        return []
