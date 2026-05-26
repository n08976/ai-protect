"""NVIDIA garak adapter.

garak is an LLM vulnerability scanner — a battery of probes for prompt
injection, encoding attacks, leakage, jailbreaks, toxicity, etc. We run it
as a subprocess and parse the JSONL report.

Repo: https://github.com/NVIDIA/garak
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..core.findings import Category, Finding, Severity
from .base import Adapter, AdapterUnavailable


# Map garak probe names → our finding categories. garak names are stable
# enough that this is maintainable; unknown probes default to OTHER.
PROBE_CATEGORY: dict[str, Category] = {
    "promptinject": Category.PROMPT_INJECTION,
    "promptinject.HijackHateHumans": Category.PROMPT_INJECTION,
    "dan": Category.JAILBREAK,
    "dan.Dan_11_0": Category.JAILBREAK,
    "encoding": Category.PROMPT_INJECTION,
    "leakreplay": Category.DATA_LEAKAGE,
    "knownbadsignatures": Category.HARMFUL_CONTENT,
    "malwaregen": Category.HARMFUL_CONTENT,
    "realtoxicityprompts": Category.HARMFUL_CONTENT,
    "snowball": Category.HALLUCINATION,
    "goodside": Category.PROMPT_INJECTION,
    "atkgen": Category.JAILBREAK,
    "xss": Category.HARMFUL_CONTENT,
    "lmrc": Category.HALLUCINATION,
    "continuation": Category.HARMFUL_CONTENT,
}


def _probe_to_category(probe: str) -> Category:
    if probe in PROBE_CATEGORY:
        return PROBE_CATEGORY[probe]
    base = probe.split(".", 1)[0]
    return PROBE_CATEGORY.get(base, Category.OTHER)


class GarakAdapter(Adapter):
    """Run garak probes against the manifest's primary model."""

    name = "garak"
    description = "NVIDIA garak — LLM vulnerability scanner (probes, encoding, leakage, jailbreak)"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("garak"):
            raise AdapterUnavailable(
                "garak CLI not on PATH. Install with: pip install garak"
            )
        if not self.manifest.models:
            raise AdapterUnavailable("Manifest has no model endpoints declared.")

    def _model_args(self) -> list[str]:
        """Convert the primary model declaration into garak --model_type / --model_name args."""
        model = self.manifest.models[0]
        provider_to_type = {
            "anthropic": "anthropic.AnthropicAPI",
            "openai": "openai.OpenAIGenerator",
            "azure": "openai.AzureOpenAI",
            "cohere": "cohere.CohereGenerator",
            "huggingface": "huggingface.Pipeline",
        }
        gtype = provider_to_type.get(model.provider, "rest.RestGenerator")
        return ["--model_type", gtype, "--model_name", model.model]

    def run(self) -> list[Finding]:
        self.preflight()
        from ..core.dast_config import DastConfig
        dc = DastConfig.from_manifest(self.manifest)
        probes = self.config.get("probes", "promptinject,leakreplay,encoding")
        with tempfile.TemporaryDirectory() as td:
            report_prefix = os.path.join(td, "garak_run")
            cmd = [
                "garak",
                *self._model_args(),
                "--probes", probes,
                "--report_prefix", report_prefix,
                "--generations", str(self.config.get("generations", 1)),
                # garak --parallel_requests controls concurrent calls to the
                # target model — same intent as max_concurrency.
                "--parallel_requests", str(dc.max_concurrency),
            ]
            env = os.environ.copy()
            for m in self.manifest.models:
                if m.auth_env:
                    # Make sure the credential is exported; garak reads from env.
                    if m.auth_env not in env:
                        raise AdapterUnavailable(
                            f"Auth env var {m.auth_env!r} for model {m.name!r} is not set."
                        )
            timeout = dc.subprocess_timeout(override=self.config.get("timeout_s", 1800))
            try:
                subprocess.run(
                    cmd,
                    env=env,
                    check=True,
                    timeout=timeout,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                raise AdapterUnavailable(f"garak exited non-zero: {e.stderr[:500]}")
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable(f"garak exceeded timebox ({timeout}s)")
            report_path = Path(report_prefix + ".report.jsonl")
            if not report_path.exists():
                # Older / newer garak versions may use a slightly different name.
                candidates = list(Path(td).glob("*.report.jsonl"))
                if not candidates:
                    raise AdapterUnavailable("garak report not found.")
                report_path = candidates[0]
            return list(self._parse_report(report_path))

    def _parse_report(self, report_path: Path):
        from ..core.tiering import classify
        tier = classify(self.manifest).tier
        with open(report_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("entry_type") != "attempt":
                    continue
                if rec.get("status") != "FAIL":  # garak: probe FAIL means model was vulnerable
                    continue
                probe = rec.get("probe_classname") or rec.get("probe", "unknown")
                detector = rec.get("detector", "unknown")
                category = _probe_to_category(probe)
                severity = self._severity(category, rec.get("score", 1.0))
                yield self.make_finding(
                    tier=tier,
                    category=category,
                    severity=severity,
                    title=f"garak probe {probe} flagged by detector {detector}",
                    description=(
                        f"Probe {probe!r} elicited a response that detector {detector!r} "
                        f"classified as a failure (model was vulnerable)."
                    ),
                    evidence={
                        "prompt": (rec.get("prompt") or "")[:2000],
                        "output": (rec.get("output") or "")[:2000],
                        "probe": probe,
                        "detector": detector,
                        "score": rec.get("score"),
                    },
                    affected={
                        "model": self.manifest.models[0].model,
                        "provider": self.manifest.models[0].provider,
                    },
                    remediation=(
                        "Review the gateway prompt-DLP rule and output filter for this category; "
                        "if the model is intended to handle this surface, raise the eval threshold."
                    ),
                    references=[
                        f"https://reference.garak.ai/en/latest/garak.probes.{probe.split('.')[0]}.html",
                    ],
                )

    @staticmethod
    def _severity(category: Category, score: float | None) -> Severity:
        # Categories that are always at-least HIGH in healthcare context.
        if category in (Category.DATA_LEAKAGE, Category.JAILBREAK):
            return Severity.HIGH
        if category in (Category.PROMPT_INJECTION, Category.TOOL_MISUSE):
            return Severity.MEDIUM
        return Severity.LOW
