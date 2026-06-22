"""tplmap adapter — confirm Server-Side Template Injection (SSTI).

SSTI is squarely an LLM-app risk: model output (or user input) interpolated
into a server-side template (Jinja2, Twig, Freemarker, ERB, ...) yields code
execution. tplmap takes a URL/parameter and confirms the injection plus the
template engine.

REQUIRES `target.allow_mutation = True` — it issues crafted-payload requests
and, on confirmation, can reach code execution on the target.

Repo: https://github.com/epinna/tplmap
"""
from __future__ import annotations

import logging
import shutil
import subprocess

from ..core.dast_config import DastConfig
from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable

log = logging.getLogger("ai-protect.tplmap")


def _which_tplmap() -> str | None:
    for cand in ("tplmap", "tplmap.py"):
        path = shutil.which(cand)
        if path:
            return path
    return None


class TplmapAdapter(Adapter):
    name = "tplmap"
    description = "tplmap — server-side template injection confirmation (DAST exploitation)"
    requires_mutation = True

    def preflight(self) -> None:
        super().preflight()
        if not _which_tplmap():
            raise AdapterUnavailable(
                "tplmap not on PATH. Install: clone https://github.com/epinna/tplmap "
                "and expose tplmap.py as 'tplmap'."
            )
        if not self.manifest.target.base_url:
            raise AdapterUnavailable("Manifest has no target.base_url to test.")

    def run(self):
        self.preflight()
        dc = DastConfig.from_manifest(self.manifest)
        binary = _which_tplmap()
        target = self.manifest.target.base_url
        timeout = dc.subprocess_timeout(override=900)
        cmd = [binary, "-u", target] + list(self.config.get("args", []))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable(f"tplmap exceeded timebox ({timeout}s)")
        except OSError as e:
            raise AdapterUnavailable(f"tplmap could not be executed: {e}")
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")

        tier = classify(self.manifest).tier
        findings = []
        low = output.lower()
        confirmed = "injection point" in low or "template engine" in low or "tplmap identified" in low
        if confirmed:
            # Pull the reported engine if tplmap printed it.
            engine = None
            for line in output.splitlines():
                if "template engine" in line.lower():
                    engine = line.split(":", 1)[-1].strip() or None
                    break
            findings.append(self.make_finding(
                tier=tier,
                category=Category.INFRA_VULN,
                severity=Severity.CRITICAL,
                title=f"tplmap: SSTI confirmed{f' ({engine})' if engine else ''}",
                description=(
                    "tplmap confirmed a server-side template injection"
                    + (f" in the {engine} engine." if engine else ".")
                    + " SSTI commonly escalates to remote code execution."
                ),
                evidence={"target": target, "engine": engine, "stdout_tail": output[-3000:]},
                affected={"target": target},
                remediation=(
                    "Never render user- or model-controlled strings as templates. Use a "
                    "logic-less/sandboxed template mode, pass untrusted data as context "
                    "variables only, and escape on output."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/07-Input_Validation_Testing/"
                    "18-Testing_for_Server-side_Template_Injection",
                ],
            ))
        return findings
