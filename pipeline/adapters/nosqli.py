"""nosqli adapter — confirm NoSQL injection (MongoDB operator / JS injection).

Targets the NoSQL-injection class Nuclei/ZAP only hint at: MongoDB operator
injection ($ne/$gt/$nin), error-based, boolean-blind, and timing-based
injection. Relevant for LLM apps backing memory/vector metadata onto
Mongo-style stores.

nosqli (Charlie-belmer) replaces the originally-scoped NoSQLMap, which is
Python-2-only and interactive-menu-driven — it cannot run headless in a scan
pipeline. nosqli is a maintained, single-binary, non-interactive scanner with
deterministic stdout, so it fits the adapter model cleanly.

REQUIRES `target.allow_mutation = True` — it issues many crafted-payload
requests against the target.

Repo: https://github.com/Charlie-belmer/nosqli
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess

from ..core.dast_config import DastConfig
from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable

log = logging.getLogger("ai-protect.nosqli")

# nosqli prints one block per confirmed injection:
#   Found <Type> NoSQL Injection:
#       URL: <url>
#       param: <param>
#       Injection: <param>=<value>
_BLOCK = re.compile(
    r"Found\s+(?P<type>.+?NoSQL Injection):\s*"
    r"URL:\s*(?P<url>\S+)\s*"
    r"param:\s*(?P<param>\S+)\s*"
    r"Injection:\s*(?P<inj>.+)",
    re.IGNORECASE,
)


class NosqliAdapter(Adapter):
    name = "nosqli"
    description = "nosqli — NoSQL injection confirmation (DAST exploitation)"
    requires_mutation = True

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("nosqli"):
            raise AdapterUnavailable(
                "nosqli not on PATH. Install the prebuilt binary from "
                "https://github.com/Charlie-belmer/nosqli/releases "
                "to /usr/local/bin/nosqli."
            )
        if not self.manifest.target.base_url:
            raise AdapterUnavailable("Manifest has no target.base_url to test.")
        dc = DastConfig.from_manifest(self.manifest)
        refusal = dc.refuse_bare_origin_for(self.name)
        if refusal:
            raise AdapterUnavailable(refusal)

    def run(self):
        self.preflight()
        dc = DastConfig.from_manifest(self.manifest)
        target = self.manifest.target.base_url
        timeout = dc.subprocess_timeout(override=900)
        # nosqli has no rate/concurrency flags of its own; the subprocess
        # timebox is the only knob. Optional POST data via config['data'].
        cmd = ["nosqli", "scan", "-t", target]
        if self.config.get("data"):
            cmd += ["-d", str(self.config["data"])]
        if self.config.get("insecure"):
            cmd += ["--insecure"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable(f"nosqli exceeded timebox ({timeout}s)")
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")

        tier = classify(self.manifest).tier
        findings = []
        for m in _BLOCK.finditer(output):
            inj_type = m.group("type").strip()
            param = m.group("param").strip()
            findings.append(self.make_finding(
                tier=tier,
                category=Category.INFRA_VULN,
                severity=Severity.HIGH,
                title=f"nosqli: {inj_type} on parameter '{param}'",
                description=(
                    f"nosqli confirmed a {inj_type.lower()} against parameter "
                    f"'{param}'. The endpoint reflects NoSQL operators / payloads "
                    "into a backend query."
                ),
                evidence={
                    "type": inj_type,
                    "param": param,
                    "injection": m.group("inj").strip(),
                    "url": m.group("url").strip(),
                },
                affected={"target": target, "url": m.group("url").strip()},
                remediation=(
                    "Reject query operators in user input ($ne/$gt/$nin/$where), cast "
                    "and validate types server-side, disable server-side JS evaluation, "
                    "and use a driver that parameterizes queries."
                ),
                references=["https://owasp.org/www-community/Testing_for_NoSQL_injection"],
            ))
        return findings
