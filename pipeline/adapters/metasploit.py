"""Metasploit adapter (RPC).

Reserved for Tier 1 / authorized engagements only. The default behavior is to
enumerate auxiliary scanners and run only non-exploitative modules unless the
manifest sets target.allow_mutation = True. Even then, exploit modules require
an explicit allow-list in the adapter config.

Talks to msfrpcd over its RPC API (pymetasploit3 client).

Repo: https://github.com/rapid7/metasploit-framework
Client: https://github.com/DanMcInerney/pymetasploit3
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterAuthorizationRequired, AdapterUnavailable

log = logging.getLogger("ai-protect.msf")


# Default modules — auxiliary scanners only. Read-only network surface enumeration.
DEFAULT_AUX_MODULES = [
    "auxiliary/scanner/http/http_version",
    "auxiliary/scanner/http/title",
    "auxiliary/scanner/http/options",
    "auxiliary/scanner/http/cors_misconfig",
]


class MetasploitAdapter(Adapter):
    name = "metasploit"
    description = "Rapid7 Metasploit — auxiliary scanners (default) or exploits (Tier 1, authorized)"

    @property
    def requires_mutation(self) -> bool:
        # Exploit modules are mutating; auxiliary scanners are not.
        return any(m.startswith("exploit/") for m in self._modules())

    def _modules(self) -> list[str]:
        return self.config.get("modules", DEFAULT_AUX_MODULES)

    def preflight(self) -> None:
        super().preflight()
        try:
            from pymetasploit3.msfrpc import MsfRpcClient  # noqa: F401
        except ImportError as e:
            raise AdapterUnavailable("pymetasploit3 not installed (pip install pymetasploit3)") from e
        if not (os.environ.get("MSF_RPC_HOST") and os.environ.get("MSF_RPC_PASSWORD")):
            raise AdapterUnavailable("MSF_RPC_HOST and MSF_RPC_PASSWORD must be set.")
        if not self.manifest.target.base_url:
            raise AdapterUnavailable("Manifest has no target.base_url to point modules at.")
        # Tier-1 + explicit allow-list required for exploit modules.
        modules = self._modules()
        for m in modules:
            if m.startswith("exploit/"):
                tier = classify(self.manifest).tier
                if tier != 1:
                    raise AdapterAuthorizationRequired(
                        f"Exploit module {m!r} requires Tier 1 — manifest is Tier {tier}."
                    )
                if not self.config.get("authorized_exploits"):
                    raise AdapterAuthorizationRequired(
                        f"Exploit module {m!r} requires authorized_exploits allow-list in adapter config."
                    )
                if m not in self.config["authorized_exploits"]:
                    raise AdapterAuthorizationRequired(
                        f"Exploit module {m!r} is not in authorized_exploits."
                    )

    def run(self):
        self.preflight()
        from pymetasploit3.msfrpc import MsfRpcClient

        client = MsfRpcClient(
            os.environ["MSF_RPC_PASSWORD"],
            server=os.environ["MSF_RPC_HOST"],
            port=int(os.environ.get("MSF_RPC_PORT", "55553")),
            ssl=os.environ.get("MSF_RPC_SSL", "true").lower() == "true",
        )
        target = self.manifest.target.base_url
        rhosts = target.split("//", 1)[-1].split("/", 1)[0]
        tier = classify(self.manifest).tier

        findings = []
        for module_name in self._modules():
            kind, _, name = module_name.partition("/")
            try:
                mod = client.modules.use(kind, "/".join(module_name.split("/")[1:]))
                mod["RHOSTS"] = rhosts
                cid = mod.execute()
                # Wait briefly for the job to complete (auxiliary scanners are short).
                self._wait_for_job(client, cid.get("job_id"), timeout_s=self.config.get("timeout_s", 60))
                # Read the console for output.
                output = self._drain_consoles(client)
            except Exception as e:
                log.warning("metasploit module %s raised %s", module_name, e)
                continue
            findings.append(self.make_finding(
                tier=tier,
                category=Category.INFRA_VULN,
                severity=Severity.INFO,
                title=f"Metasploit module {module_name} executed",
                description=(
                    f"Module {module_name} ran against {rhosts}. Output captured for SCV review."
                ),
                evidence={"module": module_name, "rhosts": rhosts, "output": output[-2000:]},
                affected={"target": target},
                remediation=None,
                references=[f"https://www.rapid7.com/db/?q={module_name}"],
            ))
        return findings

    @staticmethod
    def _wait_for_job(client, job_id, timeout_s=60):
        if not job_id:
            return
        import time
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            jobs = client.jobs.list
            if str(job_id) not in jobs:
                return
            time.sleep(2)

    @staticmethod
    def _drain_consoles(client) -> str:
        out = []
        for c in client.consoles.list:
            try:
                con = client.consoles.console(c["id"])
                out.append(con.read().get("data", ""))
            except Exception:
                continue
        return "\n".join(out)
