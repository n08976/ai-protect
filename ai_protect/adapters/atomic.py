"""Red Canary Atomic Red Team adapter.

Atomic Red Team is a library of small, portable tests mapped to MITRE ATT&CK
techniques. We use it to exercise the *agent runtime host* — testing whether
EDR sees the techniques an agent could plausibly produce (T1059 command exec,
T1567 exfiltration to web service, T1071 application-layer C2, etc.).

This is the "validate the host" leg of agent runtime defense — independent of
whether the LLM is misbehaving, can detection see what an agent could do?

Repo: https://github.com/redcanaryco/atomic-red-team

This adapter REQUIRES `target.allow_mutation = True` in the manifest. Atomic
tests can drop files, run processes, and trigger AV — never run them outside
an authorized validation environment.
"""
from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable

log = logging.getLogger("ai-protect.atomic")


# Default technique set — agent-runtime relevant.
DEFAULT_TECHNIQUES = [
    "T1059",   # Command and Scripting Interpreter
    "T1071",   # Application Layer Protocol (C2)
    "T1567",   # Exfiltration over Web Service
    "T1105",   # Ingress Tool Transfer
    "T1136",   # Create Account (privilege escalation surface)
]


class AtomicRedTeamAdapter(Adapter):
    name = "atomic"
    description = "Red Canary Atomic Red Team — adversary emulation mapped to MITRE ATT&CK"
    requires_mutation = True

    def preflight(self) -> None:
        super().preflight()
        # Require either Invoke-AtomicRedTeam (PowerShell) or AtomicTestHarnesses
        if not (shutil.which("pwsh") or shutil.which("powershell")):
            raise AdapterUnavailable(
                "PowerShell (pwsh) not on PATH; Atomic Red Team requires Invoke-AtomicRedTeam."
            )
        atomics_root = self.config.get(
            "atomics_root",
            os.environ.get("ATOMIC_RED_TEAM_PATH", "/opt/atomic-red-team/atomics"),
        )
        if not Path(atomics_root).exists():
            raise AdapterUnavailable(
                f"atomics/ directory not found at {atomics_root}. "
                "Clone redcanaryco/atomic-red-team and set ATOMIC_RED_TEAM_PATH."
            )

    def run(self):
        self.preflight()
        techniques = self.config.get("techniques", DEFAULT_TECHNIQUES)
        atomics_root = self.config.get(
            "atomics_root",
            os.environ.get("ATOMIC_RED_TEAM_PATH", "/opt/atomic-red-team/atomics"),
        )
        tier = classify(self.manifest).tier
        findings = []

        for technique in techniques:
            with tempfile.TemporaryDirectory() as td:
                log_path = Path(td) / "atomic.log"
                ps_script = (
                    f"Import-Module Invoke-AtomicRedTeam -Force; "
                    f"$PSDefaultParameterValues['Invoke-AtomicTest:PathToAtomicsFolder']='{atomics_root}'; "
                    f"Invoke-AtomicTest {technique} -GetPrereqs *> '{log_path}'; "
                    f"Invoke-AtomicTest {technique} -Confirm:$false *>> '{log_path}'; "
                    f"Invoke-AtomicTest {technique} -Cleanup -Confirm:$false *>> '{log_path}'"
                )
                shell = shutil.which("pwsh") or shutil.which("powershell")
                proc = subprocess.run(
                    [shell, "-NonInteractive", "-Command", ps_script],
                    capture_output=True,
                    text=True,
                    timeout=self.config.get("timeout_s", 600),
                )
                output = log_path.read_text() if log_path.exists() else proc.stdout

                # We turn each technique into a finding regardless of detection,
                # then SCV cross-references with EDR telemetry to determine if
                # detection actually fired. The finding here is the *test artifact*.
                detected = self._was_detected(technique)
                if detected is False:
                    severity = Severity.HIGH
                    title = f"ATT&CK {technique} executed and was NOT detected by EDR"
                    description = (
                        f"Atomic test for {technique} ran successfully on the agent runtime host. "
                        "No matching EDR alert was found in the SCV correlation window. "
                        "Detection coverage gap for this technique."
                    )
                elif detected is True:
                    severity = Severity.INFO
                    title = f"ATT&CK {technique} detected by EDR (control validated)"
                    description = (
                        f"Atomic test for {technique} ran and EDR alert fired within the "
                        "correlation window. Detection coverage is in place."
                    )
                else:
                    severity = Severity.LOW
                    title = f"ATT&CK {technique} executed; detection status unknown"
                    description = (
                        "EDR correlation lookup unavailable; manual SCV review needed."
                    )

                findings.append(self.make_finding(
                    tier=tier,
                    category=Category.INFRA_VULN,
                    severity=severity,
                    title=title,
                    description=description,
                    evidence={
                        "technique": technique,
                        "stdout_tail": (output or "")[-2000:],
                    },
                    affected={"host": "agent-runtime-host"},
                    remediation=(
                        "If detection failed: open ticket with SOC/EDR team referencing "
                        f"{technique}. If detection fired: file as control-validation evidence."
                    ),
                    references=[
                        f"https://attack.mitre.org/techniques/{technique}/",
                        "https://github.com/redcanaryco/atomic-red-team",
                    ],
                ))
        return findings

    def _was_detected(self, technique: str) -> bool | None:
        """Stub: cross-reference EDR/SIEM for a matching alert in the run window.

        Real implementation queries the SCV correlation API. Returning None here
        means the orchestrator records the test artifact and a human (or follow-up
        job) closes the loop.
        """
        # Hook for SCV integration — left as a no-op unless configured.
        return None
