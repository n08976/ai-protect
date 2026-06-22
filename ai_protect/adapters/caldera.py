"""MITRE Caldera adapter (REST API).

Caldera is an autonomous adversary-emulation platform: rather than running
techniques one at a time (Atomic Red Team's shape), an *adversary profile* —
a chain of ATT&CK abilities — is dispatched against a deployed agent and the
planner walks the chain end-to-end. Each ability becomes a Finding with the
same detection-status semantics Atomic uses (executed → expected EDR alert →
fired or didn't), so the SCV vertical can compare *chained* technique
coverage against the per-technique coverage Atomic produces.

Repo: https://github.com/mitre/caldera

This adapter REQUIRES `target.allow_mutation = True` in the manifest. Caldera
operations execute commands on the deployed agent host. Never run them outside
an authorized validation environment.

Configuration:
    CALDERA_API_URL    base URL of the Caldera v2 API (e.g. http://caldera:8888)
    CALDERA_API_KEY    API key sent in the `KEY` header (Caldera convention)

Adapter config:
    adversary_id       (required) Caldera adversary profile UUID to run
    source_id          (optional) source/fact-set UUID; defaults to "basic"
    planner_id         (optional) planner UUID; defaults to atomic ordering
    obfuscator         (optional) Caldera obfuscator name; defaults to "plain-text"
    timeout_s          (optional) operation poll timeout; defaults to 1800
    poll_interval_s    (optional) between status polls; defaults to 15
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable

log = logging.getLogger("ai-protect.caldera")


# Caldera link/ability status codes (operation API)
#   0 = success / completed
#   negative values = failed / timed out / collection error
LINK_STATUS_OK = 0


class CalderaAdapter(Adapter):
    name = "caldera"
    description = "MITRE Caldera — autonomous adversary emulation (chained ATT&CK abilities)"
    requires_mutation = True

    def preflight(self) -> None:
        super().preflight()
        if not os.environ.get("CALDERA_API_URL"):
            raise AdapterUnavailable(
                "CALDERA_API_URL not set. Point at a Caldera v2 server (http://host:8888)."
            )
        if not os.environ.get("CALDERA_API_KEY"):
            raise AdapterUnavailable(
                "CALDERA_API_KEY not set. Generate one in Caldera (advanced → configuration)."
            )
        if not self.config.get("adversary_id"):
            raise AdapterUnavailable(
                "caldera adapter requires config.adversary_id — the UUID of an "
                "authorized Caldera adversary profile to dispatch."
            )
        try:
            r = requests.get(
                f"{self._api()}/api/v2/health",
                headers=self._headers(),
                timeout=10,
            )
            r.raise_for_status()
        except requests.RequestException as exc:
            raise AdapterUnavailable(f"Caldera health check failed: {exc}")

    def _api(self) -> str:
        return os.environ["CALDERA_API_URL"].rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "KEY": os.environ.get("CALDERA_API_KEY", ""),
        }

    def run(self):
        self.preflight()
        tier = classify(self.manifest).tier
        adversary_id = self.config["adversary_id"]
        source_id = self.config.get("source_id", "basic")
        planner_id = self.config.get("planner_id", "atomic")
        obfuscator = self.config.get("obfuscator", "plain-text")
        timeout_s = self.config.get("timeout_s", 1800)
        poll_interval_s = self.config.get("poll_interval_s", 15)

        op_id = self._start_operation(adversary_id, source_id, planner_id, obfuscator)
        if not op_id:
            raise AdapterUnavailable("Caldera did not return an operation id.")

        self._wait_for_operation(op_id, timeout_s, poll_interval_s)

        links = self._fetch_links(op_id)
        findings = []
        for link in links:
            ability = link.get("ability", {}) or {}
            technique_id = ability.get("technique_id") or "unknown"
            technique_name = ability.get("technique_name") or ""
            ability_name = ability.get("name") or "ability"
            paw = link.get("paw") or link.get("agent_paw") or "unknown-agent"
            status = link.get("status", -1)
            command = link.get("command") or ""
            output = link.get("output") or ""

            # Same posture as Atomic: each executed ability is a Finding; SCV
            # closes the loop on whether EDR fired by querying detection telemetry.
            executed = status == LINK_STATUS_OK
            detected = self._was_detected(technique_id, paw)

            if executed and detected is False:
                severity = Severity.HIGH
                title = f"Caldera ability executed without EDR detection — {technique_id} {ability_name}"
                description = (
                    f"Caldera ran ability '{ability_name}' (ATT&CK {technique_id} "
                    f"{technique_name}) on agent {paw} successfully. No matching EDR "
                    "alert was found in the SCV correlation window — chained-ability "
                    "detection coverage gap."
                )
            elif executed and detected is True:
                severity = Severity.INFO
                title = f"Caldera ability detected by EDR — {technique_id} {ability_name}"
                description = (
                    f"Caldera ran '{ability_name}' (ATT&CK {technique_id}) on agent {paw} "
                    "and EDR alert fired in the correlation window. Chained-ability "
                    "control validated."
                )
            elif executed:
                severity = Severity.LOW
                title = f"Caldera ability executed; detection status unknown — {technique_id}"
                description = (
                    f"Caldera ran '{ability_name}' on agent {paw}; EDR correlation "
                    "lookup unavailable. Manual SCV review required."
                )
            else:
                severity = Severity.INFO
                title = f"Caldera ability did not execute — {technique_id} {ability_name}"
                description = (
                    f"Caldera attempted '{ability_name}' on agent {paw} but the link "
                    f"reported status {status}. Either the host blocked the technique "
                    "(potentially good — control evidence) or the planner stopped early."
                )

            findings.append(self.make_finding(
                tier=tier,
                category=Category.INFRA_VULN,
                severity=severity,
                title=title,
                description=description,
                evidence={
                    "operation_id": op_id,
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "ability_name": ability_name,
                    "agent_paw": paw,
                    "status_code": status,
                    "command_tail": command[-500:] if command else "",
                    "output_tail": output[-2000:] if output else "",
                },
                affected={"host": "agent-runtime-host", "agent_paw": paw},
                remediation=(
                    "If detection failed: open ticket with SOC/EDR team referencing the "
                    f"ATT&CK technique ({technique_id}) and Caldera ability. "
                    "If detection fired: file as control-validation evidence."
                ),
                references=[
                    f"https://attack.mitre.org/techniques/{technique_id}/",
                    f"{self._api()}/api/v2/operations/{op_id}",
                    "https://github.com/mitre/caldera",
                ],
            ))
        return findings

    def _start_operation(self, adversary_id: str, source_id: str, planner_id: str, obfuscator: str) -> str:
        body = {
            "name": f"ai-protect/{self.manifest.name}",
            "adversary": {"adversary_id": adversary_id},
            "source": {"id": source_id},
            "planner": {"id": planner_id},
            "obfuscator": obfuscator,
            "auto_close": True,
            "state": "running",
        }
        r = requests.post(
            f"{self._api()}/api/v2/operations",
            json=body,
            headers=self._headers(),
            timeout=30,
        )
        r.raise_for_status()
        data = r.json() or {}
        return data.get("id") or data.get("operation_id") or ""

    def _wait_for_operation(self, op_id: str, timeout_s: int, poll_interval_s: int) -> None:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            r = requests.get(
                f"{self._api()}/api/v2/operations/{op_id}",
                headers=self._headers(),
                timeout=30,
            )
            r.raise_for_status()
            data = r.json() or {}
            state = (data.get("state") or "").lower()
            if state in ("finished", "cleanup", "out_of_time"):
                return
            time.sleep(poll_interval_s)
        log.warning("caldera operation %s did not finish within %ss; pulling partial links", op_id, timeout_s)

    def _fetch_links(self, op_id: str) -> list[dict[str, Any]]:
        r = requests.get(
            f"{self._api()}/api/v2/operations/{op_id}/links",
            headers=self._headers(),
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            return data
        return data.get("links", []) or []

    def _was_detected(self, technique_id: str, paw: str) -> bool | None:
        """Stub: cross-reference EDR/SIEM for a matching alert in the run window.

        Real implementation queries the SCV correlation API (same hook Atomic uses).
        Returning None means the orchestrator records the test artifact and a human
        or follow-up job closes the loop.
        """
        return None
