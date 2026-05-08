"""Burp Suite adapter (REST API).

Burp Suite Professional + Burp Enterprise both expose a REST API. This adapter
drives a passive or active scan against the surrounding web app — the API
surface that wraps the LLM. AI doesn't make XSS / SSRF / IDOR go away; the
gateway, the chat UI, the admin console all have classical web surface that
still needs testing.

Reference docs: https://portswigger.net/burp/documentation/enterprise/api
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

log = logging.getLogger("ai-protect.burp")


# Burp issue type → finding category. Burp publishes a stable issue catalog.
ISSUE_CATEGORY = {
    "XSS": Category.HARMFUL_CONTENT,
    "SQL injection": Category.INFRA_VULN,
    "SSRF": Category.INFRA_VULN,
    "Open redirect": Category.INFRA_VULN,
    "Server-side template injection": Category.INFRA_VULN,
    "Cleartext submission of password": Category.AUTH,
    "JWT": Category.AUTH,
    "OAuth": Category.AUTH,
    "Information disclosure": Category.DATA_LEAKAGE,
    "Hardcoded credentials": Category.SECRETS,
    "Insecure direct object reference": Category.SCOPE_VIOLATION,
}

SEVERITY_MAP = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "information": Severity.INFO,
    "critical": Severity.CRITICAL,
}


class BurpAdapter(Adapter):
    name = "burp"
    description = "PortSwigger Burp Suite — web app vulnerability scanning (passive/active)"

    @property
    def requires_mutation(self) -> bool:
        # Active scan mutates target; passive does not.
        return self.config.get("scan", "passive").lower() == "active"

    def preflight(self) -> None:
        super().preflight()
        if not self.manifest.target.base_url:
            raise AdapterUnavailable(
                "Manifest has no target.base_url — burp adapter has nothing to scan."
            )
        if not os.environ.get("BURP_API_URL"):
            raise AdapterUnavailable(
                "BURP_API_URL not set. Configure the Burp Enterprise / Professional REST endpoint."
            )

    def _api(self) -> str:
        return os.environ["BURP_API_URL"].rstrip("/")

    def _key(self) -> str:
        return os.environ.get("BURP_API_KEY", "")

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._key():
            h["Authorization"] = self._key()
        return h

    def run(self):
        self.preflight()
        scan_type = self.config.get("scan", "passive").lower()
        target_url = self.manifest.target.base_url
        tier = classify(self.manifest).tier

        # 1. Start a scan
        body = {"urls": [target_url], "scope": {"include": [{"rule": target_url}]}}
        if scan_type == "passive":
            body["scan_configurations"] = [{"name": "Crawl strategy - fastest", "type": "NamedConfiguration"}]
        r = requests.post(f"{self._api()}/scan", json=body, headers=self._headers(), timeout=30)
        r.raise_for_status()
        scan_id = r.headers.get("Location", "").rsplit("/", 1)[-1] or r.json().get("id")
        if not scan_id:
            raise AdapterUnavailable("Burp scan did not return an id.")

        # 2. Poll until done (or hit the timeout)
        deadline = time.time() + self.config.get("timeout_s", 1800)
        while time.time() < deadline:
            r = requests.get(f"{self._api()}/scan/{scan_id}", headers=self._headers(), timeout=30)
            r.raise_for_status()
            status = r.json().get("scan_status", "").lower()
            if status in ("succeeded", "failed", "abandoned"):
                break
            time.sleep(15)

        # 3. Pull issues
        r = requests.get(f"{self._api()}/scan/{scan_id}", headers=self._headers(), timeout=30)
        r.raise_for_status()
        data = r.json()
        issues = data.get("issue_events", []) or data.get("issues", [])

        findings = []
        for issue in issues:
            i = issue.get("issue", issue)
            name = i.get("name", "Unknown Burp issue")
            sev = SEVERITY_MAP.get(i.get("severity", "low").lower(), Severity.LOW)
            cat = self._categorize(name)
            findings.append(self.make_finding(
                tier=tier,
                category=cat,
                severity=sev,
                title=f"Burp: {name}",
                description=(i.get("description") or "")[:1500],
                evidence={
                    "url": i.get("origin"),
                    "path": i.get("path"),
                    "evidence": (i.get("evidence") or "")[:1500],
                    "confidence": i.get("confidence"),
                },
                affected={"target": target_url},
                remediation=(i.get("remediation") or "")[:1500] or None,
                references=i.get("references", []),
            ))
        return findings

    @staticmethod
    def _categorize(name: str) -> Category:
        for key, cat in ISSUE_CATEGORY.items():
            if key.lower() in name.lower():
                return cat
        return Category.INFRA_VULN
