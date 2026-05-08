"""OWASP ZAP adapter — free Burp Pro substitute.

ZAP exposes a REST API on its admin port. We drive it the same way the burp
adapter drives Burp Enterprise — start a scan, poll for completion, pull
alerts. Designed for orgs without Burp Pro/Enterprise licensed.

Run ZAP first (pick one):

    docker run -d -u zap -p 8090:8090 --name zap \\
        ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon \\
        -host 0.0.0.0 -port 8090 -config api.disablekey=true

    # Or local install: zap.sh -daemon -port 8090

Then point this adapter at it via env:
    ZAP_API_URL=http://localhost:8090
    ZAP_API_KEY=<key from ZAP UI or empty if api.disablekey=true>

Repo: https://github.com/zaproxy/zaproxy
"""
from __future__ import annotations

import logging
import os
import time

import requests

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable

log = logging.getLogger("ai-protect.zap")


SEVERITY_MAP = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}


# Risk + alert name → category, best-effort
def _categorize(name: str) -> Category:
    n = (name or "").lower()
    if "xss" in n: return Category.HARMFUL_CONTENT
    if "sql injection" in n: return Category.INFRA_VULN
    if "ssrf" in n: return Category.INFRA_VULN
    if "directory listing" in n: return Category.DATA_LEAKAGE
    if "information disclosure" in n: return Category.DATA_LEAKAGE
    if "cookie" in n or "jwt" in n or "session" in n: return Category.AUTH
    return Category.INFRA_VULN


class ZAPAdapter(Adapter):
    name = "zap"
    description = "OWASP ZAP — free DAST scanner via REST API (Burp Pro substitute)"

    @property
    def requires_mutation(self) -> bool:
        return self.config.get("mode", "spider").lower() in ("active", "ascan")

    def preflight(self) -> None:
        super().preflight()
        if not self.manifest.target.base_url:
            raise AdapterUnavailable("Manifest has no target.base_url to scan.")
        if not os.environ.get("ZAP_API_URL"):
            raise AdapterUnavailable(
                "ZAP_API_URL not set. Start ZAP daemon and export the URL."
            )

    def _api(self) -> str:
        return os.environ["ZAP_API_URL"].rstrip("/")

    def _key(self) -> str:
        return os.environ.get("ZAP_API_KEY", "")

    def _params(self, **extra) -> dict:
        p = {"apikey": self._key()} if self._key() else {}
        p.update(extra)
        return p

    def run(self):
        self.preflight()
        target = self.manifest.target.base_url
        mode = self.config.get("mode", "spider")  # spider | active | passive
        timeout_s = self.config.get("timeout_s", 1200)
        deadline = time.time() + timeout_s
        tier = classify(self.manifest).tier

        # Always start with a spider so ZAP knows the URL tree.
        log.info("ZAP spider %s", target)
        r = requests.get(f"{self._api()}/JSON/spider/action/scan/", params=self._params(url=target), timeout=15)
        r.raise_for_status()
        scan_id = r.json().get("scan")
        while time.time() < deadline:
            r = requests.get(f"{self._api()}/JSON/spider/view/status/", params=self._params(scanId=scan_id), timeout=15)
            if r.json().get("status") == "100":
                break
            time.sleep(5)

        if mode in ("active", "ascan"):
            log.info("ZAP active scan %s", target)
            r = requests.get(f"{self._api()}/JSON/ascan/action/scan/", params=self._params(url=target), timeout=15)
            r.raise_for_status()
            scan_id = r.json().get("scan")
            while time.time() < deadline:
                r = requests.get(f"{self._api()}/JSON/ascan/view/status/", params=self._params(scanId=scan_id), timeout=15)
                if r.json().get("status") == "100":
                    break
                time.sleep(10)

        # Pull all alerts for this baseurl.
        r = requests.get(f"{self._api()}/JSON/core/view/alerts/", params=self._params(baseurl=target), timeout=30)
        r.raise_for_status()
        alerts = r.json().get("alerts", [])

        findings = []
        for a in alerts:
            severity = SEVERITY_MAP.get(a.get("risk", "Low"), Severity.LOW)
            name = a.get("name", "Unknown")
            findings.append(self.make_finding(
                tier=tier,
                category=_categorize(name),
                severity=severity,
                title=f"ZAP: {name}",
                description=(a.get("description") or "")[:1500],
                evidence={
                    "url": a.get("url"),
                    "param": a.get("param"),
                    "evidence": (a.get("evidence") or "")[:1000],
                    "confidence": a.get("confidence"),
                    "cweid": a.get("cweid"),
                    "wascid": a.get("wascid"),
                },
                affected={"url": a.get("url")},
                remediation=(a.get("solution") or "")[:1500] or None,
                references=[a.get("reference")] if a.get("reference") else [],
            ))
        return findings
