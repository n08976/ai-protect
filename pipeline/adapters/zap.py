"""OWASP ZAP adapter — free Burp Pro substitute.

ZAP exposes a REST API on its admin port. We drive it the same way the burp
adapter drives Burp Enterprise — kick a scan, poll for completion, pull
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

Supported modes (via config.mode):

    spider    — URL discovery only (fastest; no vulnerabilities)
    baseline  — 1-minute spider + passive rules; safe for live targets and Tier 3/4
    active    — spider + active scan; mutating
    full      — spider + active scan + extended passive rules; longest run
    api       — import OpenAPI / SOAP / GraphQL spec, then spider + active;
                strong fit for AI gateway and MCP server surfaces. Provide
                config.api_spec_url, or the adapter will try
                <target.api_url>/openapi.json as a fallback.
"""
from __future__ import annotations

import logging
import os
import time

import requests

from ..core import settings as user_settings
from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


def _resolve_zap_api_url() -> str:
    """ZAP daemon API base URL: ZAP_API_URL env wins, else the zap_api_url
    setting. Lets the daemon be configured durably (survives any UI launch)."""
    return (os.environ.get("ZAP_API_URL") or user_settings.get("zap_api_url", "") or "").rstrip("/")

log = logging.getLogger("ai-protect.zap")


SEVERITY_MAP = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}


SUPPORTED_MODES = ("spider", "baseline", "active", "ascan", "full", "api")
MUTATING_MODES = ("active", "ascan", "full", "api")


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
    description = "OWASP ZAP — free DAST scanner via REST API (modes: spider, baseline, active, full, api)"

    @property
    def requires_mutation(self) -> bool:
        return self.config.get("mode", "spider").lower() in MUTATING_MODES

    def preflight(self) -> None:
        super().preflight()
        if not self.manifest.target.base_url:
            raise AdapterUnavailable("Manifest has no target.base_url to scan.")
        if not _resolve_zap_api_url():
            raise AdapterUnavailable(
                "ZAP daemon URL not configured. Start a ZAP daemon and set the "
                "ZAP_API_URL env var or the zap_api_url setting (/settings → DAST)."
            )
        mode = self.config.get("mode", "spider").lower()
        if mode not in SUPPORTED_MODES:
            raise AdapterUnavailable(
                f"Unknown ZAP mode {mode!r}. Supported: {', '.join(SUPPORTED_MODES)}"
            )
        # ZAP spider + active scan both crawl the URL tree below the seed.
        # Refuse bare-origin targets per the global DAST safety policy so we
        # don't accidentally crawl every URL on the host (vendor blogs,
        # marketing pages, admin panels not in scope).
        from ..core.dast_config import DastConfig
        dc = DastConfig.from_manifest(self.manifest)
        refusal = dc.refuse_bare_origin_for(self.name)
        if refusal:
            raise AdapterUnavailable(refusal)

    def _api(self) -> str:
        return _resolve_zap_api_url()

    def _key(self) -> str:
        return os.environ.get("ZAP_API_KEY", "")

    def _params(self, **extra) -> dict:
        p = {"apikey": self._key()} if self._key() else {}
        p.update(extra)
        return p

    def run(self):
        self.preflight()
        from ..core.dast_config import DastConfig
        dc = DastConfig.from_manifest(self.manifest)
        target = self.manifest.target.base_url
        mode = self.config.get("mode", "spider").lower()
        # Universal timebox: ZAP runs polling-based scans against a daemon,
        # so we enforce the cap via deadline checks rather than subprocess
        # timeout. Per-call config can request shorter; never longer than dc.
        timeout_s = dc.subprocess_timeout(override=self.config.get("timeout_s", 1200)) or 1200
        deadline = time.time() + timeout_s
        tier = classify(self.manifest).tier
        # Apply concurrency: ZAP exposes threadsPerHost on the active scanner.
        # Best-effort — older ZAP versions may not honor; ignore on 4xx/5xx.
        try:
            requests.get(
                f"{self._api()}/JSON/ascan/action/setOptionThreadPerHost/",
                params=self._params(Integer=str(dc.max_concurrency)),
                timeout=10,
            )
        except Exception:
            pass

        if mode == "api":
            self._import_api_spec()

        # Every mode kicks off with a spider so ZAP knows the URL tree. Baseline
        # caps the spider at ~1 minute to stay quick for low-tier scans.
        spider_deadline = min(deadline, time.time() + 60) if mode == "baseline" else deadline
        self._spider(target, spider_deadline)

        if mode in ("active", "ascan", "full", "api"):
            self._active_scan(target, deadline)

        if mode in ("baseline", "full"):
            self._wait_passive(deadline)

        return self._collect_alerts(target, tier)

    def _spider(self, target: str, deadline: float) -> None:
        log.info("ZAP spider %s", target)
        r = requests.get(
            f"{self._api()}/JSON/spider/action/scan/",
            params=self._params(url=target),
            timeout=15,
        )
        r.raise_for_status()
        scan_id = r.json().get("scan")
        while time.time() < deadline:
            r = requests.get(
                f"{self._api()}/JSON/spider/view/status/",
                params=self._params(scanId=scan_id),
                timeout=15,
            )
            if r.json().get("status") == "100":
                break
            time.sleep(5)

    def _active_scan(self, target: str, deadline: float) -> None:
        log.info("ZAP active scan %s", target)
        r = requests.get(
            f"{self._api()}/JSON/ascan/action/scan/",
            params=self._params(url=target),
            timeout=15,
        )
        r.raise_for_status()
        scan_id = r.json().get("scan")
        while time.time() < deadline:
            r = requests.get(
                f"{self._api()}/JSON/ascan/view/status/",
                params=self._params(scanId=scan_id),
                timeout=15,
            )
            if r.json().get("status") == "100":
                break
            time.sleep(10)

    def _wait_passive(self, deadline: float) -> None:
        """Wait for passive scan queue to drain."""
        while time.time() < deadline:
            r = requests.get(
                f"{self._api()}/JSON/pscan/view/recordsToScan/",
                params=self._params(),
                timeout=15,
            )
            try:
                remaining = int(r.json().get("recordsToScan", "0"))
            except (ValueError, TypeError):
                break
            if remaining == 0:
                break
            time.sleep(5)

    def _import_api_spec(self) -> None:
        """Import an OpenAPI / SOAP / GraphQL spec into ZAP before spidering."""
        spec_url = self._resolve_api_spec_url()
        if not spec_url:
            log.warning("ZAP api mode: no spec URL provided or inferable; falling back to URL spider only")
            return

        api_url = self.manifest.target.api_url or self.manifest.target.base_url

        # OpenAPI / Swagger
        if any(spec_url.lower().endswith(ext) for ext in (".json", ".yaml", ".yml")) or "openapi" in spec_url.lower() or "swagger" in spec_url.lower():
            log.info("ZAP importing OpenAPI/Swagger spec %s", spec_url)
            r = requests.get(
                f"{self._api()}/JSON/openapi/action/importUrl/",
                params=self._params(url=spec_url, hostOverride=api_url or ""),
                timeout=60,
            )
            r.raise_for_status()
            return

        # SOAP / WSDL
        if spec_url.lower().endswith(".wsdl") or "wsdl" in spec_url.lower():
            log.info("ZAP importing SOAP WSDL %s", spec_url)
            r = requests.get(
                f"{self._api()}/JSON/soap/action/importUrl/",
                params=self._params(url=spec_url),
                timeout=60,
            )
            r.raise_for_status()
            return

        # GraphQL — endpoint URL with introspection (ZAP graphql add-on)
        if "graphql" in spec_url.lower():
            log.info("ZAP importing GraphQL endpoint %s", spec_url)
            r = requests.get(
                f"{self._api()}/JSON/graphql/action/importUrl/",
                params=self._params(endurl=spec_url),
                timeout=60,
            )
            # GraphQL add-on may not be installed; treat as soft-fail
            if r.status_code >= 400:
                log.warning("ZAP graphql import failed (add-on not installed?); continuing without spec")
            return

        log.warning("ZAP api mode: unrecognized spec format at %s; continuing without import", spec_url)

    def _resolve_api_spec_url(self) -> str | None:
        spec = self.config.get("api_spec_url")
        if spec:
            return spec
        api_url = self.manifest.target.api_url
        if api_url:
            return api_url.rstrip("/") + "/openapi.json"
        return None

    def _collect_alerts(self, target: str, tier: int):
        r = requests.get(
            f"{self._api()}/JSON/core/view/alerts/",
            params=self._params(baseurl=target),
            timeout=30,
        )
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
