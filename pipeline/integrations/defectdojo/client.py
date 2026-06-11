"""Thin REST client for DefectDojo's import-scan / reimport-scan endpoints."""
from __future__ import annotations

import io
import json

from ...core.findings import Finding
from .config import DefectDojoConfig
from .serialize import SCAN_TYPE, to_generic_report


class DefectDojoError(RuntimeError):
    """Raised on a non-2xx response from DefectDojo."""


class DefectDojoClient:
    def __init__(self, config: DefectDojoConfig, session=None):
        self.config = config
        if session is None:
            import requests  # deferred: only needed for a real push, not dry-run/tests
            session = requests.Session()
        self.session = session

    def push(
        self,
        findings: list[Finding],
        *,
        product: str,
        engagement: str,
        test_title: str | None = None,
        reimport: bool = True,
        minimum_severity: str = "Info",
        close_old_findings: bool = True,
        auto_create_context: bool = True,
        timeout: int = 120,
    ) -> dict:
        """POST findings to DefectDojo's (re)import-scan endpoint. Returns parsed JSON."""
        payload = json.dumps(to_generic_report(findings)).encode("utf-8")
        endpoint = "/api/v2/reimport-scan/" if reimport else "/api/v2/import-scan/"
        data = {
            "scan_type": SCAN_TYPE,
            "product_name": product,
            "engagement_name": engagement,
            "active": "true",
            "verified": "false",
            "minimum_severity": minimum_severity,
            "close_old_findings": "true" if close_old_findings else "false",
            "auto_create_context": "true" if auto_create_context else "false",
        }
        if test_title:
            data["test_title"] = test_title
        files = {"file": ("ai-protect-findings.json", io.BytesIO(payload), "application/json")}
        resp = self.session.post(
            self.config.url + endpoint,
            headers={"Authorization": f"Token {self.config.token}"},
            data=data,
            files=files,
            verify=self.config.verify_ssl,
            timeout=timeout,
        )
        if resp.status_code >= 400:
            raise DefectDojoError(
                f"DefectDojo {endpoint} -> HTTP {resp.status_code}: {resp.text[:500]}")
        try:
            return resp.json()
        except ValueError:
            return {"status_code": resp.status_code}
