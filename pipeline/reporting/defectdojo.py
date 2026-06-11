"""Export normalized Findings to an open-source DefectDojo instance.

DefectDojo's built-in **Generic Findings Import** parser accepts a JSON
document of findings; we serialize the pipeline's normalized ``Finding``
objects into that shape and POST it to the DefectDojo REST API.

Two endpoints are used:

* ``/api/v2/reimport-scan/`` (default) — reconciles against the previous test
  for the same product/engagement/test, so findings that no longer appear are
  auto-closed. This is the natural fit for the continuous fix→verify loop: a
  remediated finding disappears from the next push and DefectDojo closes it.
* ``/api/v2/import-scan/`` (``--no-reimport``) — always creates a fresh test.

``auto_create_context=true`` lets DefectDojo create the product and engagement
on first push, so no manual setup in the UI is required.

Each finding carries a stable ``unique_id_from_tool`` (the pipeline
fingerprint) so DefectDojo can dedupe/reconcile across runs.

Config comes from the environment (inject the token from Vault / Key Vault in
real deployments):

    DEFECTDOJO_URL          e.g. https://defectdojo.internal
    DEFECTDOJO_API_TOKEN    API v2 token (Settings → API v2 Key)
    DEFECTDOJO_VERIFY_SSL   "0" to disable TLS verification (default: on)
"""
from __future__ import annotations

import io
import json
import os
import time
from dataclasses import dataclass

from ..core.findings import Finding, Severity

SCAN_TYPE = "Generic Findings Import"

# ai-protect Severity -> DefectDojo severity label (DefectDojo wants Title-case).
_DD_SEVERITY = {
    Severity.INFO: "Info",
    Severity.LOW: "Low",
    Severity.MEDIUM: "Medium",
    Severity.HIGH: "High",
    Severity.CRITICAL: "Critical",
}

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


class DefectDojoConfigError(RuntimeError):
    """Raised when URL/token aren't configured."""


class DefectDojoError(RuntimeError):
    """Raised on a non-2xx response from DefectDojo."""


# --------------------------------------------------------------------------- #
# Serialization: Finding -> DefectDojo Generic Findings Import
# --------------------------------------------------------------------------- #
def _fmt_date(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def _tags(f: Finding) -> list[str]:
    tags = [f"app:{f.app_name}", f"tier:{f.tier}", f"stage:{f.stage}",
            f"adapter:{f.adapter}", f"category:{f.category.value}"]
    tags += [f"compliance:{c}" for c in f.compliance]
    return tags


def _description(f: Finding) -> str:
    parts = [f.description or ""]
    if f.affected:
        parts.append("**Affected**\n" + "\n".join(f"- {k}: {v}" for k, v in f.affected.items()))
    if f.evidence:
        # `response` bodies from red-team adapters can be huge — drop them here;
        # the full evidence is preserved in the findings store.
        ev = {k: v for k, v in f.evidence.items() if k != "response"}
        if ev:
            blob = json.dumps(ev, indent=2, default=str)
            parts.append("**Evidence**\n```json\n" + blob[:4000] + "\n```")
    parts.append(f"_stage={f.stage} · adapter={f.adapter} · tier={f.tier} · "
                 f"category={f.category.value}_")
    return "\n\n".join(p for p in parts if p).strip()


def finding_to_generic(f: Finding) -> dict:
    """Map one Finding to a DefectDojo Generic Findings Import entry."""
    ev = f.evidence or {}
    out: dict = {
        "title": f.title,
        "description": _description(f),
        "severity": _DD_SEVERITY[f.severity],
        "date": _fmt_date(f.detected_at),
        "active": True,
        "verified": False,
        "unique_id_from_tool": f.fingerprint,   # stable across runs -> dedupe/auto-close
        "vuln_id_from_tool": f.fingerprint,
        "service": f.app_name,
        "tags": _tags(f),
    }
    if f.remediation:
        out["mitigation"] = f.remediation
    if f.references:
        out["references"] = "\n".join(f.references)
    if f.compliance:
        out["severity_justification"] = "Compliance: " + ", ".join(f.compliance)

    file_path = ev.get("file") or ev.get("file_path") or ev.get("path")
    if file_path:
        out["file_path"] = str(file_path)
    line = ev.get("line", ev.get("line_number"))
    if line is not None:
        try:
            out["line"] = int(line)
        except (TypeError, ValueError):
            pass
    cwe = ev.get("cwe")
    if cwe is not None:
        try:
            out["cwe"] = int(str(cwe).lower().replace("cwe-", "").strip())
        except (TypeError, ValueError):
            pass
    return out


def to_generic_report(findings: list[Finding]) -> dict:
    """Wrap findings in the Generic Findings Import envelope."""
    return {"findings": [finding_to_generic(f) for f in findings]}


def filter_by_severity(findings: list[Finding], minimum: str) -> list[Finding]:
    """Keep findings at or above ``minimum`` (info|low|medium|high|critical)."""
    thr = _SEV_ORDER.index(minimum)
    return [f for f in findings if _SEV_ORDER.index(f.severity.value) >= thr]


# --------------------------------------------------------------------------- #
# REST client
# --------------------------------------------------------------------------- #
@dataclass
class DefectDojoConfig:
    url: str
    token: str
    verify_ssl: bool = True

    @classmethod
    def from_env(cls, url: str | None = None, token: str | None = None) -> "DefectDojoConfig":
        url = (url or os.environ.get("DEFECTDOJO_URL", "")).rstrip("/")
        token = token or os.environ.get("DEFECTDOJO_API_TOKEN", "")
        verify = os.environ.get("DEFECTDOJO_VERIFY_SSL", "1").lower() not in ("0", "false", "no")
        if not url or not token:
            raise DefectDojoConfigError(
                "DefectDojo is not configured: set DEFECTDOJO_URL and DEFECTDOJO_API_TOKEN "
                "(or pass --url/--token).")
        return cls(url=url, token=token, verify_ssl=verify)


class DefectDojoClient:
    def __init__(self, config: DefectDojoConfig, session=None):
        self.config = config
        if session is None:
            import requests  # deferred: only needed for a real push, not for dry-run/tests
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
        """POST findings to DefectDojo's (re)import-scan endpoint. Returns the parsed JSON."""
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


def push_findings(
    findings: list[Finding],
    *,
    product: str,
    engagement: str,
    config: DefectDojoConfig | None = None,
    **kwargs,
) -> dict:
    """Convenience one-shot: build a client from env (unless ``config`` given) and push."""
    cfg = config or DefectDojoConfig.from_env()
    return DefectDojoClient(cfg).push(findings, product=product, engagement=engagement, **kwargs)
