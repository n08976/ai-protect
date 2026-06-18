"""Nikto adapter — web server misconfiguration + known-vuln scanning.

Nikto fills a gap Nuclei/ZAP/Burp don't cover well: fast enumeration of
dangerous files, outdated server software, insecure HTTP headers, default
credentials pages, and ~7k known problematic URLs against a web server.
Around an LLM app this catches the exposed admin/debug surface, leftover
backup files, and server-banner leakage.

Scanner-class (read-mostly probing), so it follows the Nuclei safety model:
no mutation gate, but bare-origin refusal applies per the global DAST policy.

Repo: https://github.com/sullo/nikto
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from defusedxml.ElementTree import ParseError as _XmlParseError, fromstring as _xml_fromstring

from ..core.dast_config import DastConfig
from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


class NiktoAdapter(Adapter):
    name = "nikto"
    description = "Nikto — web server misconfiguration + known-vuln scanning"

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("nikto"):
            raise AdapterUnavailable(
                "nikto not on PATH. Install: apt install nikto "
                "(or clone https://github.com/sullo/nikto)"
            )
        if not self.manifest.target.base_url:
            raise AdapterUnavailable("Manifest has no target.base_url to scan.")
        dc = DastConfig.from_manifest(self.manifest)
        refusal = dc.refuse_bare_origin_for(self.name)
        if refusal:
            raise AdapterUnavailable(refusal)

    def run(self):
        self.preflight()
        dc = DastConfig.from_manifest(self.manifest)
        target = self.manifest.target.base_url
        timeout = dc.subprocess_timeout(override=1200)

        with tempfile.TemporaryDirectory() as td:
            # XML, not JSON: many packaged nikto builds (e.g. 2.1.5) reject
            # "-Format json" with "Invalid output format" and abort instantly,
            # writing nothing — which looked like a 0-finding scan. XML is
            # supported everywhere and is structured.
            out_file = Path(td) / "nikto.xml"
            cmd = [
                "nikto",
                "-h", target,
                "-Format", "xml",
                "-output", str(out_file),
                "-nointeractive",
                "-ask", "no",
                # Keep Nikto inside the pipeline timebox even if it stalls on a
                # slow host; -maxtime accepts seconds.
                "-maxtime", str(timeout),
            ]
            try:
                subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=timeout + 30, check=False,
                )
            except subprocess.TimeoutExpired:
                raise AdapterUnavailable(f"nikto exceeded timebox ({timeout}s)")
            raw = out_file.read_text() if out_file.exists() else ""

        if not raw.strip():
            return []
        try:
            root = _xml_fromstring(raw)   # defusedxml: DTD present but no entity expansion
        except _XmlParseError:
            return []

        tier = classify(self.manifest).tier
        findings = []
        for item in root.iter("item"):
            msg = (item.findtext("description") or "").strip()
            if not msg:
                continue
            url = (item.findtext("namelink") or item.findtext("uri") or "").strip() or target
            osvdb = (item.get("osvdbid") or "").strip()
            findings.append(self.make_finding(
                tier=tier,
                category=Category.INFRA_VULN,
                severity=Severity.MEDIUM,
                title=f"Nikto: {msg[:120]}",
                description=msg[:1500],
                evidence={
                    "id": item.get("id"),
                    "osvdb": osvdb,
                    "method": item.get("method"),
                    "url": url,
                },
                affected={"target": target, "url": url},
                remediation=(
                    "Triage the flagged path/header: remove backup or debug files, "
                    "patch outdated server software, and tighten response headers."
                ),
                references=(
                    [f"https://www.osvdb.org/{osvdb}"] if osvdb.isdigit() and osvdb != "0" else []
                ),
            ))
        return self.filter_findings(findings)
