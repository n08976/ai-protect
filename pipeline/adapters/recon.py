"""Recon adapter — ProjectDiscovery chain (subfinder → dnsx → naabu → httpx → katana).

Discovery layer for shadow-AI surfacing. v2.1 names this as a Phase 1
deliverable: continuous asset discovery routes findings into the engagement
pattern. This adapter does:

    1. subfinder  — passive subdomain enumeration for the apex domain
    2. httpx      — resolve which subdomains have HTTP services up
    3. naabu      — fast SYN port scan against discovered hosts
    4. katana     — crawl the web app to enumerate URL paths

Each stage emits findings (mostly INFO severity — they're discovery facts,
not vulns). High severity is reserved for unexpected reachability — e.g.,
a host on a Tier 1 subnet that wasn't supposed to be public.

Repos:
  https://github.com/projectdiscovery/subfinder
  https://github.com/projectdiscovery/httpx
  https://github.com/projectdiscovery/naabu
  https://github.com/projectdiscovery/katana
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from urllib.parse import urlparse

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable

log = logging.getLogger("ai-protect.recon")


class ReconAdapter(Adapter):
    name = "recon"
    description = "Recon chain (subfinder + httpx + naabu + katana) — shadow-AI discovery"

    def preflight(self) -> None:
        super().preflight()
        missing = [t for t in ("subfinder", "httpx", "naabu", "katana") if not shutil.which(t)]
        if len(missing) == 4:
            raise AdapterUnavailable(
                "None of subfinder/httpx/naabu/katana on PATH. Install ProjectDiscovery toolkit."
            )
        if not self.manifest.target.base_url:
            raise AdapterUnavailable("Manifest has no target.base_url for recon.")

    def run(self):
        self.preflight()
        url = self.manifest.target.base_url
        host = urlparse(url).netloc.split(":")[0]
        apex = self.config.get("apex", host)
        tier = classify(self.manifest).tier
        findings = []

        if shutil.which("subfinder"):
            subs = self._subfinder(apex)
            for s in subs:
                findings.append(self.make_finding(
                    tier=tier, category=Category.OTHER, severity=Severity.INFO,
                    title=f"Subdomain discovered: {s}",
                    description=f"subfinder enumerated {s} via passive sources.",
                    evidence={"subdomain": s, "apex": apex},
                    affected={"subdomain": s},
                    references=["https://github.com/projectdiscovery/subfinder"],
                ))

        if shutil.which("httpx"):
            for live in self._httpx([host] + [f.evidence["subdomain"] for f in findings if f.evidence.get("subdomain")]):
                findings.append(self.make_finding(
                    tier=tier, category=Category.OTHER, severity=Severity.INFO,
                    title=f"HTTP service live: {live.get('url')}",
                    description=f"httpx confirmed {live.get('url')} is reachable. status={live.get('status_code')} title={live.get('title')!r}",
                    evidence=live,
                    affected={"host": live.get("host")},
                ))

        if shutil.which("naabu"):
            ports = self._naabu(host)
            for p in ports:
                severity = Severity.LOW if p.get("port") not in (80, 443, 22, 8000, 8080) else Severity.INFO
                findings.append(self.make_finding(
                    tier=tier, category=Category.INFRA_VULN, severity=severity,
                    title=f"Port open: {host}:{p.get('port')}",
                    description=(
                        "naabu detected an open port. Cross-reference with the network "
                        "provisioning policy: per-tier subnets should default-deny lateral access."
                    ),
                    evidence=p,
                    affected={"host": host, "port": p.get("port")},
                ))

        if shutil.which("katana"):
            urls = self._katana(url)
            # Don't emit a finding per URL (would be hundreds). Emit a summary.
            if urls:
                findings.append(self.make_finding(
                    tier=tier, category=Category.OTHER, severity=Severity.INFO,
                    title=f"katana crawled {len(urls)} URLs",
                    description=(
                        f"Crawl produced {len(urls)} URL endpoints. Feed these into Nuclei + ZAP "
                        "for templated and active-scan coverage."
                    ),
                    evidence={"sample": urls[:25], "count": len(urls)},
                    affected={"target": url},
                ))
        return findings

    # Instance methods (not staticmethods) so each can pull DastConfig from
    # the manifest — fanout limits + universal timebox come from there.

    def _dc(self):
        from ..core.dast_config import DastConfig
        return DastConfig.from_manifest(self.manifest)

    def _subfinder(self, apex: str) -> list[str]:
        dc = self._dc()
        # Cap the result set so a hostile apex (or simply a giant brand)
        # doesn't yield thousands of subdomains we then pipe into the slow
        # httpx + naabu stages.
        max_results = int(self.config.get("subfinder_max", 200))
        try:
            proc = subprocess.run(
                ["subfinder", "-d", apex, "-silent", "-max-time", "2"],
                capture_output=True, text=True,
                timeout=dc.subprocess_timeout(override=120), check=False,
            )
            return [l.strip() for l in proc.stdout.splitlines() if l.strip()][:max_results]
        except Exception as e:
            log.warning("subfinder failed: %s", e)
            return []

    def _httpx(self, hosts: list[str]) -> list[dict]:
        if not hosts:
            return []
        dc = self._dc()
        try:
            proc = subprocess.run(
                ["httpx", "-silent", "-json", "-status-code", "-title",
                 "-threads", str(dc.max_concurrency),
                 "-rate-limit", str(dc.max_rps)],
                input="\n".join(hosts),
                capture_output=True, text=True,
                timeout=dc.subprocess_timeout(override=180), check=False,
            )
            return [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]
        except Exception as e:
            log.warning("httpx failed: %s", e)
            return []

    def _naabu(self, host: str) -> list[dict]:
        dc = self._dc()
        # Top-1000 ports by default; the manifest can widen, but the bare
        # default avoids a /24 sweep on the runner host.
        ports = str(self.config.get("ports", "top-1000"))
        # naabu's -rate is packets/sec. Multiply max_rps by 5 since port
        # scans need bursts but cap at 500 absolute.
        rate = min(500, dc.max_rps * 5)
        try:
            proc = subprocess.run(
                ["naabu", "-host", host, "-silent", "-json",
                 "-rate", str(rate), "-top-ports", ports if ports.startswith("top") else "100",
                 *(["-p", ports] if not ports.startswith("top") else [])],
                capture_output=True, text=True,
                timeout=dc.subprocess_timeout(override=300), check=False,
            )
            return [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]
        except Exception as e:
            log.warning("naabu failed: %s", e)
            return []

    def _katana(self, url: str) -> list[str]:
        dc = self._dc()
        # Katana IS a crawler — bare-origin refusal applies. If the manifest
        # target is just an origin, we'd crawl everything; honor the global
        # 'require scope prefix' guard instead.
        refusal = dc.refuse_bare_origin_for("katana")
        if refusal:
            log.info("%s — skipping katana crawl", refusal)
            return []
        depth = int(self.config.get("katana_depth", 2))
        max_urls = int(self.config.get("katana_max_urls", 500))
        try:
            proc = subprocess.run(
                ["katana", "-u", url, "-silent",
                 "-d", str(depth),
                 "-c", str(dc.max_concurrency),
                 "-rate-limit", str(dc.max_rps)],
                capture_output=True, text=True,
                timeout=dc.subprocess_timeout(override=180), check=False,
            )
            return [l.strip() for l in proc.stdout.splitlines() if l.strip()][:max_urls]
        except Exception as e:
            log.warning("katana failed: %s", e)
            return []
