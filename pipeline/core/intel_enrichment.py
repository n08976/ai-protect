"""Stamp intel context onto scanner findings.

Called from the orchestrator after each adapter run, before the findings are
persisted. CVE ids in the finding's title/description/references/evidence are
matched against IntelStore; matches add an `intel_sources` block to evidence
and can bump severity (KEV inclusion → CRITICAL).

Intel feeds AUGMENT scanner findings — they do not replace them. The original
adapter's findings remain the source of truth; intel just adds external context
the scanner doesn't have on its own (active-exploitation status, max observed
CVSS, advisory links from multiple feeds).
"""
from __future__ import annotations

import json
import re
from typing import Iterable

from .findings import Finding, Severity

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _cves_in(finding: Finding) -> list[str]:
    """All distinct CVE-XXXX-N strings referenced anywhere on this finding."""
    blob_parts = [
        finding.title or "",
        finding.description or "",
        " ".join(finding.references or []),
    ]
    # evidence often carries CVE ids inside structured fields (e.g. pip_audit
    # puts them in evidence['aliases']) — flatten to a JSON string so a single
    # regex sweep catches them regardless of nesting.
    if finding.evidence:
        try:
            blob_parts.append(json.dumps(finding.evidence, default=str))
        except (TypeError, ValueError):
            pass
    blob = " ".join(blob_parts)
    return sorted({m.group(0).upper() for m in _CVE_RE.finditer(blob)})


def _is_kev_feed(feed_name: str) -> bool:
    """Heuristic: does this feed's display name suggest CISA KEV / Known
    Exploited Vulnerabilities? KEV inclusion is the highest-signal enrichment
    we expose (active exploitation → bump to critical)."""
    n = (feed_name or "").lower()
    return "kev" in n or "known exploited" in n


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    """Mutate findings in-place to add intel context. Returns the same list.

    Empty / no-CVE findings pass through unchanged. Imports are local so the
    orchestrator can import this module without dragging in the intel stack
    at import time (avoids hard intel-module dependency in CLI-only paths).
    """
    if not findings:
        return findings
    try:
        from ..intel.feeds import FeedStore, IntelStore
    except Exception:
        return findings   # intel module unavailable — no-op

    intel_items = IntelStore().all()
    if not intel_items:
        return findings

    feeds_by_id = {f.feed_id: f for f in FeedStore().all(include_deleted=True)}

    # Index intel by CVE id once — cheap for our volumes (thousands of items).
    by_cve: dict[str, list] = {}
    for i in intel_items:
        if i.cve_id:
            by_cve.setdefault(i.cve_id.upper(), []).append(i)

    for f in findings:
        cves = _cves_in(f)
        if not cves:
            continue
        sources: list[dict] = []
        cvss_max: float | None = None
        kev_listed = False
        kev_feed_names: list[str] = []
        for cve in cves:
            for item in by_cve.get(cve, []):
                feed = feeds_by_id.get(item.source_feed_id)
                feed_name = feed.name if feed else item.source_feed_id
                sources.append({
                    "cve": item.cve_id,
                    "feed": feed_name,
                    "severity": item.severity,
                    "cvss": item.cvss,
                    "link": item.link,
                    "published": item.published,
                })
                if item.cvss is not None:
                    cvss_max = item.cvss if cvss_max is None else max(cvss_max, item.cvss)
                if _is_kev_feed(feed_name):
                    kev_listed = True
                    if feed_name not in kev_feed_names:
                        kev_feed_names.append(feed_name)
        if not sources:
            continue
        # Stamp the evidence. Adapter-original evidence is preserved; we only add.
        f.evidence = dict(f.evidence or {})
        f.evidence["intel_sources"] = sources
        if cvss_max is not None:
            f.evidence["cvss_max"] = cvss_max
        if kev_listed:
            f.evidence["kev_listed"] = True
            f.evidence["kev_feeds"] = kev_feed_names
            # CISA KEV = active exploitation in the wild. Treat as CRITICAL
            # regardless of the scanner's CVSS-based call. Already-critical
            # findings stay critical; this only ratchets up.
            if f.severity != Severity.CRITICAL:
                f.evidence["severity_bumped_from"] = f.severity.value
                f.severity = Severity.CRITICAL
    return findings
