"""intel_match — emit findings when intel feed items match this app's assets.

Reads IntelStore once, tokenizes the manifest's declared assets (model names,
provider, MCP server names, description), and emits a Finding for every intel
item whose title+summary shares a non-stoplisted token. KEV-listed matches are
CRITICAL; other matches map from the intel item's normalized severity.

This is the DETECTION half of the intel integration (the other half is
enrichment in core.intel_enrichment, which stamps context onto findings other
scanners already produced). Together they ensure CVE feeds participate in
scans rather than just sitting on the side.
"""
from __future__ import annotations

import re

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter

# A token is "identifier-like" only if it's clearly a proper noun (starts with
# a capital in the source) or contains a digit / hyphen / underscore. Bare
# lowercase English words ("editor", "internal", "wraps") would match
# thousands of CVE titles and produce a tsunami of false positives, so we drop
# them. Stoplist below filters the small remaining set of common English
# proper-noun-ish words that aren't products.
_STOPLIST = {
    # generic English nouns/verbs/adjectives that happen to be capitalized
    # at the start of CVE titles or manifest descriptions
    "the", "and", "for", "with", "from", "via", "this", "that",
    "internal", "external", "public", "private",
    "open", "free", "main", "core", "data", "code", "user", "users",
    "tool", "tools", "agent", "agents", "model", "models",
    "service", "server", "client", "system", "test", "tests",
    "version", "type", "name", "info", "endpoint",
    "high", "low", "medium", "critical",
    # tokens too short to be confidently a product identifier
    "ai", "api", "app", "web", "url", "llm", "rag", "tcp", "udp", "ssh",
    "ssl", "tls", "xss", "rce", "sql", "css", "dns",
    # AI / agent vocabulary — present in nearly every AI app manifest AND
    # in many feed titles, so the noise-to-signal is hopeless
    "chat", "prompt", "embedding", "embeddings", "vector",
    "transcription", "audio", "video", "image", "text",
    "workflow", "workflows", "editor", "wraps", "helper",
    "docs", "portal", "input", "output",
    # severity / category words that appear in feed titles
    "vulnerability", "vulnerabilities", "injection", "overflow",
    "denial", "execution", "remote", "local", "elevation",
    # debris from splitting hyphenated identifiers (e.g. "Drupal-based" → "based",
    # "gpt-4o-mini" → "mini"). These leak through length checks but are pure noise.
    "based", "mini", "lite", "edge", "beta", "alpha",
    # generic adapter / pipeline / test scaffolding words that show up in
    # manifest names like "smoke-test-intel-match"
    "intel", "match", "smoke", "scan", "scanner", "scanners",
    "feed", "feeds", "store", "policy", "stage", "stages",
    # narrative connectives that appear in descriptions but also in
    # countless CVE titles (e.g. "single-operator" / "write-back")
    "single", "multi", "operator", "operators", "write", "back",
    "main", "primary", "secondary", "static", "dynamic",
    "automation", "runners", "runner", "scripts", "script",
    "portal", "studio", "platform", "framework", "library",
    "module", "modules", "package", "packages",
}

# Identifier-like: starts with capital (proper noun) OR contains a digit
# or hyphen/underscore (e.g. "gpt-4o", "claude-sonnet-4-6", "log4j2"). Length
# floor of 4 to skip noise. We extract these from the original string with
# case preserved, then lowercase for matching.
_IDENT_RE = re.compile(r"\b(?:[A-Z][A-Za-z0-9_-]{3,}|[A-Za-z]*[0-9][A-Za-z0-9_-]*|[A-Za-z]+[_-][A-Za-z0-9_-]+)\b")


def _tokens(s: str | None) -> set[str]:
    """Extract identifier-like tokens (case-insensitive). Drops stoplist hits
    and anything shorter than 4 chars after lowercasing.

    Hyphenated / underscored tokens are emitted both whole AND split, so a
    manifest mentioning 'Drupal-based' will still match feed items that say
    just 'Drupal'.
    """
    if not s:
        return set()
    out: set[str] = set()
    def _keep(low: str) -> None:
        if len(low) >= 4 and low not in _STOPLIST:
            out.add(low)
    for m in _IDENT_RE.findall(s):
        low = m.lower()
        _keep(low)
        if "-" in low or "_" in low:
            for piece in re.split(r"[-_]", low):
                _keep(piece)
    return out


_INTEL_SEV_TO_FINDING = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


_SEV_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}


class IntelMatchAdapter(Adapter):
    name = "intel_match"
    description = "Cross-reference manifest-declared assets against fetched intel feeds (CISA KEV, NVD, vendor CVE feeds)"

    # Default emission threshold — only HIGH+ matches emit findings by default.
    # Override via config={"min_severity": "medium"} in the policy table if a
    # tier wants broader coverage. KEV-listed matches always emit regardless
    # of this floor (KEV inclusion = active exploitation; never filter those).
    _DEFAULT_MIN_SEVERITY = "high"

    def run(self):
        # Local import — keeps this adapter loadable in environments where the
        # intel module is unavailable (the orchestrator just yields zero
        # findings rather than crashing the whole stage).
        try:
            from ..intel.feeds import FeedStore, IntelStore
        except Exception:
            return []

        # Build the manifest's "asset token" set. These are the strings we
        # look for inside intel item titles + summaries.
        m = self.manifest
        tokens: set[str] = set()
        for em in m.models:
            tokens |= _tokens(em.name) | _tokens(em.provider) | _tokens(em.model)
        for srv in m.mcp_servers:
            tokens |= _tokens(srv.name)
            for a in srv.actions or []:
                tokens |= _tokens(a)
        tokens |= _tokens(m.description)
        # NOT tokenizing m.name on purpose — manifest.name is an internal
        # identifier (e.g. "example-ads-studio"), not a product/library name,
        # so matching it against feed titles produces false positives more
        # often than not.
        if not tokens:
            return []

        intel = IntelStore().all()
        if not intel:
            return []
        feeds_by_id = {f.feed_id: f for f in FeedStore().all(include_deleted=True)}

        # Frequency-based noise filter. A manifest token is useful for matching
        # ONLY if it's discriminating — rare in the intel corpus. "python" or
        # "meta" appear in thousands of CVE titles and shouldn't match; "drupal"
        # or "supabase" appear in dozens and should. Threshold 5% of corpus
        # tunes itself automatically as the intel store grows.
        haystacks: list[set[str]] = [
            _tokens((it.title or "") + " " + (it.summary or "")) for it in intel
        ]
        freq: dict[str, int] = {}
        for hs in haystacks:
            for t in hs:
                freq[t] = freq.get(t, 0) + 1
        noise_threshold = max(5, int(len(intel) * 0.05))
        discriminating = {t for t, c in freq.items() if c <= noise_threshold}
        # Manifest tokens that aren't in the intel store at all are kept too
        # (freq == 0), so brand-new products still match if they later appear.
        tokens = {t for t in tokens if freq.get(t, 0) <= noise_threshold}
        if not tokens:
            return []

        try:
            tier = classify(m).tier
        except Exception:
            tier = 3   # safe default if classify hiccups

        min_sev_name = (self.config.get("min_severity") or self._DEFAULT_MIN_SEVERITY).lower()
        try:
            min_sev_rank = _SEV_RANK[Severity(min_sev_name)]
        except (KeyError, ValueError):
            min_sev_rank = _SEV_RANK[Severity.HIGH]

        seen_cves: set[str] = set()
        findings: list = []
        for item, item_tokens in zip(intel, haystacks):
            matched = tokens & item_tokens
            if not matched:
                continue
            # Dedup: one finding per CVE id (across all feeds that mention it).
            # Items without a CVE id still emit by item_id so distinct
            # advisories aren't collapsed.
            dedup_key = item.cve_id.upper() if item.cve_id else f"item:{item.item_id}"
            if dedup_key in seen_cves:
                continue
            seen_cves.add(dedup_key)

            feed = feeds_by_id.get(item.source_feed_id)
            feed_name = feed.name if feed else item.source_feed_id
            is_kev = "kev" in feed_name.lower() or "known exploited" in feed_name.lower()
            severity = (
                Severity.CRITICAL if is_kev
                else _INTEL_SEV_TO_FINDING.get(item.severity or "", Severity.MEDIUM)
            )
            # Emission gate: KEV always emits (active exploitation in the wild),
            # otherwise drop anything below the configured min_severity floor.
            if not is_kev and _SEV_RANK[severity] < min_sev_rank:
                continue
            cve_label = item.cve_id or item.title[:80]
            findings.append(self.make_finding(
                category=Category.SUPPLY_CHAIN,
                severity=severity,
                title=f"Intel match: {cve_label}",
                description=(
                    f"External intel feed '{feed_name}' reports a vulnerability that mentions "
                    f"asset(s) declared in this app's manifest. Matched tokens: "
                    f"{', '.join(sorted(matched))}. "
                    + ("[CISA KEV — active exploitation in the wild; severity raised to CRITICAL.] "
                       if is_kev else "")
                    + (item.summary or "")[:600]
                ),
                evidence={
                    "intel_match": True,
                    "matched_tokens": sorted(matched),
                    "intel_feed": feed_name,
                    "intel_severity": item.severity,
                    "intel_cvss": item.cvss,
                    "intel_published": item.published,
                    "kev_listed": is_kev,
                },
                affected={"asset_tokens_matched": sorted(matched)},
                remediation=(
                    "Verify whether the manifest-declared asset is the same product/version "
                    "as the CVE target. If yes, follow the vendor advisory linked under References. "
                    "If no, the match is a token-overlap false positive — add a note and ignore."
                ),
                references=[item.link] if item.link else [],
                tier=tier,
            ))
        return findings
