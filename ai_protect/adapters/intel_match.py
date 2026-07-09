"""intel_match — emit findings when intel feed items match this app's assets.

Reads IntelStore once, tokenizes the manifest's declared assets (model names,
provider, MCP server names, description), and emits a Finding for every intel
item whose title+summary shares a non-stoplisted token. KEV-listed matches are
CRITICAL; other matches map from the intel item's normalized severity.

This is the DETECTION half of the intel integration (the other half is
enrichment in core.intel_enrichment, which stamps context onto findings other
scanners already produced). Together they ensure CVE feeds participate in
scans rather than just sitting on the side.

Corpus scope (why this adapter doesn't flood): a manifest is matched against a
BOUNDED slice of the intel store, not the whole append-only corpus. By default
that slice is CISA KEV only — actively-exploited CVEs, a slow-growing (~1-2k),
high-signal set — so the emitted count tracks the app's declared components and
the KEV list, NOT the raw size of the feed store. Set `intel_match_recent_days`
in the policy config to additionally include CVEs first seen within N days.
Without this bound the count climbed with every feed poll (matched CVEs never
leave the append-only store, so they were re-emitted forever and never
auto-resolved) — see the 2026-07 metaads-commercial regression.
"""
from __future__ import annotations

import re
import time

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
    # FP tokens observed on real scans (commercial / studio, 2026-05-24):
    # generic tech English that matches unrelated products (VMware Workspace
    # ONE matched "workspace" split from "workspace-secret", etc.).
    "workspace", "workspaces", "secret", "secrets", "encryption", "encrypt",
    "decrypt", "key", "keys", "auth", "oauth", "token", "tokens",
    "session", "sessions", "cookie", "cookies",
    "backend", "frontend", "fullstack", "client", "clients",
    "billing", "billing-secret", "stripe", "stripe-secret",
    "tenant", "tenants", "multi-tenant",
    "param", "params", "parameter", "parameters", "query", "queries",
    "assembly", "assemble", "compose", "composer",
    "tasks", "task", "job", "jobs", "queue", "queues",
    "headers", "header", "body", "request", "requests", "response", "responses",
    # generic infra words — match dozens of unrelated CVEs
    "docker", "container", "containers", "image", "images",
    "nginx", "apache", "gunicorn", "uwsgi", "wsgi", "asgi",
    "linux", "windows", "macos", "darwin",
    "github", "gitlab", "bitbucket", "ghactions",
    # everything-matches words from manifest descriptions
    "central", "global", "remote", "local", "default", "custom",
    "config", "configuration", "settings", "options",
    "admin", "administrator", "root",
}

# Identifier-like: starts with capital (proper noun) OR contains a digit
# or hyphen/underscore (e.g. "gpt-4o", "claude-sonnet-4-6", "log4j2"). Length
# floor of 4 to skip noise. We extract these from the original string with
# case preserved, then lowercase for matching.
_IDENT_RE = re.compile(r"\b(?:[A-Z][A-Za-z0-9_-]{3,}|[A-Za-z]*[0-9][A-Za-z0-9_-]*|[A-Za-z]+[_-][A-Za-z0-9_-]+)\b")


def _tokens(s: str | None) -> set[str]:
    """Extract identifier-like tokens (case-insensitive). Drops stoplist hits
    and anything shorter than 4 chars (6 for split debris) after lowercasing.

    Hyphenated / underscored tokens are emitted whole AND split, so a manifest
    mentioning 'Drupal-based' will still match feed items that say just
    'Drupal'. The split parts have a STRICTER length floor (6 chars) than the
    whole tokens (4 chars) — that's how we kill the 'back' / 'write' / 'secret'
    false-positive class that flooded the May 2026 commercial+studio scans.
    Real product names that get split (drupal, supabase, openai, langflow)
    are all ≥6 chars; common-English debris is ≤5.
    """
    if not s:
        return set()
    out: set[str] = set()
    def _keep(low: str, min_len: int) -> None:
        if len(low) >= min_len and low not in _STOPLIST:
            out.add(low)
    for m in _IDENT_RE.findall(s):
        low = m.lower()
        _keep(low, 4)
        if "-" in low or "_" in low:
            for piece in re.split(r"[-_]", low):
                _keep(piece, 6)
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


def _is_kev_feed(feed_name: str) -> bool:
    n = (feed_name or "").lower()
    return "kev" in n or "known exploited" in n


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
        kev_feed_ids = {fid for fid, f in feeds_by_id.items() if _is_kev_feed(f.name)}

        # Bound the matching corpus. The intel store is append-only and only
        # grows (the NVD 'modified' feed alone adds thousands of CVEs per poll),
        # so matching against ALL of it made the emitted count climb with the
        # feed rather than the app — matched CVEs never leave the store, so they
        # were re-emitted every scan and never auto-resolved. We instead match
        # against KEV (actively-exploited, slow-growing, high-signal) plus,
        # optionally, CVEs first seen within `intel_match_recent_days`.
        try:
            recent_days = int(self.config.get("intel_match_recent_days", 0) or 0)
        except (TypeError, ValueError):
            recent_days = 0
        recent_cutoff = time.time() - recent_days * 86400 if recent_days > 0 else None

        def _in_scope(it) -> bool:
            if it.source_feed_id in kev_feed_ids:
                return True
            if recent_cutoff is not None and (it.fetched_at or 0) >= recent_cutoff:
                return True
            return False

        intel = [it for it in intel if _in_scope(it)]
        if not intel:
            return []

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
            is_kev = item.source_feed_id in kev_feed_ids
            # Severity cap: intel_match is UNVERIFIED token-overlap. We cannot
            # tell from a feed whether the operator's app actually uses the
            # affected product — only that a manifest word overlaps a CVE
            # title word. So we cap at HIGH even for KEV-listed matches.
            # Real CRITICAL severity should come from the enrichment hook on
            # scanner findings, where there's ground truth that the package
            # is present in the codebase (pip_audit / grype / etc.). May 2026
            # commercial+studio scans produced 605/643 token-overlap FPs at
            # CRITICAL before this cap; documented as evidence.intel_match_unverified
            # so the UI can flag them and operators can promote a confirmed
            # match through the change workflow.
            raw_severity = _INTEL_SEV_TO_FINDING.get(item.severity or "", Severity.MEDIUM)
            severity = Severity.HIGH if is_kev else raw_severity
            if _SEV_RANK[severity] > _SEV_RANK[Severity.HIGH]:
                severity = Severity.HIGH
            # Emission gate: KEV always emits at HIGH (still notable even when
            # unverified — active exploitation in the wild). Otherwise honor
            # the configured min_severity floor.
            if not is_kev and _SEV_RANK[severity] < min_sev_rank:
                continue
            cve_label = item.cve_id or item.title[:80]
            findings.append(self.make_finding(
                category=Category.SUPPLY_CHAIN,
                severity=severity,
                title=f"Intel match: {cve_label}",
                description=(
                    f"UNVERIFIED intel match. External feed '{feed_name}' reports a "
                    f"vulnerability whose title/summary shares a token with this app's "
                    f"manifest. Matched tokens: {', '.join(sorted(matched))}. "
                    f"This is text overlap, NOT confirmation that the affected product "
                    f"is actually in use. Verify by inspecting the product name in the "
                    f"original advisory below — if the manifest mentions e.g. 'workspace-"
                    f"secret' and the CVE is about 'VMware Workspace ONE', this is a "
                    f"false positive and can be dismissed. "
                    + ("[CISA KEV — active exploitation in the wild. Severity capped at "
                       "HIGH for unverified matches; promote to CRITICAL via the change "
                       "workflow once the asset usage is confirmed.] "
                       if is_kev else "")
                    + (item.summary or "")[:600]
                ),
                evidence={
                    "intel_match": True,                     # marker: skip in enrichment
                    "intel_match_unverified": True,          # operator-facing flag
                    "matched_tokens": sorted(matched),
                    "intel_feed": feed_name,
                    "intel_severity": item.severity,
                    "intel_cvss": item.cvss,
                    "intel_published": item.published,
                    "kev_listed": is_kev,
                    "severity_capped_at_high": True,
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
