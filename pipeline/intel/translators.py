"""Translate raw feed bytes into IntelItems.

One function per format. Each takes (raw_bytes, source_feed_id) and returns
list[IntelItem]; on shape mismatch raises TranslatorError. The validator
called from /feeds runs these in dry-run mode to tell the operator whether
the feed parses as-is.
"""
from __future__ import annotations

import html
import json
import re
import time
from xml.etree import ElementTree as ET

from .feeds import IntelItem, make_item_id


class TranslatorError(Exception):
    """Raised when a translator cannot handle the supplied bytes."""


# Severity tokens found in titles/summaries. Normalized to the Finding enum vocab.
_SEV_NORMALIZE = {
    "critical": "critical", "crit": "critical",
    "high": "high",
    "medium": "medium", "med": "medium", "moderate": "medium",
    "low": "low",
    "info": "info", "informational": "info", "none": "info", "na": "info",
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_BRACKET_SEV_RE = re.compile(r"\[(critical|high|medium|moderate|low|info|informational)\]", re.IGNORECASE)
_PIPE_SEV_RE = re.compile(r"(\d+(?:\.\d+)?)\s*\|\s*(critical|high|medium|low|none|na)", re.IGNORECASE)
_CVSS_RE = re.compile(r"(?:CVSS[^\d]{0,8})?(\d+(?:\.\d+)?)\s*(?:/10|\s*\|\s*[a-z]+)?", re.IGNORECASE)


def _normalize_severity(text: str) -> str:
    """Pull a severity word out of free text. Empty string if nothing matches."""
    if not text:
        return ""
    m = _PIPE_SEV_RE.search(text) or _BRACKET_SEV_RE.search(text)
    if m:
        token = m.group(2) if m.lastindex == 2 else m.group(1)
        return _SEV_NORMALIZE.get(token.lower(), "")
    # Fall back to bare keyword scan — less reliable but catches "Critical: ..."
    lower = text.lower()
    for token, norm in _SEV_NORMALIZE.items():
        if re.search(rf"\b{token}\b", lower):
            return norm
    return ""


def _parse_cvss(text: str) -> float | None:
    """Best-effort CVSS score extraction. None if nothing plausible."""
    if not text:
        return None
    # The "9.8 | CRITICAL" pattern wins because it's the most specific.
    m = _PIPE_SEV_RE.search(text)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    # Fall through to bare numeric near "CVSS" keyword.
    m = re.search(r"CVSS[^\d]{0,12}(\d+(?:\.\d+)?)", text, re.IGNORECASE)
    if m:
        try:
            score = float(m.group(1))
            if 0 <= score <= 10:
                return score
        except ValueError:
            pass
    return None


def _extract_cve_id(*texts: str) -> str:
    """First CVE-XXXX-N match found across the provided strings, or ''."""
    for t in texts:
        if not t:
            continue
        m = _CVE_RE.search(t)
        if m:
            return m.group(0).upper()
    return ""


def detect_format(raw: bytes) -> str:
    """Peek at the bytes and return one of: atom, rss, xml, json. Raises on unknown."""
    if not raw:
        raise TranslatorError("empty response body")
    head = raw[:2048].lstrip()
    if head.startswith(b"{") or head.startswith(b"["):
        return "json"
    if not head.startswith(b"<"):
        raise TranslatorError(f"not XML or JSON (starts with {head[:16]!r})")
    # Quick string scan over the head — cheaper than parsing.
    head_lower = head.lower()
    if b"<feed" in head_lower and b"atom" in head_lower:
        return "atom"
    if b"<rss" in head_lower or b"<channel" in head_lower:
        return "rss"
    return "xml"


def _strip_namespace(tag: str) -> str:
    """ElementTree returns {ns}tag — strip the namespace for friendlier matching."""
    return tag.split("}", 1)[1] if "}" in tag else tag


def translate_rss(raw: bytes, source_feed_id: str) -> list[IntelItem]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise TranslatorError(f"RSS parse failed: {e}") from e
    if _strip_namespace(root.tag).lower() != "rss":
        raise TranslatorError(f"expected <rss> root, got <{_strip_namespace(root.tag)}>")
    items_out: list[IntelItem] = []
    fetched_at = time.time()
    for channel in root:
        if _strip_namespace(channel.tag).lower() != "channel":
            continue
        for item in channel:
            if _strip_namespace(item.tag).lower() != "item":
                continue
            fields = {_strip_namespace(c.tag).lower(): (c.text or "").strip() for c in item}
            title = fields.get("title", "")
            link = fields.get("link", "") or fields.get("guid", "")
            summary = fields.get("description", "")
            published = fields.get("pubdate", "") or fields.get("published", "")
            cve_id = _extract_cve_id(title, link, summary)
            severity = _normalize_severity(title) or _normalize_severity(summary)
            cvss = _parse_cvss(title) or _parse_cvss(summary)
            items_out.append(IntelItem(
                item_id=make_item_id(source_feed_id, cve_id, link),
                source_feed_id=source_feed_id,
                cve_id=cve_id,
                title=title,
                severity=severity,
                cvss=cvss,
                link=link,
                published=published,
                summary=html.unescape(summary)[:2000],
                fetched_at=fetched_at,
            ))
    return items_out


_ATOM_NS = {"a": "http://www.w3.org/2005/Atom"}


def translate_atom(raw: bytes, source_feed_id: str) -> list[IntelItem]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise TranslatorError(f"Atom parse failed: {e}") from e
    if _strip_namespace(root.tag).lower() != "feed":
        raise TranslatorError(f"expected <feed> root, got <{_strip_namespace(root.tag)}>")
    items_out: list[IntelItem] = []
    fetched_at = time.time()
    for entry in root.findall("a:entry", _ATOM_NS) or [e for e in root if _strip_namespace(e.tag) == "entry"]:
        def _txt(tag: str) -> str:
            el = entry.find(f"a:{tag}", _ATOM_NS)
            if el is None:
                el = next((c for c in entry if _strip_namespace(c.tag) == tag), None)
            return (el.text or "").strip() if el is not None else ""

        title = _txt("title")
        published = _txt("published") or _txt("updated")
        summary = _txt("summary") or _txt("content")
        # <link href=...> — Atom uses an attribute, not text content.
        link = ""
        for cand in entry:
            if _strip_namespace(cand.tag) == "link":
                href = cand.attrib.get("href", "")
                rel = cand.attrib.get("rel", "alternate")
                if href and rel == "alternate":
                    link = href
                    break
                if href and not link:
                    link = href
        cve_id = _extract_cve_id(title, link, summary)
        severity = _normalize_severity(summary) or _normalize_severity(title)
        cvss = _parse_cvss(summary) or _parse_cvss(title)
        items_out.append(IntelItem(
            item_id=make_item_id(source_feed_id, cve_id, link),
            source_feed_id=source_feed_id,
            cve_id=cve_id,
            title=title,
            severity=severity,
            cvss=cvss,
            link=link,
            published=published,
            summary=html.unescape(summary)[:2000],
            fetched_at=fetched_at,
        ))
    return items_out


def translate_xml_generic(raw: bytes, source_feed_id: str) -> list[IntelItem]:
    """Last-resort XML translator: looks for repeated child elements at depth 1 or 2.

    Useful for non-RSS/Atom XML feeds (e.g. custom NVD-like dumps). Pulls
    common fields by tag name: id/cve, title/summary, link/url, severity,
    cvss, published/date.
    """
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise TranslatorError(f"XML parse failed: {e}") from e

    # Find the repeating element: the most-common child tag at depth 1 or 2.
    candidates: list[ET.Element] = list(root)
    if len(candidates) == 1:
        candidates = list(candidates[0])
    if not candidates:
        raise TranslatorError("no child elements to iterate")

    items_out: list[IntelItem] = []
    fetched_at = time.time()
    for el in candidates:
        fields = {}
        for c in el.iter():
            tag = _strip_namespace(c.tag).lower()
            if c.text and c.text.strip() and tag not in fields:
                fields[tag] = c.text.strip()
        title = fields.get("title") or fields.get("summary") or fields.get("name") or ""
        link = fields.get("link") or fields.get("url") or fields.get("href") or ""
        published = fields.get("published") or fields.get("pubdate") or fields.get("date") or ""
        summary = fields.get("description") or fields.get("summary") or ""
        sev_text = fields.get("severity") or fields.get("baseseverity") or title or summary
        cvss_text = fields.get("cvss") or fields.get("score") or fields.get("basescore") or summary
        cve_id = _extract_cve_id(fields.get("id", ""), fields.get("cve", ""), title, link, summary)
        if not cve_id and not title:
            continue   # row has nothing usable
        items_out.append(IntelItem(
            item_id=make_item_id(source_feed_id, cve_id, link),
            source_feed_id=source_feed_id,
            cve_id=cve_id,
            title=title or cve_id,
            severity=_normalize_severity(sev_text),
            cvss=_parse_cvss(cvss_text),
            link=link,
            published=published,
            summary=html.unescape(summary)[:2000],
            fetched_at=fetched_at,
        ))
    if not items_out:
        raise TranslatorError("XML had no parseable rows — needs a custom translator")
    return items_out


def translate_json(raw: bytes, source_feed_id: str) -> list[IntelItem]:
    """JSON feed translator. Handles common shapes:
       - JSON Feed 1.x (items list with title/url/date_published/summary)
       - NVD-ish ({"vulnerabilities": [{...}]})
       - CISA KEV ({"vulnerabilities": [{"cveID", "vulnerabilityName", ...}]})
       - Bare list of records
    """
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise TranslatorError(f"JSON parse failed: {e}") from e

    rows: list[dict] = []
    if isinstance(doc, list):
        rows = [r for r in doc if isinstance(r, dict)]
    elif isinstance(doc, dict):
        for key in ("items", "vulnerabilities", "data", "results", "entries"):
            v = doc.get(key)
            if isinstance(v, list):
                rows = [r for r in v if isinstance(r, dict)]
                break
        else:
            rows = [doc]   # single-record document

    if not rows:
        raise TranslatorError("no rows found in JSON (looked for items/vulnerabilities/data/results/entries)")

    items_out: list[IntelItem] = []
    fetched_at = time.time()
    for row in rows:
        # CVE id alias set covers JSON Feed (id), NVD (cve), CISA KEV (cveID).
        cve_id = _extract_cve_id(
            str(row.get("cveID", "")),
            str(row.get("cve", "")),
            str(row.get("id", "")),
            str(row.get("title", "")),
            str(row.get("vulnerabilityName", "")),
            str(row.get("shortDescription", "")),
            str(row.get("description", "")),
            str(row.get("summary", "")),
            str(row.get("url", "") or row.get("link", "")),
        )
        # CISA KEV puts the catchy name in vulnerabilityName; vendorProject + product
        # gives the operator quick context when the name is generic ("RCE").
        vendor_product = " ".join(
            x for x in (row.get("vendorProject"), row.get("product")) if x
        )
        title = (
            row.get("title")
            or row.get("vulnerabilityName")
            or row.get("name")
            or (f"{vendor_product}: {cve_id}" if vendor_product and cve_id else "")
            or row.get("summary")
            or ""
        )
        link = row.get("url") or row.get("link") or row.get("href") or ""
        # KEV rows have no link; the CVE id deterministically resolves on NVD.
        if not link and cve_id:
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        published = (
            row.get("date_published")
            or row.get("published")
            or row.get("dateAdded")
            or row.get("date")
            or ""
        )
        summary = (
            row.get("content_text")
            or row.get("shortDescription")
            or row.get("description")
            or row.get("summary")
            or row.get("requiredAction")
            or ""
        )
        sev_text = str(row.get("severity") or row.get("baseSeverity") or "")
        # KEV doesn't carry a severity per row — but presence on the KEV list
        # means actively exploited in the wild, which CISA itself treats as
        # critical-priority. Mark accordingly if the row has KEV-only fields.
        if not sev_text and ("dueDate" in row or "requiredAction" in row):
            sev_text = "critical"
        cvss_raw = row.get("cvss") or row.get("score") or row.get("baseScore")
        try:
            cvss = float(cvss_raw) if cvss_raw is not None else _parse_cvss(str(summary))
        except (TypeError, ValueError):
            cvss = _parse_cvss(str(summary))
        if not cve_id and not title:
            continue
        items_out.append(IntelItem(
            item_id=make_item_id(source_feed_id, cve_id, str(link)),
            source_feed_id=source_feed_id,
            cve_id=cve_id,
            title=str(title) or cve_id,
            severity=_normalize_severity(sev_text) or _normalize_severity(str(title)),
            cvss=cvss,
            link=str(link),
            published=str(published),
            summary=html.unescape(str(summary))[:2000],
            fetched_at=fetched_at,
        ))
    if not items_out:
        raise TranslatorError("JSON had rows but none parseable — needs a custom translator")
    return items_out


TRANSLATORS = {
    "atom": translate_atom,
    "rss": translate_rss,
    "xml": translate_xml_generic,
    "json": translate_json,
}


def translate(raw: bytes, fmt: str, source_feed_id: str) -> list[IntelItem]:
    fn = TRANSLATORS.get(fmt)
    if not fn:
        raise TranslatorError(f"unknown format '{fmt}' (expected one of: {list(TRANSLATORS)})")
    return fn(raw, source_feed_id)
