"""intel_match corpus bounding — the emitted count must track the app's
declared components + KEV, not the raw size of the append-only intel store.

Regression for the 2026-07 metaads-commercial blow-up: matching against the
whole store made findings climb with every feed poll (matched CVEs never leave
the store, so they were re-emitted forever and never auto-resolved).
"""
from __future__ import annotations

import time

import pytest

from ai_protect.adapters.intel_match import IntelMatchAdapter
from ai_protect.core.manifest import Manifest
from ai_protect.intel import feeds as feeds_mod
from ai_protect.intel.feeds import Feed, IntelItem, make_item_id

KEV_FEED = "f-kev"
NVD_FEED = "f-nvd"
DAY = 86400


def _feeds():
    return [
        Feed(feed_id=KEV_FEED, name="CISA KEV Catalog", url="https://kev", format="json", poll_seconds=3600),
        Feed(feed_id=NVD_FEED, name="NVD CVE 2.0 modified", url="https://nvd", format="json", poll_seconds=14400),
    ]


def _item(cve, feed_id, title, fetched_at, severity="high"):
    return IntelItem(
        item_id=make_item_id(feed_id, cve, ""),
        source_feed_id=feed_id, cve_id=cve, title=title, severity=severity,
        cvss=8.1, link=f"https://x/{cve}", published="2026-01-01", summary=title,
        fetched_at=fetched_at,
    )


def _manifest():
    # "Drupal" is a discriminating, identifier-like token (capitalized, >=6).
    return Manifest.from_dict({
        "name": "intel-match-test", "owner": "t",
        "description": "A Drupal based content portal.",
        "data_sensitivity": "public", "decision_impact": "advisory",
        "integration_footprint": "read_only", "user_population": "team",
        "models": [], "mcp_servers": [],
    })


def _patch_stores(monkeypatch, items):
    monkeypatch.setattr(feeds_mod, "IntelStore",
                        lambda *a, **k: type("S", (), {"all": lambda self: list(items)})())
    feeds = _feeds()
    monkeypatch.setattr(feeds_mod, "FeedStore",
                        lambda *a, **k: type("F", (), {"all": lambda self, include_deleted=False: list(feeds)})())


def _run(monkeypatch, items, config=None):
    _patch_stores(monkeypatch, items)
    return IntelMatchAdapter(_manifest(), "build", config or {}).run()


def test_default_is_kev_only(monkeypatch):
    now = time.time()
    items = [
        _item("CVE-2024-0001", KEV_FEED, "Drupal core RCE actively exploited", now),
        _item("CVE-2020-1111", NVD_FEED, "Drupal old advisory", now - 400 * DAY),
        _item("CVE-2026-2222", NVD_FEED, "Drupal recent advisory", now),
    ]
    findings = _run(monkeypatch, items)
    cves = [f.title for f in findings]
    assert cves == ["Intel match: CVE-2024-0001"], cves
    assert findings[0].evidence["kev_listed"] is True


def test_recent_window_includes_fresh_nonkev(monkeypatch):
    now = time.time()
    items = [
        _item("CVE-2024-0001", KEV_FEED, "Drupal core RCE", now),
        _item("CVE-2020-1111", NVD_FEED, "Drupal old advisory", now - 400 * DAY),
        _item("CVE-2026-2222", NVD_FEED, "Drupal recent advisory", now - 3 * DAY),
    ]
    findings = _run(monkeypatch, items, {"intel_match_recent_days": 30})
    got = sorted(f.title for f in findings)
    # KEV always in; the 3-day-old NVD item is inside the window; the 400-day
    # one is not.
    assert got == ["Intel match: CVE-2024-0001", "Intel match: CVE-2026-2222"], got


def test_count_is_decoupled_from_corpus_growth(monkeypatch):
    # The core regression: pile thousands of stale non-KEV matches into the
    # store; default (KEV-only) emission must not move.
    now = time.time()
    items = [_item("CVE-2024-0001", KEV_FEED, "Drupal core RCE", now)]
    for i in range(3000):
        items.append(_item(f"CVE-2019-{i:04d}", NVD_FEED, "Drupal legacy advisory",
                           now - 300 * DAY))
    findings = _run(monkeypatch, items)
    assert len(findings) == 1
    assert findings[0].title == "Intel match: CVE-2024-0001"


def test_empty_when_no_kev_and_no_window(monkeypatch):
    now = time.time()
    items = [_item("CVE-2026-2222", NVD_FEED, "Drupal recent advisory", now)]
    assert _run(monkeypatch, items) == []
