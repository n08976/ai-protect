"""NVD CVE JSON 2.0 ingestion: translator, gzip handling, META gate, upsert."""
import gzip
import json
import time

import pytest

from ai_protect.intel import fetcher
from ai_protect.intel.feeds import (
    Feed, FeedFetchStore, FeedStore, IntelItem, IntelStore, make_item_id,
)
from ai_protect.intel.fetcher import _gunzip_capped, _meta_sidecar_url
from ai_protect.intel.translators import translate_json


def _nvd_doc():
    """Minimal but shape-faithful NVD CVE JSON 2.0 document."""
    return {
        "resultsPerPage": 3, "startIndex": 0, "totalResults": 3,
        "format": "NVD_CVE", "version": "2.0",
        "timestamp": "2026-07-08T08:00:04.000",
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2026-11111",
                "published": "2026-07-01T10:00:00.000",
                "lastModified": "2026-07-07T22:01:29.190",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {"lang": "es", "value": "desbordamiento de búfer"},
                    {"lang": "en", "value": "Heap overflow in ExampleServer allows RCE."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"source": "cna@example.com", "type": "Secondary",
                         "cvssData": {"version": "3.1", "baseScore": 5.0, "baseSeverity": "MEDIUM"}},
                        {"source": "nvd@nist.gov", "type": "Primary",
                         "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}},
                    ],
                    "cvssMetricV2": [
                        {"source": "nvd@nist.gov", "type": "Primary",
                         "cvssData": {"version": "2.0", "baseScore": 10.0},
                         "baseSeverity": "HIGH"},
                    ],
                },
            }},
            {"cve": {
                # Freshly published — no metrics yet.
                "id": "CVE-2026-22222",
                "published": "2026-07-08T01:00:00.000",
                "vulnStatus": "Received",
                "descriptions": [{"lang": "en", "value": "Awaiting analysis."}],
                "metrics": {},
            }},
            {"cve": {
                "id": "CVE-2026-33333",
                "published": "2026-06-01T00:00:00.000",
                "vulnStatus": "Rejected",
                "descriptions": [{"lang": "en", "value": "Rejected reason: withdrawn by CNA."}],
                "metrics": {"cvssMetricV31": [
                    {"source": "nvd@nist.gov", "type": "Primary",
                     "cvssData": {"version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH"}},
                ]},
            }},
        ],
    }


def test_nvd2_rows_parse_with_metrics_preference():
    items = translate_json(json.dumps(_nvd_doc()).encode(), "feed-nvd")
    assert [i.cve_id for i in items] == ["CVE-2026-11111", "CVE-2026-22222", "CVE-2026-33333"]
    a = items[0]
    # v3.1 Primary wins over the CNA Secondary and over v2.
    assert a.cvss == 9.8
    assert a.severity == "critical"
    assert a.summary == "Heap overflow in ExampleServer allows RCE."
    assert a.title.startswith("CVE-2026-11111: Heap overflow")
    assert a.link == "https://nvd.nist.gov/vuln/detail/CVE-2026-11111"
    assert a.published == "2026-07-01T10:00:00.000"


def test_nvd2_received_row_has_no_score_yet():
    items = translate_json(json.dumps(_nvd_doc()).encode(), "feed-nvd")
    received = items[1]
    assert received.cvss is None
    assert received.severity == ""


def test_nvd2_rejected_row_demoted_to_info():
    items = translate_json(json.dumps(_nvd_doc()).encode(), "feed-nvd")
    rejected = items[2]
    # Kept for visibility, but never actionable — even though a score exists.
    assert rejected.severity == "info"


def test_kev_shape_still_parses():
    # KEV also uses a "vulnerabilities" list but with flat rows — the NVD
    # branch must not swallow it.
    kev = {"vulnerabilities": [{
        "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j",
        "vulnerabilityName": "Log4Shell", "dateAdded": "2021-12-10",
        "shortDescription": "JNDI RCE.", "requiredAction": "Patch", "dueDate": "2021-12-24",
    }]}
    items = translate_json(json.dumps(kev).encode(), "feed-kev")
    assert items[0].cve_id == "CVE-2021-44228"
    assert items[0].severity == "critical"          # KEV presence ratchet


def test_gunzip_capped_roundtrip_and_bomb_guard():
    raw = json.dumps(_nvd_doc()).encode()
    assert _gunzip_capped(gzip.compress(raw)) == raw
    with pytest.raises(ValueError):
        _gunzip_capped(gzip.compress(b"x" * 4096), cap=1024)


def test_gunzip_rejects_truncated_stream():
    # A partially-downloaded feed body must fail loudly, not parse partially.
    full = gzip.compress(b'{"vulnerabilities": []}' * 100)
    with pytest.raises(ValueError, match="truncated"):
        _gunzip_capped(full[: len(full) // 2])


def test_gunzip_handles_multimember_and_zero_padding():
    # Concatenated gzip members are valid gzip; some producers zero-pad the tail.
    two = gzip.compress(b"hello ") + gzip.compress(b"world") + b"\x00" * 8
    assert _gunzip_capped(two) == b"hello world"


def test_meta_sidecar_url_mapping():
    assert _meta_sidecar_url(
        "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
    ) == "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta"
    # Only hosts known to publish sidecars participate.
    assert _meta_sidecar_url("https://example.com/feed.json.gz") == ""
    assert _meta_sidecar_url("https://cvefeed.io/rssfeed/latest.xml") == ""


def _item(**kw):
    d = dict(
        source_feed_id="f1", cve_id="CVE-2026-11111", title="t",
        severity="", cvss=None, link="l", published="p", summary="s",
        fetched_at=time.time(),
    )
    d.update(kw)
    d["item_id"] = make_item_id(d["source_feed_id"], d["cve_id"], d["link"])
    return IntelItem(**d)


def test_intel_store_upserts_on_material_change(tmp_path):
    store = IntelStore(tmp_path / "intel.jsonl")
    assert store.write_many([_item()]) == 1
    # Same content re-fetched → no append.
    assert store.write_many([_item()]) == 0
    # NVD analyzed the CVE: severity/cvss arrive later → row is superseded.
    assert store.write_many([_item(severity="critical", cvss=9.8)]) == 1
    rows = store.all()
    assert len(rows) == 1
    assert rows[0].severity == "critical" and rows[0].cvss == 9.8


def test_meta_gate_skips_unchanged_body(tmp_path, monkeypatch):
    feed = Feed(
        feed_id="f-nvd", name="NVD modified", format="json", poll_seconds=14400,
        url="https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
    )
    feed_store = FeedStore(tmp_path / "feeds.jsonl")
    fetch_store = FeedFetchStore(tmp_path / "fetches.jsonl")
    intel_store = IntelStore(tmp_path / "intel.jsonl")

    body = json.dumps(_nvd_doc()).encode()
    meta = b"lastModifiedDate:2026-07-08T08:00:04-04:00\nsha256:" + b"A" * 64 + b"\n"
    calls = []

    def fake_get(url):
        calls.append(url)
        return 200, meta if url.endswith(".meta") else body

    monkeypatch.setattr(fetcher, "_http_get", fake_get)

    first = fetcher.fetch_feed(feed, feed_store, fetch_store, intel_store)
    assert first.status == "ok" and first.items_count == 3
    assert feed.last_meta_sha256 == "A" * 64

    calls.clear()
    second = fetcher.fetch_feed(feed, feed_store, fetch_store, intel_store)
    assert second.status == "ok"
    assert "unchanged" in second.note
    assert calls == [feed.url.replace(".json.gz", ".meta")]   # body never fetched
    # Corpus counts survive the short-circuit instead of zeroing out.
    assert feed.last_item_count == 3
