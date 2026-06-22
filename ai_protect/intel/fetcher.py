"""Fetch feeds, persist intel items, log fetch history, run the poll loop.

The poller is a daemon thread started inside the Flask process (see
ai_protect/ui/server.py). It wakes every POLL_TICK_SECONDS and dispatches each
enabled feed whose `poll_seconds` since `last_fetch_ts` has elapsed.
"""
from __future__ import annotations

import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .feeds import Feed, FeedFetch, FeedFetchStore, FeedStore, IntelStore
from .translators import TranslatorError, detect_format, translate

POLL_TICK_SECONDS = 30
USER_AGENT = "ai-protect/1.0 (+CVE intel poller)"
HTTP_TIMEOUT = 20


def _http_get(url: str) -> tuple[int, bytes]:
    # Restrict to http(s) — blocks file:// / ftp:// and similar via urlopen.
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"refusing non-http(s) feed URL: {url!r}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # nosec B310 — scheme restricted to http(s) above
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def fetch_feed(feed: Feed, feed_store: FeedStore, fetch_store: FeedFetchStore,
               intel_store: IntelStore) -> FeedFetch:
    """One fetch attempt — HTTP, translate, persist, log. Always returns a FeedFetch."""
    started = time.time()
    fetch = FeedFetch(feed_id=feed.feed_id, ts=started, status="ok")
    try:
        http_status, body = _http_get(feed.url)
        fetch.http_status = http_status
        if http_status >= 400 or not body:
            fetch.status = "http_error"
            fetch.error = f"HTTP {http_status}"
        else:
            try:
                items = translate(body, feed.format, feed.feed_id)
            except TranslatorError as e:
                fetch.status = "translator_error"
                fetch.error = str(e)
                items = []
            fetch.items_count = len(items)
            if items:
                fetch.new_count = intel_store.write_many(items)
    except Exception as e:
        fetch.status = "http_error"
        fetch.error = f"{type(e).__name__}: {e}"
    fetch.duration_ms = int((time.time() - started) * 1000)
    fetch_store.write(fetch)

    feed.last_fetch_ts = fetch.ts
    feed.last_status = fetch.status
    feed.last_error = fetch.error
    feed.last_item_count = fetch.items_count
    feed.last_new_count = fetch.new_count
    feed_store.write(feed)
    return fetch


def detect_feed_format(url: str) -> tuple[str, int, str]:
    """Fetch the URL and return (format, http_status, error).

    Used by /feeds (auto-detect on Add/Edit) and /feeds/discover (best-effort
    classification of candidate links). Empty format means detection failed —
    error string explains why.
    """
    try:
        http_status, body = _http_get(url)
        if http_status >= 400 or not body:
            return "", http_status, f"HTTP {http_status}"
        try:
            return detect_format(body), http_status, ""
        except TranslatorError as e:
            return "", http_status, f"unrecognized shape: {e}"
    except Exception as e:
        return "", 0, f"{type(e).__name__}: {e}"


def validate_feed(url: str, fmt: str = "") -> dict:
    """Dry-run a fetch — no persistence. Used by the /feeds validator.

    Returns a structured result the page can render directly:
      {ok, http_status, detected_format, declared_format, format_matches,
       item_count, sample, error}
    """
    out: dict = {
        "ok": False, "http_status": None, "detected_format": None,
        "declared_format": fmt or None, "format_matches": None,
        "item_count": 0, "sample": None, "error": "",
    }
    try:
        http_status, body = _http_get(url)
        out["http_status"] = http_status
        if http_status >= 400 or not body:
            out["error"] = f"HTTP {http_status}"
            return out
        try:
            detected = detect_format(body)
            out["detected_format"] = detected
        except TranslatorError as e:
            out["error"] = f"could not detect format: {e}"
            return out
        use_fmt = fmt or detected
        out["format_matches"] = (not fmt) or (fmt == detected)
        items = translate(body, use_fmt, "validator-preview")
        out["item_count"] = len(items)
        if items:
            s = items[0]
            out["sample"] = {
                "cve_id": s.cve_id, "title": s.title[:140],
                "severity": s.severity, "cvss": s.cvss,
                "published": s.published, "link": s.link,
            }
        out["ok"] = True
    except TranslatorError as e:
        out["error"] = f"translator: {e}"
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


_poller_lock = threading.Lock()
_poller_started = False


def start_poller(feed_store: FeedStore, fetch_store: FeedFetchStore,
                 intel_store: IntelStore) -> None:
    """Idempotently start a daemon thread that polls feeds at their intervals.

    Idempotent because Flask's debug reloader and gunicorn workers can each
    call create_app(); we want a single poller per process.
    """
    global _poller_started
    with _poller_lock:
        if _poller_started:
            return
        _poller_started = True

    def loop():
        while True:
            try:
                _tick(feed_store, fetch_store, intel_store)
            except Exception:
                # Never let an exception kill the poller. Errors per-feed
                # already get logged into FeedFetchStore by fetch_feed.
                pass
            time.sleep(POLL_TICK_SECONDS)

    t = threading.Thread(target=loop, name="intel-poller", daemon=True)
    t.start()


def _tick(feed_store: FeedStore, fetch_store: FeedFetchStore, intel_store: IntelStore) -> None:
    now = time.time()
    for feed in feed_store.all():
        if not feed.enabled:
            continue
        if feed.last_fetch_ts and (now - feed.last_fetch_ts) < feed.poll_seconds:
            continue
        fetch_feed(feed, feed_store, fetch_store, intel_store)
