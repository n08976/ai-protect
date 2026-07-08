"""Fetch feeds, persist intel items, log fetch history, run the poll loop.

The poller is a daemon thread started inside the Flask process (see
ai_protect/ui/server.py). It wakes every POLL_TICK_SECONDS and dispatches each
enabled feed whose `poll_seconds` since `last_fetch_ts` has elapsed.
"""
from __future__ import annotations

import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

from .feeds import Feed, FeedFetch, FeedFetchStore, FeedStore, IntelStore
from .translators import TranslatorError, detect_format, translate

POLL_TICK_SECONDS = 30
USER_AGENT = "ai-protect/1.0 (+https://github.com/n08976/ai-protect; CVE intel poller)"
HTTP_TIMEOUT = 60
# Download / decompression ceilings — NVD's largest year file is ~30 MB gz /
# ~350 MB raw; anything past these is misconfiguration or a decompression bomb.
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024


def _gunzip_capped(data: bytes, cap: int = MAX_DECOMPRESSED_BYTES) -> bytes:
    """Decompress gzip bytes, refusing to inflate past `cap`.

    Handles multi-member streams (valid gzip may be concatenated members) and
    rejects truncated input — a partially-downloaded NVD feed that still
    parses as JSON would otherwise ingest an incomplete dataset silently.
    """
    out = bytearray()
    remaining = data
    while remaining:
        d = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
        out += d.decompress(remaining, cap - len(out) + 1)
        if len(out) > cap:
            raise ValueError(f"gzip body exceeds {cap} bytes decompressed — refusing")
        if not d.eof:
            raise ValueError("truncated gzip stream — refusing partial feed body")
        # Next member, if any. Some producers zero-pad the tail; tolerate it.
        remaining = d.unused_data.lstrip(b"\x00")
    return bytes(out)


def _read_capped(resp, cap: int = MAX_DOWNLOAD_BYTES) -> bytes:
    """Read an HTTP response body in chunks, refusing to buffer past `cap`."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = resp.read(1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > cap:
            raise ValueError(f"response body exceeds {cap} bytes — refusing")
        chunks.append(chunk)


def _http_get(url: str) -> tuple[int, bytes]:
    # Restrict to http(s) — blocks file:// / ftp:// and similar via urlopen.
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"refusing non-http(s) feed URL: {url!r}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # nosec B310 — scheme restricted to http(s) above
            body = _read_capped(resp)
    except urllib.error.HTTPError as e:
        return e.code, b""
    # Gzip *file* feeds (NVD ships .json.gz) arrive as opaque bytes, not as
    # Content-Encoding — sniff the magic and inflate so every downstream
    # consumer (translators, validator, /feeds/discover) sees plain text.
    if body[:2] == b"\x1f\x8b":
        body = _gunzip_capped(body)
    return resp.status, body


# NVD-style feeds publish a tiny .meta sidecar (lastModifiedDate, size,
# sha256) refreshed every ~2h. Checking it before pulling the multi-MB feed
# is the polite-consumer pattern NVD asks for on the data-feeds page.
_META_SIDECAR_HOSTS = ("nvd.nist.gov",)
_META_SHA_RE = re.compile(r"sha256\s*:\s*([0-9A-Fa-f]{64})")


def _meta_sidecar_url(url: str) -> str:
    """Return the .meta URL for feeds known to ship one, else ''."""
    parts = urllib.parse.urlsplit(url)
    # .json.zip is deliberately absent — the fetcher inflates gzip only, so
    # claiming zip here would gate a body we can't decompress.
    if parts.hostname in _META_SIDECAR_HOSTS and parts.path.endswith((".json.gz", ".json")):
        return re.sub(r"\.json(\.gz)?$", ".meta", url)
    return ""


def _meta_sha256(meta_url: str) -> str:
    """Fetch the sidecar and pull out its sha256. '' on any failure —
    callers fall through to a normal full fetch."""
    try:
        status, body = _http_get(meta_url)
        if status >= 400 or not body:
            return ""
        m = _META_SHA_RE.search(body.decode("utf-8", "replace"))
        return m.group(1).upper() if m else ""
    except Exception:
        return ""


def fetch_feed(feed: Feed, feed_store: FeedStore, fetch_store: FeedFetchStore,
               intel_store: IntelStore) -> FeedFetch:
    """One fetch attempt — HTTP, translate, persist, log. Always returns a FeedFetch."""
    started = time.time()
    fetch = FeedFetch(feed_id=feed.feed_id, ts=started, status="ok")
    unchanged = False
    meta_sha = ""
    try:
        meta_url = _meta_sidecar_url(feed.url)
        if meta_url:
            meta_sha = _meta_sha256(meta_url)
            if meta_sha and meta_sha == feed.last_meta_sha256:
                unchanged = True
                fetch.note = "unchanged (META gate) — feed body not downloaded"
        if not unchanged:
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
                if meta_sha and fetch.status == "ok":
                    feed.last_meta_sha256 = meta_sha
    except Exception as e:
        fetch.status = "http_error"
        fetch.error = f"{type(e).__name__}: {e}"
    fetch.duration_ms = int((time.time() - started) * 1000)
    fetch_store.write(fetch)

    feed.last_fetch_ts = fetch.ts
    feed.last_status = fetch.status
    feed.last_error = fetch.error
    if not unchanged:
        # An unchanged META short-circuit keeps the previous corpus counts —
        # overwriting them with 0 would misread as "the feed went empty".
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
