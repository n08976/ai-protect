"""Feed config + intel item stores.

Three append-only JSONL files live in REMEDIATE_HOME:
- feeds.jsonl         — latest-row-per-feed_id wins (config + last_* status)
- feed_fetches.jsonl  — every fetch attempt, in order
- intel.jsonl         — fetched intel items, deduped by (source_feed_id, cve_id)

Stores re-read from disk on every call. Fine for the volumes we expect
(< 100 feeds, < 100k items) — avoids any in-process cache invalidation bugs
when the poller thread and the request thread both write.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..remediate.state import REMEDIATE_HOME

FEEDS_PATH = REMEDIATE_HOME / "feeds.jsonl"
FEED_FETCHES_PATH = REMEDIATE_HOME / "feed_fetches.jsonl"
INTEL_PATH = REMEDIATE_HOME / "intel.jsonl"

VALID_FORMATS = ("atom", "rss", "xml", "json")


def new_feed_id() -> str:
    return f"f-{int(time.time())}-{uuid.uuid4().hex[:6]}"


@dataclass
class Feed:
    feed_id: str
    name: str
    url: str
    format: str                         # one of VALID_FORMATS
    poll_seconds: int                   # how often the poller fetches it
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    last_fetch_ts: float | None = None
    last_status: str = ""               # "ok" | "http_error" | "parse_error" | ""
    last_error: str = ""
    last_item_count: int | None = None
    last_new_count: int | None = None   # new (unseen) items in last fetch
    deleted: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class FeedStore:
    def __init__(self, path: Path = FEEDS_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, feed: Feed) -> None:
        with open(self.path, "a") as f:
            f.write(json.dumps(feed.to_dict()) + "\n")

    def all(self, include_deleted: bool = False) -> list[Feed]:
        if not self.path.exists():
            return []
        latest: dict[str, Feed] = {}
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    latest[d["feed_id"]] = Feed(**d)
                except Exception:
                    continue
        out = list(latest.values())
        if not include_deleted:
            out = [x for x in out if not x.deleted]
        return sorted(out, key=lambda x: x.created_at)

    def get(self, feed_id: str) -> Feed | None:
        for f in self.all(include_deleted=True):
            if f.feed_id == feed_id:
                return f
        return None


@dataclass
class FeedFetch:
    feed_id: str
    ts: float
    status: str            # "ok" | "http_error" | "parse_error" | "translator_error"
    items_count: int = 0
    new_count: int = 0
    duration_ms: int = 0
    http_status: int | None = None
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class FeedFetchStore:
    def __init__(self, path: Path = FEED_FETCHES_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, fetch: FeedFetch) -> None:
        with open(self.path, "a") as f:
            f.write(json.dumps(fetch.to_dict()) + "\n")

    def for_feed(self, feed_id: str, limit: int = 50) -> list[FeedFetch]:
        if not self.path.exists():
            return []
        out: list[FeedFetch] = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    if d.get("feed_id") == feed_id:
                        out.append(FeedFetch(**d))
                except Exception:
                    continue
        out.sort(key=lambda x: -x.ts)
        return out[:limit]


@dataclass
class IntelItem:
    item_id: str            # stable hash of (source_feed_id, cve_id or link)
    source_feed_id: str
    cve_id: str             # may be "" if the feed item has no CVE id
    title: str
    severity: str           # "critical"/"high"/"medium"/"low"/"info"/"" — normalized
    cvss: float | None
    link: str
    published: str          # ISO 8601 or RFC 822 — store as-given
    summary: str
    fetched_at: float

    def to_dict(self) -> dict:
        return asdict(self)


def make_item_id(source_feed_id: str, cve_id: str, link: str) -> str:
    """Stable id used for dedupe across fetches."""
    key = f"{source_feed_id}|{cve_id or link}"
    # non-security dedupe id — usedforsecurity=False (clears bandit B324)
    return hashlib.sha1(key.encode("utf-8"), usedforsecurity=False).hexdigest()[:16]


class IntelStore:
    def __init__(self, path: Path = INTEL_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write_many(self, items: list[IntelItem]) -> int:
        """Append items, returning the count actually appended (dedup-filtered)."""
        existing = {i.item_id for i in self.all()}
        new = [i for i in items if i.item_id not in existing]
        with open(self.path, "a") as f:
            for i in new:
                f.write(json.dumps(i.to_dict()) + "\n")
        return len(new)

    def all(self) -> list[IntelItem]:
        if not self.path.exists():
            return []
        latest: dict[str, IntelItem] = {}
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    latest[d["item_id"]] = IntelItem(**d)
                except Exception:
                    continue
        return sorted(latest.values(), key=lambda x: -x.fetched_at)

    def for_feed(self, feed_id: str, limit: int = 200) -> list[IntelItem]:
        return [i for i in self.all() if i.source_feed_id == feed_id][:limit]
