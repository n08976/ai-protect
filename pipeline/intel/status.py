"""System status lamp — overall + per-component health for the index page.

Levels: green / yellow / red. Overall = worst of the three components.
Components:
  - feeds:  any feed errored on last poll → red. Stale beyond 2× interval → yellow.
  - scans:  any orphan crashed → red. Something running → yellow. Otherwise green.
  - store:  findings path on /tmp → red. Otherwise green.
"""
from __future__ import annotations

import time
from typing import Any

from .feeds import FeedStore
from ..remediate.scans import all_scans, update_status_from_pid


LEVEL_RANK = {"green": 0, "yellow": 1, "red": 2}


def _worst(*levels: str) -> str:
    return max(levels, key=lambda l: LEVEL_RANK.get(l, 0))


def feed_status(feed_store: FeedStore | None = None) -> dict[str, Any]:
    store = feed_store or FeedStore()
    feeds = store.all()
    if not feeds:
        return {"level": "green", "detail": "no feeds configured", "counts": {"total": 0}}
    now = time.time()
    errored = [f for f in feeds if f.enabled and f.last_status not in ("ok", "")]
    never_fetched = [f for f in feeds if f.enabled and not f.last_fetch_ts]
    stale = [
        f for f in feeds
        if f.enabled and f.last_fetch_ts and (now - f.last_fetch_ts) > (2 * f.poll_seconds)
    ]
    if errored:
        return {
            "level": "red",
            "detail": f"{len(errored)} feed(s) errored on last fetch: " + ", ".join(f.name for f in errored[:3]),
            "counts": {"total": len(feeds), "errored": len(errored), "stale": len(stale)},
        }
    if stale or never_fetched:
        bits = []
        if stale: bits.append(f"{len(stale)} stale")
        if never_fetched: bits.append(f"{len(never_fetched)} never fetched")
        return {
            "level": "yellow",
            "detail": " · ".join(bits),
            "counts": {"total": len(feeds), "stale": len(stale), "never_fetched": len(never_fetched)},
        }
    return {
        "level": "green",
        "detail": f"all {len(feeds)} feed(s) fresh",
        "counts": {"total": len(feeds)},
    }


def scan_status() -> dict[str, Any]:
    scans = all_scans()
    if not scans:
        return {"level": "green", "detail": "no scans on record"}
    # Reconcile orphan PIDs before reporting — turns dead "running" rows into
    # failed/crashed so the lamp doesn't show stale state.
    for s in scans[:20]:
        update_status_from_pid(s)
    crashed = [s for s in scans[:50] if s.status == "failed" and s.exit_code in (None, -1)]
    running = [s for s in scans[:20] if s.status == "running"]
    if crashed:
        return {"level": "red", "detail": f"{len(crashed)} recent crashed scan(s)"}
    if running:
        return {"level": "yellow", "detail": f"{len(running)} scan(s) running"}
    return {"level": "green", "detail": "scans idle"}


def store_status(findings_path: str) -> dict[str, Any]:
    if findings_path.startswith("/tmp"):
        return {
            "level": "red",
            "detail": f"findings path '{findings_path}' is on /tmp — results lost on reboot",
        }
    return {"level": "green", "detail": f"findings durable at {findings_path}"}


def overall_status(findings_path: str) -> dict[str, Any]:
    feeds = feed_status()
    scans = scan_status()
    store = store_status(findings_path)
    return {
        "level": _worst(feeds["level"], scans["level"], store["level"]),
        "components": {"feeds": feeds, "scans": scans, "store": store},
    }
