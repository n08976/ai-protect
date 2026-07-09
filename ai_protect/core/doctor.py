"""`ai-protect doctor` — environment + adapter capability report.

The onboarding question this answers is: *"what actually works on my machine
right now, and what do I need to install to unlock the rest?"*

We probe every registered adapter's ``preflight()`` against a permissive stub
manifest (a real bundled sample with a dummy live target + mutation allowed) so
the signal measured is **tool/credential availability**, not target
reachability. Each probe runs in a worker thread with a hard timeout and a low
socket default, so an adapter that tries to reach an absent daemon (ZAP,
Metasploit, Caldera, …) degrades to "needs setup" instead of hanging the CLI.

Results classify into:
  live           — ready to run with zero extra setup
  needs_setup    — external tool / API key / daemon missing (hint included)
  mutation_gated — installed & ready, but only runs when a manifest opts into
                   state-changing actions (target.allow_mutation = true)
"""
from __future__ import annotations

import concurrent.futures
import platform
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

from ..adapters.base import AdapterAuthorizationRequired, AdapterUnavailable
from ..adapters.registry import REGISTRY
from ..core.manifest import Manifest
from ..remediate.state import REMEDIATE_HOME
from . import settings as user_settings

try:
    from ..ui.catalog import CATALOG
except Exception:                       # UI optional; doctor still works
    CATALOG = {}

LIVE = "live"
NEEDS_SETUP = "needs_setup"
GATED = "mutation_gated"

_MARK = {LIVE: "✓", NEEDS_SETUP: "○", GATED: "◐"}
_LABEL = {LIVE: "live", NEEDS_SETUP: "needs setup", GATED: "mutation-gated"}

_SAMPLE = Path(__file__).resolve().parent.parent / "manifests" / "SAMPLE-clinical-assistant-prototype.yml"
_PROBE_TIMEOUT = 6.0


@dataclass
class AdapterStatus:
    name: str
    kind: str
    category: str
    status: str
    detail: str

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind, "category": self.category,
                "status": self.status, "detail": self.detail}


def _first_line(text: str) -> str:
    for ln in (text or "").strip().splitlines():
        if ln.strip():
            return ln.strip()
    return ""


def _stub_manifest() -> Manifest | None:
    try:
        m = Manifest.from_yaml(_SAMPLE)
    except Exception:
        return None
    # Make the target permissive so DAST adapters reach their binary/daemon
    # check rather than failing on "no target given".
    try:
        m.target.base_url = "https://example.com"
        m.target.api_url = "https://example.com"
        m.target.allow_mutation = True
    except Exception:
        pass
    return m


def _probe(name: str, cls, manifest: Manifest) -> AdapterStatus:
    meta = CATALOG.get(name, {})
    kind = meta.get("kind", "?")
    category = meta.get("category", "Other")

    def run() -> AdapterStatus:
        try:
            cls(manifest, "preprod", {}).preflight()
            return AdapterStatus(name, kind, category, LIVE, "ready")
        except AdapterAuthorizationRequired:
            return AdapterStatus(name, kind, category, GATED,
                                 "set target.allow_mutation in the manifest to enable")
        except AdapterUnavailable as e:
            return AdapterStatus(name, kind, category, NEEDS_SETUP, _first_line(str(e)))
        except Exception as e:                       # never let one adapter break doctor
            return AdapterStatus(name, kind, category, NEEDS_SETUP,
                                 f"{type(e).__name__}: {_first_line(str(e))}")

    # Most preflights are a `which`/socket check and finish in well under a
    # second, so the tight default keeps a mis-probed daemon adapter from
    # hanging doctor. Adapters that load a model in preflight (presidio pulls
    # in a ~400 MB spaCy model) declare a longer budget via a class attribute.
    timeout = getattr(cls, "doctor_probe_timeout", None) or _PROBE_TIMEOUT

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(run)
        try:
            return fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return AdapterStatus(name, kind, category, NEEDS_SETUP,
                                 "probe timed out — required service/daemon not reachable")


def diagnose() -> dict:
    """Build the full doctor report (environment + per-adapter capability)."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3)
    try:
        manifest = _stub_manifest()
        statuses: list[AdapterStatus] = []
        if manifest is not None:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                statuses = list(ex.map(lambda kv: _probe(kv[0], kv[1], manifest),
                                       sorted(REGISTRY.items())))
    finally:
        socket.setdefaulttimeout(old_timeout)

    findings_path = user_settings.get("findings_path", "") or str(REMEDIATE_HOME / "findings.jsonl")
    fp = Path(findings_path)
    counts = {LIVE: 0, NEEDS_SETUP: 0, GATED: 0}
    for s in statuses:
        counts[s.status] = counts.get(s.status, 0) + 1

    return {
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "data_home": str(REMEDIATE_HOME),
            "data_home_exists": REMEDIATE_HOME.exists(),
            "findings_path": findings_path,
            "findings_exists": fp.exists(),
            "config_exists": (REMEDIATE_HOME / "config.json").exists(),
            "source_provider": user_settings.get("source_provider", "filesystem"),
        },
        "adapters": [s.to_dict() for s in statuses],
        "summary": {"total": len(statuses), **counts},
    }


def render_text(report: dict) -> str:
    env = report["environment"]
    summ = report["summary"]
    out: list[str] = []
    out.append("ai-protect doctor")
    out.append("=" * 60)
    out.append("Environment")
    out.append(f"  python         {env['python']}  ({env['platform']})")
    out.append(f"  data home      {env['data_home']}  [{'present' if env['data_home_exists'] else 'will be created'}]")
    out.append(f"  findings       {env['findings_path']}  [{'present' if env['findings_exists'] else 'empty — no scans yet'}]")
    out.append(f"  settings       config.json {'present' if env['config_exists'] else 'not yet — using defaults'}")
    out.append(f"  source provider {env['source_provider']}")
    out.append("")

    # group adapters by category, ordered
    by_cat: dict[str, list[dict]] = {}
    for a in report["adapters"]:
        by_cat.setdefault(a["category"], []).append(a)
    out.append("Adapters")
    for cat in sorted(by_cat):
        out.append(f"  {cat}")
        for a in sorted(by_cat[cat], key=lambda x: x["name"]):
            mark = _MARK.get(a["status"], "?")
            line = f"    {mark} {a['name']:<20} {_LABEL.get(a['status'], a['status'])}"
            if a["status"] != LIVE and a["detail"]:
                line += f" — {a['detail']}"
            out.append(line)
    out.append("")
    out.append("Summary")
    out.append(f"  {summ.get(LIVE, 0)} live · {summ.get(GATED, 0)} mutation-gated · "
               f"{summ.get(NEEDS_SETUP, 0)} need setup  (of {summ['total']})")
    out.append("  Built-in policy/AI checks run with zero setup. Install the tools above")
    out.append("  to light up the rest — every missing tool is skipped non-fatally.")
    return "\n".join(out)
