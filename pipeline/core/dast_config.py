"""DastConfig — the typed carrier of intent that DAST adapters consume.

Per PAL's design note (gpt-5.2, 2026-05-26): standardize the few knobs
that actually matter across adapters; let each adapter map them to its
native CLI flags rather than forcing every tool into a one-size-fits-all
abstraction.

The four knobs that EVERY DAST adapter should honor:
  - max_rps           — soft request-rate cap (passed to adapters with a rate flag)
  - max_concurrency   — parallel worker hint (nuclei -c, ZAP threadsPerHost)
  - timebox_s         — hard wall-clock cap, applied via subprocess timeout
  - scope_prefix      — URL path the crawler is allowed to descend into; the
                        universal stop on "crawler escapes into the marketing site"

Three additional knobs that gate riskier behavior:
  - require_scope_prefix — when on, crawlers refuse a bare origin (path = '/')
                           unless an explicit scope_prefix is supplied
  - allow_active         — opt-in for state-changing tests (ZAP active, Burp
                           active, sqlmap exploit modes)
  - allow_adversary      — opt-in for adversary emulation (metasploit, atomic,
                           caldera). Distinct from allow_active even if both
                           map to manifest.target.allow_mutation today — PAL
                           recommended designing the UX/code shape so the
                           future split is invisible.

Adapters consume DastConfig.from_manifest(manifest) at run-time. They do
NOT consume settings directly — that keeps the config-resolution logic in
one place and makes the per-manifest override path uniform.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import settings as user_settings


@dataclass
class DastConfig:
    max_rps: int = 20
    max_concurrency: int = 10
    timebox_s: int = 1800
    scope_prefix: str = ""
    require_scope_prefix: bool = True
    allow_active: bool = False
    allow_adversary: bool = False
    # Raw target URL — handy when an adapter needs to derive flags from it
    # (e.g. ZAP context include-regex built from the scope prefix).
    target_url: str = ""

    @classmethod
    def from_manifest(cls, manifest) -> "DastConfig":
        """Load defaults from user settings, then apply per-manifest overrides
        from the TargetEnvironment block."""
        s = user_settings.load()
        try:
            max_rps = int(s.get("dast_max_rps") or 20)
        except (TypeError, ValueError):
            max_rps = 20
        try:
            max_concurrency = int(s.get("dast_max_concurrency") or 10)
        except (TypeError, ValueError):
            max_concurrency = 10
        try:
            timebox_s = int(s.get("dast_timebox_seconds") or 1800)
        except (TypeError, ValueError):
            timebox_s = 1800
        require_scope_prefix = (s.get("dast_require_scope_prefix_for_crawlers", "on") == "on")

        # Per-manifest overrides live on target.* — operators can tune
        # individual apps without touching the global defaults.
        target = getattr(manifest, "target", None)
        target_url = (target and target.base_url) or ""
        allow_active = bool(target and target.allow_mutation)
        # No separate adversary toggle on the dataclass yet — same boolean
        # as allow_active. The UI gate exists so the split can land later
        # without re-painting downstream code.
        allow_adversary = allow_active

        # Scope prefix: if the manifest's base_url has a non-root path,
        # treat that path as the implicit scope. Otherwise blank (and the
        # crawler refuses to launch if require_scope_prefix is on).
        scope_prefix = ""
        if target_url:
            parsed = urlparse(target_url)
            if parsed.path and parsed.path not in ("", "/"):
                scope_prefix = target_url   # keep the full URL as the prefix

        return cls(
            max_rps=max_rps,
            max_concurrency=max_concurrency,
            timebox_s=timebox_s,
            scope_prefix=scope_prefix,
            require_scope_prefix=require_scope_prefix,
            allow_active=allow_active,
            allow_adversary=allow_adversary,
            target_url=target_url,
        )

    def bare_origin(self) -> bool:
        """True if the target_url's path is empty or just '/' — no scope
        narrowing. Crawlers that respect require_scope_prefix refuse this."""
        if not self.target_url:
            return True
        parsed = urlparse(self.target_url)
        return parsed.path in ("", "/")

    def refuse_bare_origin_for(self, adapter_name: str) -> str:
        """Returns a refusal message if a crawler should not run against a
        bare-origin URL, '' otherwise. Adapters call this in preflight().
        """
        if not self.require_scope_prefix:
            return ""
        if not self.bare_origin():
            return ""
        return (
            f"{adapter_name}: refusing to crawl a bare origin {self.target_url!r} — "
            f"set a scope prefix in the manifest's target.base_url (e.g. "
            f"https://target.example.com/myapp/) or turn off "
            f"'Require scope prefix for crawlers' on /settings → DAST defaults."
        )

    def subprocess_timeout(self, override: int | None = None) -> int | None:
        """Return the subprocess.run timeout to use. None when timebox is
        disabled (set to 0). The `override` arg lets an adapter request its
        own shorter timeout (e.g. nuclei needs only 600s); a larger override
        is clamped to the universal cap."""
        if not self.timebox_s or self.timebox_s <= 0:
            return None
        if override and override > 0:
            return min(override, self.timebox_s)
        return self.timebox_s
