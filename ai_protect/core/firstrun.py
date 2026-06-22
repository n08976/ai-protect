"""First-run welcome banner.

Printed once — the first time any entrypoint (CLI or web UI) runs against a
fresh ``~/.ai-protect`` home — then a sentinel file keeps us quiet forever
after. The goal (per the public-release onboarding work) is to answer the
new user's first three questions before they have to ask:

    1. What did this just create on my machine, and where?
    2. Does anything leave my computer?
    3. Why did some scanners not run, and what do I do about it?

The banner writes to stderr so it never pollutes machine-readable stdout
(the CLI prints JSON to stdout; the UI prints nothing there).
"""
from __future__ import annotations

import sys
from typing import TextIO

from ..remediate.state import REMEDIATE_HOME

SENTINEL = REMEDIATE_HOME / ".welcomed"

_BANNER = """\
┌─ ai-protect · first run ───────────────────────────────┐
  Welcome. Setting up your local install.

  Data home : {home}
              config, findings, intel cache and backups all live here.
              Nothing is written outside this directory or the repo
              you point a scan at.

  Privacy   : everything runs locally. The only outbound traffic is
              the CVE / threat feeds you explicitly enable under
              Settings → Intel feeds.

  Scanners  : adapters that need an external tool (nuclei, trufflehog,
              garak, ZAP, …) are skipped automatically until you
              install them — a zero-setup run still works using the
              built-in checks.

  Next      : python -m ai_protect.cli doctor        # what works on this box
              python -m ai_protect.cli tier <manifest>  # classify an app
              python -m ai_protect.ui.server            # open the dashboard
└────────────────────────────────────────────────┘
"""


def maybe_welcome(stream: TextIO | None = None) -> bool:
    """Print the welcome banner once. Returns True if it was shown.

    Idempotent: a sentinel file under the data home suppresses every
    subsequent call. Never raises into the caller — a read-only or
    unwritable home degrades to "show the banner, skip the sentinel".
    """
    out = stream or sys.stderr
    try:
        if SENTINEL.exists():
            return False
    except OSError:
        return False
    try:
        REMEDIATE_HOME.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    out.write(_BANNER.format(home=REMEDIATE_HOME))
    out.flush()
    try:
        SENTINEL.write_text("")
    except OSError:
        pass
    return True
