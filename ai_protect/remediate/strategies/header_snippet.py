"""header_snippet — generate a Flask middleware that adds missing security headers.

Strategy:
  - Group nuclei "missing security headers" findings by which header is missing
  - Emit a Flask after_request snippet (or Nginx/Caddy fragment) that adds them
  - Phase 1: snippet is surfaced for manual application — file_changes is empty
    unless manifest declares `web_config_path` pointing at the Flask app file.
  - Test plan: a pytest that boots the Flask app, hits "/", asserts header set

Confidence:
  - 0.85 when manifest has web_config_path declared
  - 0.6 when surfaced as snippet only (no file change)
"""
from __future__ import annotations

import re
from pathlib import Path

from ...core.findings import Category, Finding
from ..base import FileChange, Proposal, Remediator


# Map common nuclei header names → header value snippets we'd add.
HEADER_VALUES = {
    "x-frame-options": ("X-Frame-Options", "DENY"),
    "x-content-type-options": ("X-Content-Type-Options", "nosniff"),
    "referrer-policy": ("Referrer-Policy", "strict-origin-when-cross-origin"),
    "permissions-policy": ("Permissions-Policy", "geolocation=(), camera=(), microphone=()"),
    "strict-transport-security": ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    "content-security-policy": ("Content-Security-Policy", "default-src 'self'"),
    "cross-origin-embedder-policy": ("Cross-Origin-Embedder-Policy", "require-corp"),
    "cross-origin-opener-policy": ("Cross-Origin-Opener-Policy", "same-origin"),
    "cross-origin-resource-policy": ("Cross-Origin-Resource-Policy", "same-origin"),
}


class HeaderSnippetRemediator(Remediator):
    name = "header_snippet"
    handles = {Category.INFRA_VULN}
    description = "Generate Flask middleware adding the missing security header(s); apply if web_config_path declared."

    def can_fix(self, finding: Finding, manifest_raw: dict) -> bool:
        if finding.category != Category.INFRA_VULN:
            return False
        if finding.adapter != "nuclei":
            return False
        title = (finding.title or "").lower()
        return "header" in title

    def propose(self, finding: Finding, manifest_raw: dict) -> Proposal | None:
        # Identify which headers are missing — try evidence first, then title.
        missing = self._detect_headers(finding)
        if not missing:
            return None
        snippet = _flask_after_request_snippet(missing)
        target_url = (finding.affected or {}).get("target", "")

        web_config = manifest_raw.get("web_config_path")
        file_changes: list[FileChange] = []
        confidence = 0.6
        if web_config and Path(web_config).exists():
            patched = _inject_into_flask_file(Path(web_config).read_text(), snippet)
            file_changes = [FileChange(path=str(Path(web_config).resolve()), new_content=patched, create=False)]
            confidence = 0.85

        summary = (
            f"Add {len(missing)} missing security header(s) to {target_url}: "
            + ", ".join(h for h, _ in missing)
        )

        return Proposal(
            summary=summary,
            confidence=confidence,
            rescan_adapter="nuclei",
            file_changes=file_changes,
            test_plan={
                "kind": "http_header",
                "url": target_url,
                "headers": [h for h, _ in missing],
            },
            notes=(
                "Phase 1 default: snippet surfaced for manual application unless "
                "manifest.web_config_path is set. Snippet shown in change notes.\n\n" + snippet
            ),
        )

    @staticmethod
    def _detect_headers(finding: Finding) -> list[tuple[str, str]]:
        # nuclei missing-headers templates emit multiple findings, one per header.
        # The template name or matched_at often reveals which header is missing.
        ev = finding.evidence or {}
        text = " ".join([
            (ev.get("template") or ""),
            (ev.get("matcher_name") or ""),
            (finding.title or ""),
        ]).lower()
        out = []
        for key, val in HEADER_VALUES.items():
            if key in text:
                out.append(val)
        # Default fallback: if nuclei didn't tell us which header, propose the
        # safest-by-default trio.
        if not out:
            out = [
                HEADER_VALUES["x-content-type-options"],
                HEADER_VALUES["x-frame-options"],
                HEADER_VALUES["referrer-policy"],
            ]
        return out


def _flask_after_request_snippet(headers: list[tuple[str, str]]) -> str:
    lines = ["# Added by ai-protect remediation. Review before deploying.",
             "@app.after_request",
             "def _ai_protect_security_headers(response):"]
    for name, val in headers:
        lines.append(f"    response.headers.setdefault({name!r}, {val!r})")
    lines.append("    return response")
    return "\n".join(lines)


_FLASK_APP_RE = re.compile(r"^app\s*=\s*Flask\(", re.MULTILINE)


def _inject_into_flask_file(source: str, snippet: str) -> str:
    """Insert the snippet after the `app = Flask(...)` line."""
    m = _FLASK_APP_RE.search(source)
    if not m:
        # No detected Flask app — append at end.
        return source.rstrip() + "\n\n\n" + snippet + "\n"
    end = source.find("\n", m.end())
    if end < 0:
        end = len(source)
    return source[: end + 1] + "\n\n" + snippet + "\n" + source[end + 1 :]
