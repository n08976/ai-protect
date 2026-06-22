"""GitHubProvider — clone a manifest's repo to a local path before scan.

Auth methods supported:
  - none       — public repo, no token sent
  - pat        — fine-grained or classic PAT, injected as
                 https://x-access-token:<TOKEN>@github.com/...
  - github_app — exchanges App credentials (App ID + private key + installation
                 id) for a short-lived installation access token via the
                 /app/installations/<id>/access_tokens API, then clones with it

Clone strategies:
  - per_scan — shallow clone to a temp dir, removed on exit
  - cached   — persistent clone under settings.source_cache_dir/<owner>/<repo>;
               'git fetch' on subsequent scans for cheap updates

GHES is supported by setting settings.github_base_url to the enterprise
hostname (https://ghes.example.com). The token-exchange URL and clone URLs
both flow off the configured base.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # nosec B404 — used only for git with fixed argv (no shell); inputs validated
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

from ..core import settings as user_settings
from .base import SourceProvider, SourceMaterialization, SourceError


GIT = "git"

# Manifest-supplied owner/repo segments and the git ref are interpolated into
# argv for `git clone`/`checkout`. Even though we never use a shell, a value
# beginning with '-' would be parsed by git as an OPTION (argument injection,
# e.g. ref='--upload-pack=...'). Constrain to safe charsets and reject leading
# dashes. Refs allow '/' (refs/heads/...) but nothing exotic.
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]*$")   # owner / repo name
_SAFE_REF = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._/-]*$")       # branch / tag / SHA


def _resolve_subdir(root: str, subdir: str) -> str:
    """Resolve <root>/<subdir> for monorepo scans, refusing traversal escapes.
    Empty subdir returns the repo root unchanged."""
    if not subdir:
        return root
    rootp = Path(root).resolve()
    p = (rootp / subdir).resolve()
    if p != rootp and rootp not in p.parents:
        raise SourceError(f"github_subdir {subdir!r} escapes the repository root")
    if not p.is_dir():
        raise SourceError(f"github_subdir {subdir!r} does not exist in the repository")
    return str(p)


def _require_safe(value: str, pattern: re.Pattern, what: str) -> str:
    if not pattern.match(value):
        raise SourceError(
            f"unsafe github {what} {value!r}: must match {pattern.pattern} "
            "(no leading '-'; restricted charset) to prevent git argument injection"
        )
    return value


class GitHubProvider(SourceProvider):
    name = "github"

    @contextmanager
    def materialize(self, manifest) -> Iterator[SourceMaterialization]:
        repo = (getattr(manifest, "github_repo", "") or "").strip()
        if not repo:
            raise SourceError(
                f"manifest '{manifest.name}' has source_provider=github but no github_repo set "
                f"(expected 'owner/name' or a full https URL)"
            )
        ref = (
            (getattr(manifest, "github_ref", "") or "").strip()
            or user_settings.get("github_default_ref", "main")
        )
        depth_raw = getattr(manifest, "github_clone_depth", None)
        if depth_raw in (None, ""):
            depth_raw = user_settings.get("github_clone_depth", "1")
        try:
            depth = int(depth_raw)
        except (TypeError, ValueError):
            depth = 1

        ref = _require_safe(ref, _SAFE_REF, "ref")
        base_url = user_settings.get("github_base_url", "https://github.com").rstrip("/")
        owner, repo_name = _split_repo(repo, base_url)
        token = _resolve_token(owner, repo_name, base_url)
        clone_url = _build_clone_url(base_url, owner, repo_name, token)
        strategy = user_settings.get("github_clone_strategy", "per_scan")
        subdir = (getattr(manifest, "github_subdir", "") or "").strip().strip("/")

        if strategy == "cached":
            cache_dir = Path(user_settings.get("source_cache_dir") or "")
            cache_dir = cache_dir.expanduser()
            target = cache_dir / owner / repo_name
            self._fetch_cached(clone_url, target, ref, depth)
            sha = _head_sha(target)
            try:
                yield SourceMaterialization(
                    paths=[_resolve_subdir(str(target), subdir)],
                    provider=self.name,
                    metadata={
                        "owner": owner, "repo": repo_name, "ref": ref,
                        "sha": sha, "clone_strategy": "cached",
                        "base_url": base_url, "subdir": subdir,
                    },
                )
            finally:
                pass   # cache survives — that's the point
        else:
            tmp = tempfile.mkdtemp(prefix=f"ai-protect-{repo_name}-")
            try:
                self._clone_shallow(clone_url, tmp, ref, depth)
                sha = _head_sha(Path(tmp))
                yield SourceMaterialization(
                    paths=[_resolve_subdir(tmp, subdir)],
                    provider=self.name,
                    metadata={
                        "owner": owner, "repo": repo_name, "ref": ref,
                        "sha": sha, "clone_strategy": "per_scan",
                        "base_url": base_url, "subdir": subdir,
                    },
                )
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

    # ----------------------------------------------------------- internals

    def _clone_shallow(self, clone_url: str, target: str, ref: str, depth: int) -> None:
        cmd = [GIT, "clone", "--quiet"]
        if depth and depth > 0:
            cmd += ["--depth", str(depth)]
        # --branch supports tags too, but does NOT accept arbitrary SHAs.
        # When the ref looks like a SHA we clone the branch first and then
        # checkout the SHA explicitly.
        if _looks_like_sha(ref):
            cmd += [_redact(clone_url), target]
            _run_or_raise(cmd, "git clone")
            _run_or_raise([GIT, "-C", target, "checkout", "--quiet", ref], "git checkout")
        else:
            cmd += ["--branch", ref, _redact(clone_url), target]
            # Replace the redacted URL with the real one for the actual exec
            cmd[-2] = clone_url
            _run_or_raise(cmd, "git clone")

    def _fetch_cached(self, clone_url: str, target: Path, ref: str, depth: int) -> None:
        if not target.exists() or not (target / ".git").exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            self._clone_shallow(clone_url, str(target), ref, depth)
            return
        # Existing cache — fetch + checkout the ref.
        # Use the up-to-date URL on every fetch in case the token rotated.
        _run_or_raise([GIT, "-C", str(target), "remote", "set-url", "origin", clone_url],
                      "git remote set-url")
        fetch_cmd = [GIT, "-C", str(target), "fetch", "--quiet"]
        if depth and depth > 0:
            fetch_cmd += ["--depth", str(depth)]
        fetch_cmd += ["origin", ref if _looks_like_sha(ref) else f"{ref}:{ref}"]
        # The colon-form refspec won't work for SHAs; fall back to a plain
        # fetch + checkout in that case.
        try:
            _run_or_raise(fetch_cmd, "git fetch")
        except SourceError:
            _run_or_raise([GIT, "-C", str(target), "fetch", "--quiet", "origin", ref], "git fetch (fallback)")
        _run_or_raise([GIT, "-C", str(target), "checkout", "--quiet", "--force", ref], "git checkout")


# -------------------------------------------------------------- helpers


def _split_repo(repo: str, base_url: str) -> tuple[str, str]:
    """Normalize 'owner/name', full HTTPS URLs, and SSH-style git@ URLs to
    (owner, repo_name)."""
    s = repo.strip().rstrip("/")
    if s.startswith(("http://", "https://")):
        path = urlparse(s).path.lstrip("/")
    elif s.startswith("git@"):
        path = s.split(":", 1)[1].lstrip("/")
    else:
        path = s
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.split("/", 1)
    if len(parts) != 2:
        raise SourceError(f"could not parse 'owner/name' from github_repo='{repo}'")
    owner = _require_safe(parts[0], _SAFE_SEGMENT, "repo owner")
    name = _require_safe(parts[1], _SAFE_SEGMENT, "repo name")
    return owner, name


def _build_clone_url(base_url: str, owner: str, repo_name: str, token: str | None) -> str:
    """Build an HTTPS clone URL, optionally embedding the token for auth."""
    parsed = urlparse(base_url)
    host = parsed.netloc or parsed.path  # tolerate bare hostnames
    scheme = parsed.scheme or "https"
    if token:
        return f"{scheme}://x-access-token:{token}@{host}/{owner}/{repo_name}.git"
    return f"{scheme}://{host}/{owner}/{repo_name}.git"


def _redact(url: str) -> str:
    """Strip the token from a clone URL for logging."""
    if "@" not in url:
        return url
    scheme, rest = url.split("://", 1)
    creds, host_path = rest.split("@", 1)
    return f"{scheme}://***@{host_path}"


def _resolve_token(owner: str, repo_name: str, base_url: str) -> str | None:
    """Return an HTTPS auth token per the configured auth method, or None for
    anonymous (public) cloning."""
    visibility = user_settings.get("github_visibility", "public")
    auth = user_settings.get("github_auth_method", "pat")
    if visibility == "public" and auth == "none":
        return None
    if auth == "none":
        return None
    if auth == "pat":
        token = user_settings.get("github_pat", "") or ""
        return token.strip() or None
    if auth == "github_app":
        return _exchange_app_token(owner, repo_name, base_url)
    return None


def _exchange_app_token(owner: str, repo_name: str, base_url: str) -> str | None:
    """Mint a short-lived installation access token from the configured App."""
    app_id = (user_settings.get("github_app_id") or "").strip()
    key_path = (user_settings.get("github_app_private_key_path") or "").strip()
    install_id = (user_settings.get("github_app_installation_id") or "").strip()
    if not (app_id and key_path and install_id):
        raise SourceError(
            "github_app auth selected but app_id / private_key_path / installation_id are not all set"
        )
    try:
        import jwt as _jwt
    except ImportError:
        raise SourceError("PyJWT not installed (needed for GitHub App auth). pip install PyJWT cryptography")
    try:
        key_bytes = Path(key_path).expanduser().read_bytes()
    except OSError as e:
        raise SourceError(f"cannot read GitHub App private key at {key_path}: {e}")
    now = int(time.time())
    # GitHub requires the iat be in the past — back off 60s to tolerate clock skew.
    payload = {"iat": now - 60, "exp": now + 540, "iss": app_id}
    jwt_token = _jwt.encode(payload, key_bytes, algorithm="RS256")
    # The token-exchange endpoint hangs off the API host: api.github.com for
    # public, /api/v3 for GHES.
    api_host = _api_host(base_url)
    url = f"{api_host}/app/installations/{install_id}/access_tokens"
    import urllib.request as _u
    req = _u.Request(
        url, method="POST",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ai-protect/1.0",
        },
        data=b"",   # empty body required
    )
    try:
        with _u.urlopen(req, timeout=15) as r:  # nosec B310 nosemgrep — URL is the configured GitHub(-ES) API host, not user input
            body = json.loads(r.read())
            return body.get("token")
    except Exception as e:
        raise SourceError(f"GitHub App token exchange failed: {e}")


def _api_host(base_url: str) -> str:
    """Map a GitHub web URL to its REST API host. Public github.com → api.github.com;
    GHES → <ghes>/api/v3."""
    base = base_url.rstrip("/")
    p = urlparse(base)
    host = p.netloc or p.path
    if host.endswith("github.com"):
        return "https://api.github.com"
    return f"{p.scheme or 'https'}://{host}/api/v3"


def _looks_like_sha(ref: str) -> bool:
    if not ref:
        return False
    s = ref.strip()
    return len(s) in (7, 8, 40) and all(c in "0123456789abcdef" for c in s.lower())


def _head_sha(target: Path) -> str:
    try:
        out = subprocess.check_output(  # nosec B603 — git, fixed argv, no shell
            [GIT, "-C", str(target), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL, timeout=10,
        )
        return out.decode().strip()
    except Exception:
        return ""


def _run_or_raise(cmd: list[str], what: str) -> None:
    """Run a subprocess; on failure raise SourceError with the redacted command + stderr."""
    redacted_cmd = [_redact(c) if isinstance(c, str) and c.startswith(("http://", "https://")) else c for c in cmd]
    try:
        proc = subprocess.run(  # nosec B603 — git, fixed argv, no shell; owner/repo/ref validated against safe charset
            cmd, capture_output=True, text=True, timeout=300, check=False,
        )
    except subprocess.TimeoutExpired:
        raise SourceError(f"{what} timed out after 300s: {' '.join(redacted_cmd)}")
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip().splitlines()[-5:]
        raise SourceError(f"{what} failed (rc={proc.returncode}): {' '.join(redacted_cmd)}\n  " + "\n  ".join(tail))
