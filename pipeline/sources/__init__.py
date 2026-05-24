"""Source providers — materialize a manifest's code into a local path before scan.

A SourceProvider knows how to fetch / clone / checkout the source for a given
manifest and yield a local directory path the adapters can scan. The
orchestrator wraps adapter dispatch with the provider's context manager so
materialization + cleanup are guaranteed even on adapter errors.

Adding a new provider (gitlab, bitbucket, s3, etc.) means dropping a module
here and registering it in PROVIDERS.
"""
from __future__ import annotations

from .base import SourceProvider, SourceMaterialization, SourceError
from .local import LocalProvider
from .github import GitHubProvider


PROVIDERS: dict[str, type[SourceProvider]] = {
    "local": LocalProvider,
    "github": GitHubProvider,
}


def get_provider(name: str) -> SourceProvider:
    cls = PROVIDERS.get(name)
    if cls is None:
        raise SourceError(f"unknown source provider '{name}' (registered: {sorted(PROVIDERS)})")
    return cls()


__all__ = [
    "SourceProvider", "SourceMaterialization", "SourceError",
    "LocalProvider", "GitHubProvider",
    "PROVIDERS", "get_provider",
]
