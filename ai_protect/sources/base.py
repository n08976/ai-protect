"""Base classes for source providers."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator


class SourceError(Exception):
    """Raised when a source provider cannot materialize the manifest source."""


@dataclass
class SourceMaterialization:
    """The materialized form of a manifest's source. The adapters scan paths;
    metadata is logged for traceability (commit SHA, ref, provider name)."""
    paths: list[str]                # filesystem paths the adapters should scan
    provider: str                   # "local" / "github" / ...
    metadata: dict[str, Any]        # provider-specific (e.g. {"sha": "...", "ref": "main"})


class SourceProvider:
    """A source provider materializes a manifest into one or more local paths
    and cleans up on exit. Subclasses override `materialize()` as a context
    manager; the orchestrator uses it like:

        with provider.materialize(manifest) as sm:
            for adapter_call in stage:
                # adapters scan sm.paths
                run_adapter(adapter_call, manifest, source=sm)
    """

    name: str = ""

    @contextmanager
    def materialize(self, manifest) -> Iterator[SourceMaterialization]:
        """Yield a SourceMaterialization. Cleanup happens on exit, including
        on exceptions. Subclasses must implement."""
        raise NotImplementedError
        yield  # pragma: no cover  (satisfies the iterator return type)
