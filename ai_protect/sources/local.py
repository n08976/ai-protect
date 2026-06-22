"""LocalProvider — passthrough. Manifest's source_paths are already on disk."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from .base import SourceProvider, SourceMaterialization


class LocalProvider(SourceProvider):
    name = "local"

    @contextmanager
    def materialize(self, manifest) -> Iterator[SourceMaterialization]:
        # scan_targets() folds source_paths + source_path together; falls back
        # to ["."] if neither is set, which preserves the existing default
        # behavior of adapters when there's no scope declaration.
        paths = manifest.scan_targets() or ["."]
        yield SourceMaterialization(
            paths=paths,
            provider=self.name,
            metadata={"source_paths": paths},
        )
