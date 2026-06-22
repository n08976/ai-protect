"""External integrations / findings sinks for ai-protect.

A *sink* is a destination for normalized findings produced by a scan. The
``FindingsSink`` base class and the registry keep destinations pluggable:
implement the base class, register in ``registry.py``, and the CLI/run flow
can route findings to it. DefectDojo is the first concrete sink.
"""
from __future__ import annotations

from .base import FindingsSink, SinkContext, SinkNotConfigured, SinkResult
from .registry import configured_sinks, get_sink, sink_names

__all__ = [
    "FindingsSink",
    "SinkContext",
    "SinkResult",
    "SinkNotConfigured",
    "configured_sinks",
    "get_sink",
    "sink_names",
]
