"""Registry of available findings sinks.

Add a new destination by implementing ``FindingsSink`` and registering it
here — the CLI (`run --sink <name>`, `sinks`) and any future auto-push flow
pick it up automatically.
"""
from __future__ import annotations

from .base import FindingsSink
from .defectdojo import DefectDojoSink

# name -> factory (zero-arg; reads its own config from env/settings)
SINKS: dict[str, type[FindingsSink]] = {
    DefectDojoSink.name: DefectDojoSink,
}


def sink_names() -> list[str]:
    return sorted(SINKS)


def get_sink(name: str, **kwargs) -> FindingsSink:
    try:
        factory = SINKS[name]
    except KeyError:
        raise KeyError(f"unknown sink {name!r}; known: {', '.join(sink_names())}")
    return factory(**kwargs)


def configured_sinks() -> list[FindingsSink]:
    """Instantiate every registered sink and keep the ones that are configured."""
    out: list[FindingsSink] = []
    for factory in SINKS.values():
        try:
            sink = factory()
            if sink.is_configured():
                out.append(sink)
        except Exception:
            continue
    return out
