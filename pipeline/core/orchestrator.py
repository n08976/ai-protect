"""Pipeline orchestrator — runs the right adapters at the right tier × stage.

This is the heart of the paved-road pipeline. Reads the policy table, looks
up the manifest's tier, instantiates each adapter, runs them in order, and
streams findings into the FindingStore. Returns a RunResult summarizing the
outcome (gate passed / gate failed and why).

Adapters that are unavailable (tool not installed, target not reachable) log
and are skipped — non-fatal. Adapters that produce blocking high-severity
findings fail the gate per the policy table.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..adapters.base import Adapter, AdapterAuthorizationRequired, AdapterUnavailable
from ..adapters.registry import get_adapter_class
from .findings import Finding, FindingStore, Severity
from .manifest import Manifest
from .policy import STAGES, AdapterCall, adapters_for
from .tiering import TierDecision, classify

log = logging.getLogger("ai-protect.orchestrator")


@dataclass
class AdapterResult:
    adapter: str
    blocking: bool
    status: str                         # "ok" | "skipped" | "error" | "unavailable"
    findings_count: int = 0
    high_or_above: int = 0
    error: str | None = None
    duration_s: float = 0.0
    # Fingerprints actually emitted by this adapter in this run. Populated
    # in _run_adapter; consumed by auto_resolve.compute_and_apply at the
    # end of run_stage to detect fingerprints that disappeared this scan.
    emitted_fingerprints: set[str] = field(default_factory=set)


@dataclass
class RunResult:
    app_name: str
    stage: str
    tier_decision: TierDecision
    adapter_results: list[AdapterResult] = field(default_factory=list)
    gate_passed: bool = True
    gate_reason: str | None = None
    findings_path: str | None = None

    def to_dict(self) -> dict:
        return {
            "app_name": self.app_name,
            "stage": self.stage,
            "tier": self.tier_decision.tier,
            "tier_decision": self.tier_decision.to_dict(),
            "gate_passed": self.gate_passed,
            "gate_reason": self.gate_reason,
            "findings_path": self.findings_path,
            "adapter_results": [a.__dict__ for a in self.adapter_results],
        }


class Orchestrator:
    def __init__(self, manifest: Manifest, store: FindingStore, dry_run: bool = False):
        self.manifest = manifest
        self.store = store
        self.dry_run = dry_run

    def run_stage(self, stage: str) -> RunResult:
        if stage not in STAGES:
            raise ValueError(f"Unknown stage {stage!r}; must be one of {STAGES}")
        decision = classify(self.manifest)
        result = RunResult(
            app_name=self.manifest.name,
            stage=stage,
            tier_decision=decision,
            findings_path=str(self.store.path),
        )

        log.info(
            "run %s stage=%s tier=%d (score=%d)",
            self.manifest.name, stage, decision.tier, decision.score,
        )

        # Materialize source ONCE per stage and mutate manifest.source_paths so
        # every adapter in the stage sees the same materialized tree. On
        # provider error (clone failed, auth missing) the whole stage fails
        # gracefully with a single recorded entry — no adapter is invoked.
        try:
            with self._materialize_source() as sm:
                saved_paths = list(self.manifest.source_paths)
                saved_path = self.manifest.source_path
                self.manifest.source_paths = list(sm.paths)
                self.manifest.source_path = None
                try:
                    for call in adapters_for(decision.tier, stage):
                        ar = self._run_adapter(call, stage, decision.tier)
                        result.adapter_results.append(ar)
                        if call.blocking and ar.high_or_above > 0:
                            result.gate_passed = False
                            result.gate_reason = (
                                f"{ar.adapter} produced {ar.high_or_above} HIGH-or-above finding(s) "
                                f"and is marked blocking in the policy table."
                            )
                finally:
                    self.manifest.source_paths = saved_paths
                    self.manifest.source_path = saved_path
        except Exception as e:
            log.exception("source materialization failed for %s", self.manifest.name)
            ar = AdapterResult(adapter="_source", blocking=True, status="error")
            ar.error = f"{type(e).__name__}: {e}"
            result.adapter_results.append(ar)
            result.gate_passed = False
            result.gate_reason = f"source provider failed: {ar.error}"

        # Auto-resolve: any fingerprint a ran-ok adapter previously emitted but
        # didn't this scan is treated as fixed/gone. We don't auto-resolve when
        # materialization failed (no adapter actually looked at code) or when
        # zero adapters ran successfully. Operator can disable via
        # settings.auto_resolve_on_rescan = '' (unchecked).
        ran_ok = {ar.adapter for ar in result.adapter_results if ar.status == "ok"}
        emitted: set[str] = set()
        for ar in result.adapter_results:
            if ar.status == "ok":
                emitted |= ar.emitted_fingerprints
        if ran_ok:
            try:
                from .auto_resolve import compute_and_apply
                scan_id = (self.scan_id if hasattr(self, "scan_id") else None) or f"orch-{int(time.time())}"
                resolutions = compute_and_apply(
                    store=self.store,
                    manifest_name=self.manifest.name,
                    tier=decision.tier,
                    stage=stage,
                    ran_adapters=ran_ok,
                    emitted_fingerprints=emitted,
                    scan_id=scan_id,
                )
                if resolutions:
                    log.info(
                        "auto-resolved %d finding(s) on %s/%s — fingerprints absent this scan",
                        len(resolutions), self.manifest.name, stage,
                    )
            except Exception:
                log.exception("auto-resolve hook failed; continuing")

        log.info(
            "stage %s complete: %d adapter(s); gate=%s",
            stage,
            len(result.adapter_results),
            "PASS" if result.gate_passed else "FAIL",
        )
        return result

    def _materialize_source(self):
        """Resolve and dispatch the source provider for this manifest.

        Provider selection precedence:
          1. manifest.source_provider (explicit per-app override)
          2. settings.default_provider (global)
          3. 'local' (passthrough — preserves pre-2026-05-24 behavior)
        """
        # Local import — keeps the orchestrator loadable in environments that
        # haven't installed the optional source-provider deps (PyJWT etc.).
        from ..sources import get_provider
        from . import settings as _settings
        provider_name = (
            (self.manifest.source_provider or "").strip()
            or _settings.get("default_provider", "local")
            or "local"
        )
        return get_provider(provider_name).materialize(self.manifest)

    def run_all_stages(self, until_fail: bool = True) -> list[RunResult]:
        results = []
        for stage in STAGES:
            r = self.run_stage(stage)
            results.append(r)
            if not r.gate_passed and until_fail:
                log.warning("gate failed at stage=%s; halting subsequent stages", stage)
                break
        return results

    def _run_adapter(self, call: AdapterCall, stage: str, tier: int) -> AdapterResult:
        cls = get_adapter_class(call.adapter)
        adapter = cls(self.manifest, stage=stage, config=call.config or {})
        ar = AdapterResult(adapter=call.adapter, blocking=call.blocking, status="ok")
        t0 = time.time()
        if self.dry_run:
            ar.status = "skipped"
            ar.duration_s = time.time() - t0
            return ar
        try:
            findings = adapter.run()
        except AdapterUnavailable as e:
            ar.status = "unavailable"
            ar.error = str(e)
            ar.duration_s = time.time() - t0
            log.info("adapter %s unavailable: %s", call.adapter, e)
            return ar
        except AdapterAuthorizationRequired as e:
            ar.status = "skipped"
            ar.error = str(e)
            ar.duration_s = time.time() - t0
            log.info("adapter %s skipped (authorization): %s", call.adapter, e)
            return ar
        except SystemExit as e:
            # Some libraries (notably spacy.cli.download) call sys.exit() from
            # subprocess error paths. SystemExit inherits from BaseException
            # not Exception, so `except Exception` below wouldn't catch it.
            # Trap it explicitly so a misbehaving adapter can't kill the whole
            # scan process.
            ar.status = "error"
            ar.error = f"SystemExit (code={e.code}) raised inside {call.adapter}"
            ar.duration_s = time.time() - t0
            log.exception("adapter %s called sys.exit()", call.adapter)
            return ar
        except Exception as e:
            ar.status = "error"
            ar.error = f"{type(e).__name__}: {e}"
            ar.duration_s = time.time() - t0
            log.exception("adapter %s raised", call.adapter)
            return ar
        except BaseException as e:  # noqa: BLE001 — defense in depth
            # Catches anything else weird (KeyboardInterrupt from a misbehaving
            # subprocess, etc.) so the run keeps moving.
            ar.status = "error"
            ar.error = f"{type(e).__name__}: {e}"
            ar.duration_s = time.time() - t0
            log.exception("adapter %s raised %s", call.adapter, type(e).__name__)
            return ar

        # Enrich with intel-feed context before counting / persisting so
        # severity bumps from CISA KEV are reflected in ar.high_or_above and
        # the dashboard sees the enriched form (not the scanner's raw output).
        if findings:
            try:
                from .intel_enrichment import enrich_findings
                enrich_findings(findings)
            except Exception:
                log.exception("intel enrichment failed; falling back to raw scanner findings")
        ar.findings_count = len(findings)
        ar.high_or_above = sum(
            1 for f in findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL)
        )
        ar.duration_s = time.time() - t0
        # Capture the fingerprints THIS adapter emitted — auto_resolve consults
        # this set to decide which prior fingerprints have "disappeared".
        ar.emitted_fingerprints = {f.fingerprint for f in findings}
        if findings:
            self.store.append_many(findings)
        log.info(
            "adapter %s -> %d finding(s) (%d HIGH+) in %.1fs",
            call.adapter, ar.findings_count, ar.high_or_above, ar.duration_s,
        )
        return ar
