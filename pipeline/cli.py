"""ai-protect CLI — entrypoint for the pipeline.

Examples:

    # Classify a manifest into a tier
    python -m pipeline.cli tier manifests/example_clinical_assistant.yml

    # Run a specific stage end-to-end
    python -m pipeline.cli run manifests/example_clinical_assistant.yml --stage preprod

    # Run every stage in sequence (stops at first gate failure)
    python -m pipeline.cli run manifests/example_clinical_assistant.yml --all

    # Generate dashboards from accumulated findings
    python -m pipeline.cli report --kind technical
    python -m pipeline.cli report --kind executive

    # List adapters and what they map to
    python -m pipeline.cli adapters
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .adapters.registry import REGISTRY
from .core.findings import FindingStore
from .core.manifest import Manifest
from .core.orchestrator import Orchestrator
from .core.policy import STAGES, adapters_for
from .core.tiering import classify


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FINDINGS = REPO_ROOT / "pipeline" / "findings" / "findings.jsonl"


def cmd_tier(args):
    m = Manifest.from_yaml(args.manifest)
    decision = classify(m)
    print(json.dumps(decision.to_dict(), indent=2))


def cmd_run(args):
    m = Manifest.from_yaml(args.manifest)
    store = FindingStore(args.findings)
    orc = Orchestrator(m, store, dry_run=args.dry_run)
    if getattr(args, "scan_id", None):
        orc.scan_id = args.scan_id
    # Optional adapter filter — temporarily narrows the policy table to one adapter.
    if args.adapter:
        from .core import policy
        original = policy.POLICY
        narrowed = {tier: {stage: [c for c in calls if c.adapter == args.adapter]
                           for stage, calls in stages.items()}
                    for tier, stages in original.items()}
        policy.POLICY = narrowed
        try:
            if args.all:
                results = orc.run_all_stages(until_fail=not args.no_halt)
            else:
                results = [orc.run_stage(args.stage)]
        finally:
            policy.POLICY = original
    else:
        if args.all:
            results = orc.run_all_stages(until_fail=not args.no_halt)
        else:
            results = [orc.run_stage(args.stage)]
    for r in results:
        print(json.dumps(r.to_dict(), indent=2))
    # Policy gate: a blocking adapter produced HIGH+ findings.
    gate_fail = any(not r.gate_passed for r in results)
    # Optional CI deploy gate: fail on ANY finding at/above a severity, regardless
    # of the per-adapter blocking flag (the per-adapter `blocking` flag only gates
    # secrets / AI-red-team / policy classes — this lets CI block on Critical/High
    # from SAST/SCA too, which is what `cli remediate` then auto-fixes).
    sev = getattr(args, "fail_on_severity", None)
    if sev:
        for r in results:
            for a in r.adapter_results:
                if (sev == "critical" and a.critical_count > 0) or \
                   (sev == "high" and a.high_or_above > 0):
                    gate_fail = True
    if gate_fail:
        sys.exit(2)


def cmd_remediate(args):
    """Headless fix → verify loop for CI.

    For each open finding at/above the severity threshold that a remediator can
    handle: propose a fix. With --auto AND Tier 3-4, also approve → apply →
    re-scan to verify (reverting any fix the re-scan can't confirm). Tier 1-2
    never auto-applies (the engine enforces this) — fixes are proposed for a
    human, matching the paved-road tier fork. The gate decision stays with
    `cli run`; re-run it after this to re-gate.
    """
    from collections import Counter

    from .core.findings import SEVERITY_SCORE, Severity
    from .remediate.engine import Engine, EngineError
    from .remediate.registry import remediators_for
    from .remediate.state import ChangeState

    m = Manifest.from_yaml(args.manifest)
    store = FindingStore(args.findings)
    tier = classify(m).tier
    engine = Engine(m, store)

    threshold = SEVERITY_SCORE[Severity(args.severity)]
    auto = args.auto and tier >= 3        # engine forbids Tier 1-2 auto-apply

    # Latest finding per fingerprint for this app, at/above threshold, fixable.
    latest: dict[str, object] = {}
    for f in store.by_app(m.name):
        latest[f.fingerprint] = f
    candidates = [
        f for f in latest.values()
        if SEVERITY_SCORE.get(f.severity, 0) >= threshold and remediators_for(f, m.raw)
    ]
    if args.max:
        candidates = candidates[: args.max]

    results = []
    for f in candidates:
        rec = {"finding_id": f.finding_id, "severity": f.severity.value,
               "title": f.title[:90]}
        try:
            change = engine.propose(f.finding_id, actor="auto")
        except EngineError as e:
            rec["outcome"] = "no_fix"; rec["detail"] = str(e); results.append(rec); continue
        rec["change_id"] = change.change_id
        rec["strategy"] = change.strategy
        if not auto:
            rec["outcome"] = "proposed_awaiting_human"
            rec["reason"] = (f"Tier {tier} requires human apply"
                             if tier <= 2 else "auto-apply disabled (--auto off)")
            results.append(rec); continue
        try:
            engine.approve(change.change_id, actor="auto")
            engine.apply(change.change_id, actor="auto")
            ch, summary = engine.rescan(change.change_id, actor="auto")
        except EngineError as e:
            rec["outcome"] = "apply_error"; rec["detail"] = str(e); results.append(rec); continue
        rec["rescan"] = summary
        if ch.state == ChangeState.VALIDATED:
            rec["outcome"] = "fixed_verified"
        else:
            try:
                engine.rollback(change.change_id, actor="auto")
            except EngineError:
                pass
            rec["outcome"] = "fix_unverified_reverted"
        results.append(rec)

    counts = Counter(r["outcome"] for r in results)
    out = {"app": m.name, "tier": tier, "auto_apply": auto,
           "candidates": len(candidates), "outcomes": dict(counts), "changes": results}
    if args.format == "json":
        print(json.dumps(out, indent=2))
    else:
        print(f"remediate: app={m.name} tier={tier} auto_apply={auto} "
              f"candidates={len(candidates)}")
        for k, v in sorted(counts.items()):
            print(f"  {k}: {v}")
        for r in results:
            print(f"  - [{r['outcome']:<23}] {r['severity']:<8} "
                  f"{r.get('strategy','-'):<22} {r['title']}")

    if args.fail_on_unfixed:
        unfixed = sum(counts.get(k, 0) for k in
                      ("no_fix", "apply_error", "fix_unverified_reverted",
                       "proposed_awaiting_human"))
        if unfixed:
            sys.exit(3)


def cmd_report(args):
    from .reporting.technical import build_technical
    from .reporting.executive import build_executive

    store = FindingStore(args.findings)
    if args.kind == "technical":
        out = build_technical(store)
    elif args.kind == "executive":
        out = build_executive(store)
    else:
        raise SystemExit(f"unknown report kind {args.kind!r}")
    if args.format == "json":
        print(json.dumps(out, indent=2))
    else:
        print(out["text"])


def cmd_adapters(args):
    rows = []
    for name, cls in sorted(REGISTRY.items()):
        rows.append({
            "name": name,
            "description": cls.description,
            "requires_mutation": getattr(cls, "requires_mutation", False),
        })
    if args.format == "json":
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            mut = " [mutation]" if r["requires_mutation"] else ""
            print(f"  {r['name']:<22}{mut}  {r['description']}")


def cmd_policy(args):
    print(f"Tier {args.tier} × stage {args.stage}:")
    for c in adapters_for(args.tier, args.stage):
        flag = " [BLOCKING]" if c.blocking else ""
        cfg = f"  config={c.config}" if c.config else ""
        print(f"  - {c.adapter}{flag}{cfg}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ai-protect", description="Offensive security pipeline for AI workloads")
    parser.add_argument("--findings", default=str(DEFAULT_FINDINGS),
                        help="Path to findings JSONL store (append-only).")
    parser.add_argument("-v", "--verbose", action="store_true")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_tier = sub.add_parser("tier", help="Classify a manifest into a tier")
    p_tier.add_argument("manifest")
    p_tier.set_defaults(func=cmd_tier)

    p_run = sub.add_parser("run", help="Run one or all pipeline stages for a manifest")
    p_run.add_argument("manifest")
    p_run.add_argument("--stage", choices=STAGES, default="preprod")
    p_run.add_argument("--all", action="store_true", help="Run every stage in sequence")
    p_run.add_argument("--no-halt", action="store_true",
                       help="With --all, continue past failing gates")
    p_run.add_argument("--dry-run", action="store_true",
                       help="List what would run without invoking adapters")
    p_run.add_argument("--scan-id", default=None,
                       help="Optional scan id (passed through to events / auto-resolve provenance). "
                            "scan_runner.py supplies this when launching from the UI.")
    p_run.add_argument("--adapter", default=None,
                       help="Run only this adapter (filters the policy table)")
    p_run.add_argument("--fail-on-severity", choices=["high", "critical"], default=None,
                       help="Also fail the gate (exit 2) if this run produced any finding "
                            "at/above this severity, regardless of the per-adapter blocking "
                            "flag. Use this as the CI deploy gate.")
    p_run.set_defaults(func=cmd_run)

    p_rem = sub.add_parser("remediate", help="Headless fix → verify loop (CI). Propose fixes; "
                                             "Tier 3-4 + --auto also apply + re-scan to verify.")
    p_rem.add_argument("manifest")
    p_rem.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"],
                       default="high", help="Minimum finding severity to remediate.")
    p_rem.add_argument("--auto", action="store_true",
                       help="Apply + verify fixes (Tier 3-4 only; Tier 1-2 always propose-only).")
    p_rem.add_argument("--max", type=int, default=0, help="Cap candidates processed (0 = no cap).")
    p_rem.add_argument("--fail-on-unfixed", action="store_true",
                       help="Exit 3 if any qualifying finding wasn't fixed+verified.")
    p_rem.add_argument("--format", choices=["text", "json"], default="text")
    p_rem.set_defaults(func=cmd_remediate)

    p_rep = sub.add_parser("report", help="Generate a dashboard report from findings")
    p_rep.add_argument("--kind", choices=["technical", "executive"], default="technical")
    p_rep.add_argument("--format", choices=["text", "json"], default="text")
    p_rep.set_defaults(func=cmd_report)

    p_adp = sub.add_parser("adapters", help="List registered adapters")
    p_adp.add_argument("--format", choices=["text", "json"], default="text")
    p_adp.set_defaults(func=cmd_adapters)

    p_pol = sub.add_parser("policy", help="Show the policy table for a tier × stage")
    p_pol.add_argument("--tier", type=int, required=True, choices=[1, 2, 3, 4])
    p_pol.add_argument("--stage", required=True, choices=STAGES)
    p_pol.set_defaults(func=cmd_policy)

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
