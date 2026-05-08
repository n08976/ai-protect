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
    if any(not r.gate_passed for r in results):
        sys.exit(2)


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
    p_run.add_argument("--adapter", default=None,
                       help="Run only this adapter (filters the policy table)")
    p_run.set_defaults(func=cmd_run)

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
