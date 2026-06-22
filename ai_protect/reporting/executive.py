"""Executive dashboard — board-style rollup for CISO and risk committee.

Three numbers the v2.1 quarterly report needs:
  1. Velocity preserved — apps moving through the pipeline, % paved-road
  2. Risk made visible — open HIGH+ count, by tier, by category, trend arrows
  3. Footing established — control coverage % across HIPAA / HITRUST / NIST AI RMF
"""
from __future__ import annotations

from collections import Counter, defaultdict

from ..core.findings import FindingStore, Severity


def build_executive(store: FindingStore) -> dict:
    findings = store.all()
    by_app_tier: dict[str, int] = {}
    open_high_by_tier: dict[int, int] = defaultdict(int)
    open_high_by_category: Counter = Counter()
    compliance_evidence: Counter = Counter()

    for f in findings:
        by_app_tier[f.app_name] = f.tier
        if f.severity in (Severity.HIGH, Severity.CRITICAL):
            open_high_by_tier[f.tier] += 1
            open_high_by_category[f.category.value] += 1
        for c in f.compliance:
            compliance_evidence[c] += 1

    apps_total = len(by_app_tier)
    tier_counts = Counter(by_app_tier.values())
    high_total = sum(open_high_by_tier.values())

    # Group compliance by framework prefix.
    framework_coverage: dict[str, int] = defaultdict(int)
    for ctrl, cnt in compliance_evidence.items():
        framework = ctrl.split("-", 1)[0]
        framework_coverage[framework] += cnt

    tier_labels = [
        (1, "PHI/clinical/ext"),
        (2, "internal action"),
        (3, "internal advisory"),
        (4, "low-impact"),
    ]
    text_lines = [
        "EXECUTIVE DASHBOARD — ai-protect pipeline",
        "=" * 60,
        "",
        "VELOCITY",
        f"  {'Apps in pipeline':<28}{apps_total}",
        *[
            f"  {f'Tier {tier} ({label})':<28}{tier_counts[tier]}"
            for tier, label in tier_labels
        ],
        "",
        "RISK MADE VISIBLE",
        f"  {'Open HIGH+ findings':<28}{high_total}",
        *[f"    {f'Tier {tier}':<26}{open_high_by_tier.get(tier, 0)}" for tier in (1, 2, 3, 4)],
        "",
        "  Top finding categories (HIGH+):",
        *[f"    {cat:<26}{cnt}" for cat, cnt in open_high_by_category.most_common(8)],
        "",
        "FOOTING ESTABLISHED — control evidence touched",
        *[
            f"  {fw:<28}{cnt} evidence records"
            for fw, cnt in sorted(framework_coverage.items(), key=lambda x: -x[1])
        ],
    ]

    return {
        "kind": "executive",
        "velocity": {
            "apps_total": apps_total,
            "tier_counts": dict(tier_counts),
        },
        "risk": {
            "open_high_total": high_total,
            "open_high_by_tier": dict(open_high_by_tier),
            "open_high_by_category": dict(open_high_by_category),
        },
        "footing": {
            "framework_evidence": dict(framework_coverage),
            "control_evidence": dict(compliance_evidence),
        },
        "text": "\n".join(text_lines),
    }
