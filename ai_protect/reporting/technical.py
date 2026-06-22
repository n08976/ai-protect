"""Technical dashboard — per-app, per-adapter detail for the offensive sec leads."""
from __future__ import annotations

from collections import Counter, defaultdict

from ..core.findings import FindingStore, Severity


def build_technical(store: FindingStore) -> dict:
    findings = store.all()
    by_app: dict[str, list] = defaultdict(list)
    by_adapter: dict[str, list] = defaultdict(list)
    by_category = Counter()
    by_severity = Counter()
    by_compliance = Counter()
    open_high = 0

    for f in findings:
        by_app[f.app_name].append(f)
        by_adapter[f.adapter].append(f)
        by_category[f.category.value] += 1
        by_severity[f.severity.value] += 1
        for c in f.compliance:
            by_compliance[c] += 1
        if f.severity in (Severity.HIGH, Severity.CRITICAL):
            open_high += 1

    apps_summary = []
    for app, items in sorted(by_app.items()):
        apps_summary.append({
            "app_name": app,
            "tier": items[0].tier if items else None,
            "total": len(items),
            "high_or_above": sum(1 for f in items if f.severity in (Severity.HIGH, Severity.CRITICAL)),
            "by_category": dict(Counter(f.category.value for f in items)),
        })

    text_lines = [
        "TECHNICAL DASHBOARD — ai-protect pipeline",
        "=" * 60,
        f"Total findings: {len(findings)}",
        f"HIGH or CRITICAL: {open_high}",
        "",
        "By severity:",
        *[f"  {sev:<10} {cnt}" for sev, cnt in sorted(by_severity.items(), key=lambda x: -x[1])],
        "",
        "By category:",
        *[f"  {cat:<22} {cnt}" for cat, cnt in by_category.most_common()],
        "",
        "By adapter:",
        *[f"  {adp:<22} {len(items)}" for adp, items in sorted(by_adapter.items())],
        "",
        "By app:",
        *[
            f"  {a['app_name']:<32} tier={a['tier']} total={a['total']} HIGH+={a['high_or_above']}"
            for a in apps_summary
        ],
        "",
        "Top compliance controls touched:",
        *[f"  {ctrl:<40} {cnt}" for ctrl, cnt in by_compliance.most_common(15)],
    ]

    return {
        "kind": "technical",
        "totals": {
            "findings": len(findings),
            "high_or_above": open_high,
            "apps": len(by_app),
            "adapters_used": len(by_adapter),
        },
        "by_severity": dict(by_severity),
        "by_category": dict(by_category),
        "by_adapter": {adp: len(items) for adp, items in by_adapter.items()},
        "apps": apps_summary,
        "compliance": dict(by_compliance),
        "text": "\n".join(text_lines),
    }
