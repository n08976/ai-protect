"""Flask web UI — live findings dashboard.

Reads the FindingStore on every request, so adapters can be running in another
process and findings will surface as they're written.

Run:
    python -m pipeline.ui.server --findings /tmp/findings.jsonl --port 8000
"""
from __future__ import annotations

import argparse
import os
from collections import Counter, defaultdict
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, url_for

from ..adapters.registry import REGISTRY
from ..core.findings import FindingStore, Severity
from ..core.tiering import classify
from ..core.manifest import Manifest
from ..remediate.engine import Engine, EngineError
from ..remediate.registry import remediators_for
from ..remediate.state import ChangeState, ChangeStore, EventStore
from .catalog import CATALOG, CATEGORY_ORDER

DEFAULT_ACTOR = "operator@example.com"


def create_app(findings_path: str, manifests_dir: str) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.config["FINDINGS_PATH"] = findings_path
    app.config["MANIFESTS_DIR"] = manifests_dir

    def _engine_for(app_name: str) -> Engine | None:
        """Build an Engine for the manifest matching this app."""
        md = Path(app.config["MANIFESTS_DIR"])
        if not md.is_dir():
            return None
        for p in md.glob("*.yml"):
            try:
                m = Manifest.from_yaml(p)
                if m.name == app_name:
                    return Engine(m, FindingStore(app.config["FINDINGS_PATH"]))
            except Exception:
                continue
        return None

    @app.route("/")
    def index():
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None  # always re-read
        findings = store.all()
        # Filters
        sev_filter = request.args.get("severity")
        cat_filter = request.args.get("category")
        app_filter = request.args.get("app")
        adapter_filter = request.args.get("adapter")
        if sev_filter:
            findings = [f for f in findings if f.severity.value == sev_filter]
        if cat_filter:
            findings = [f for f in findings if f.category.value == cat_filter]
        if app_filter:
            findings = [f for f in findings if f.app_name == app_filter]
        if adapter_filter:
            findings = [f for f in findings if f.adapter == adapter_filter]
        findings.sort(key=lambda f: (-f.severity_score, f.detected_at), reverse=False)
        findings.sort(key=lambda f: -f.severity_score)
        all_findings = store.all()
        return render_template(
            "index.html",
            findings=findings,
            stats=_stats(all_findings),
            filter_severity=sev_filter,
            filter_category=cat_filter,
            filter_app=app_filter,
            filter_adapter=adapter_filter,
            apps=sorted({f.app_name for f in all_findings}),
            categories=sorted({f.category.value for f in all_findings}),
            adapters=sorted({f.adapter for f in all_findings}),
            severities=["critical", "high", "medium", "low", "info"],
        )

    @app.route("/finding/<finding_id>")
    def finding_detail(finding_id):
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        for f in store.all():
            if f.finding_id == finding_id:
                return render_template("finding.html", finding=f)
        return "Not found", 404

    @app.route("/api/findings")
    def api_findings():
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        return jsonify([f.to_dict() for f in store.all()])

    @app.route("/api/stats")
    def api_stats():
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        return jsonify(_stats(store.all()))

    @app.route("/about")
    def about():
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        findings = store.all()
        # Per-adapter live counts from the current findings store
        from collections import Counter
        counts = Counter(f.adapter for f in findings)
        registered = set(REGISTRY)
        catalog_names = set(CATALOG)

        # Group adapters by category, in display order
        by_category: dict[str, list[dict]] = {c: [] for c in CATEGORY_ORDER}
        for name in sorted(registered | catalog_names):
            meta = CATALOG.get(name, {
                "description": "(No catalog entry)",
                "source_url": "",
                "stages": "",
                "category": "Production · telemetry",
                "kind": "policy",
            })
            by_category.setdefault(meta["category"], []).append({
                "name": name,
                "description": meta["description"],
                "source_url": meta["source_url"],
                "stages": meta["stages"],
                "kind": meta["kind"],
                "registered": name in registered,
                "count": counts.get(name, 0),
            })

        # Live results table — split into found / clean / unavailable / not-applicable
        # We classify by the *current* findings store + which adapters are registered.
        results = {"found": [], "clean": [], "not_applicable": []}
        for name in sorted(registered):
            cnt = counts.get(name, 0)
            meta = CATALOG.get(name, {})
            row = {
                "name": name,
                "count": cnt,
                "stages": meta.get("stages", ""),
                "category": meta.get("category", ""),
                "kind": meta.get("kind", "policy"),
            }
            if cnt > 0:
                results["found"].append(row)
            else:
                # Without per-run telemetry we can't tell clean vs unavailable
                # at the catalog level — that's what the orchestrator output
                # has. The about page categorizes by whether the current
                # manifest target supports this kind of adapter (best effort).
                results["clean"].append(row)
        results["found"].sort(key=lambda r: -r["count"])

        total = len(findings)
        high_or_above = sum(
            1 for f in findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL)
        )

        return render_template(
            "about.html",
            by_category=by_category,
            category_order=CATEGORY_ORDER,
            results=results,
            total=total,
            high_or_above=high_or_above,
        )

    @app.route("/manifests")
    def manifests():
        md = Path(app.config["MANIFESTS_DIR"])
        items = []
        if md.is_dir():
            for p in sorted(md.glob("*.yml")):
                try:
                    m = Manifest.from_yaml(p)
                    d = classify(m)
                    items.append({
                        "name": m.name,
                        "owner": m.owner,
                        "tier": d.tier,
                        "data_sensitivity": m.data_sensitivity,
                        "decision_impact": m.decision_impact,
                        "path": str(p),
                    })
                except Exception as e:
                    items.append({"name": p.name, "error": str(e), "path": str(p)})
        return render_template("manifests.html", manifests=items)

    # ============================================================
    # Remediation routes
    # ============================================================

    @app.route("/remediations")
    def remediations_queue():
        store = ChangeStore()
        changes = store.all()
        state_filter = request.args.get("state")
        if state_filter:
            changes = [c for c in changes if c.state.value == state_filter]
        from collections import Counter
        by_state = Counter(c.state.value for c in store.all())
        return render_template(
            "remediations.html", changes=changes, by_state=by_state,
            state_filter=state_filter, all_states=[s.value for s in ChangeState],
        )

    @app.route("/change/<change_id>")
    def change_detail(change_id):
        store = ChangeStore()
        change = store.get(change_id)
        if not change:
            return "Change not found", 404
        events = EventStore().all()
        change_events = [e for e in events if e.get("change_id") == change_id]
        return render_template(
            "change_detail.html", change=change, events=change_events,
            allowed_next=_allowed_next(change.state),
        )

    @app.route("/finding/<finding_id>/propose", methods=["POST"])
    def propose_change(finding_id):
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        finding = next((f for f in store.all() if f.finding_id == finding_id), None)
        if not finding:
            return "Finding not found", 404
        eng = _engine_for(finding.app_name)
        if not eng:
            return f"No manifest for app {finding.app_name!r}", 400
        try:
            change = eng.propose(finding_id, actor=DEFAULT_ACTOR)
        except EngineError as e:
            return f"Cannot propose: {e}", 400
        return redirect(url_for("change_detail", change_id=change.change_id))

    @app.route("/change/<change_id>/<action>", methods=["POST"])
    def change_action(change_id, action):
        store = ChangeStore()
        change = store.get(change_id)
        if not change:
            return "Change not found", 404
        eng = _engine_for(change.app_name)
        if not eng:
            return f"No manifest for {change.app_name!r}", 400
        try:
            if action == "approve":
                eng.approve(change_id, actor=DEFAULT_ACTOR)
            elif action == "reject":
                eng.reject(change_id, actor=DEFAULT_ACTOR, reason=request.form.get("reason", ""))
            elif action == "apply":
                if request.form.get("confirm") != "yes":
                    return "Confirmation required", 400
                eng.apply(change_id, actor=DEFAULT_ACTOR)
            elif action == "rollback":
                eng.rollback(change_id, actor=DEFAULT_ACTOR)
            elif action == "rescan":
                eng.rescan(change_id, actor=DEFAULT_ACTOR)
            elif action == "deploy":
                eng.deploy(change_id, actor=DEFAULT_ACTOR)
            else:
                return f"Unknown action {action!r}", 400
        except EngineError as e:
            return f"Cannot {action}: {e}", 400
        return redirect(url_for("change_detail", change_id=change_id))

    @app.route("/history")
    def history():
        events = EventStore().all()
        events.reverse()  # newest first
        event_filter = request.args.get("event")
        app_filter = request.args.get("app")
        if event_filter:
            events = [e for e in events if e.get("event", "").startswith(event_filter)]
        if app_filter:
            events = [e for e in events if e.get("app") == app_filter or e.get("app_name") == app_filter]
        return render_template("history.html", events=events,
                               event_filter=event_filter, app_filter=app_filter)

    return app


def _allowed_next(state: ChangeState) -> list[str]:
    from ..remediate.state import ALLOWED
    return [s.value for s in ALLOWED.get(state, set())]


def _stats(findings) -> dict:
    by_sev: Counter = Counter()
    by_cat: Counter = Counter()
    by_adapter: Counter = Counter()
    by_app: Counter = Counter()
    high_or_above = 0
    for f in findings:
        by_sev[f.severity.value] += 1
        by_cat[f.category.value] += 1
        by_adapter[f.adapter] += 1
        by_app[f.app_name] += 1
        if f.severity in (Severity.HIGH, Severity.CRITICAL):
            high_or_above += 1
    return {
        "total": len(findings),
        "high_or_above": high_or_above,
        "by_severity": dict(by_sev),
        "by_category": dict(by_cat),
        "by_adapter": dict(by_adapter),
        "by_app": dict(by_app),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True)
    ap.add_argument("--manifests-dir",
                    default=str(Path(__file__).resolve().parent.parent / "manifests"))
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()
    app = create_app(args.findings, args.manifests_dir)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
