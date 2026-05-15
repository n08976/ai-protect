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

import csv
import io

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

from ..adapters.registry import REGISTRY
from ..core.findings import FindingStore, Severity
from ..core.tiering import classify
from ..core.manifest import Manifest
from ..remediate.engine import Engine, EngineError
from ..remediate.registry import remediators_for
from ..remediate.scans import (
    ScanJob, all_scans, get_scan, new_scan_id, update_status_from_pid, write_scan,
)
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

    @app.route("/favicon.ico")
    def favicon_ico():
        """Browsers reflexively request /favicon.ico; serve the same SVG.

        Modern browsers prefer the SVG href in <link rel='icon'>, but legacy
        UAs and Slack/Teams link previews still hit /favicon.ico directly.
        """
        return app.send_static_file("favicon.svg")

    @app.route("/")
    def index():
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None  # always re-read
        findings = _active_findings(store)
        # For the dashboard, mark each finding with whether a remediator exists.
        # Cheap: group by app once, look up the manifest, run can_fix per finding.
        engines: dict[str, Engine] = {}
        fixable: dict[str, bool] = {}
        for f in findings:
            eng = engines.get(f.app_name)
            if eng is None:
                eng = _engine_for(f.app_name)
                engines[f.app_name] = eng
            try:
                fixable[f.finding_id] = bool(eng and remediators_for(f, eng.manifest.raw))
            except Exception:
                fixable[f.finding_id] = False
        # Filters
        sev_filter = request.args.get("severity")
        cat_filter = request.args.get("category")
        app_filter = request.args.get("app")
        adapter_filter = request.args.get("adapter")
        fixable_filter = request.args.get("fixable")
        if sev_filter:
            findings = [f for f in findings if f.severity.value == sev_filter]
        if cat_filter:
            findings = [f for f in findings if f.category.value == cat_filter]
        if app_filter:
            findings = [f for f in findings if f.app_name == app_filter]
        if adapter_filter:
            findings = [f for f in findings if f.adapter == adapter_filter]
        if fixable_filter:
            findings = [f for f in findings if fixable.get(f.finding_id)]
        findings.sort(key=lambda f: (-f.severity_score, f.detected_at), reverse=False)
        findings.sort(key=lambda f: -f.severity_score)
        all_findings = _active_findings(store)
        return render_template(
            "index.html",
            findings=findings,
            fixable=fixable,
            fixable_count=sum(1 for ok in fixable.values() if ok),
            stats=_stats(all_findings),
            filter_severity=sev_filter,
            filter_category=cat_filter,
            filter_app=app_filter,
            filter_adapter=adapter_filter,
            filter_fixable=bool(fixable_filter),
            apps=sorted({f.app_name for f in all_findings}),
            categories=sorted({f.category.value for f in all_findings}),
            adapters=sorted({f.adapter for f in all_findings}),
            severities=["critical", "high", "medium", "low", "info"],
            catalog=CATALOG,
        )

    @app.route("/finding/<finding_id>")
    def finding_detail(finding_id):
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        for f in store.all():
            if f.finding_id == finding_id:
                # Look up applicable remediators given any matching manifest.
                remediators = []
                eng = _engine_for(f.app_name)
                if eng is not None:
                    remediators = [r.name for r in remediators_for(f, eng.manifest.raw)]
                # Existing changes for this finding
                changes = ChangeStore().for_finding(finding_id)
                return render_template(
                    "finding.html", finding=f,
                    remediators=remediators, existing_changes=changes,
                )
        return "Not found", 404

    @app.route("/api/findings")
    def api_findings():
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        # Active dashboard view: deduped by fingerprint + resolved filtered.
        # Pass ?include_resolved=1 to get the full append-only history instead.
        if request.args.get("include_resolved"):
            return jsonify([f.to_dict() for f in store.all()])
        return jsonify([f.to_dict() for f in _active_findings(store)])

    @app.route("/findings.pdf")
    def findings_pdf():
        """Filter-aware PDF report. Same query-param contract as /findings.csv."""
        from .pdf_report import generate_pdf
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        findings = _active_findings(store)
        sev_filter = request.args.get("severity")
        cat_filter = request.args.get("category")
        app_filter = request.args.get("app")
        adapter_filter = request.args.get("adapter")
        fixable_filter = request.args.get("fixable")
        if sev_filter:
            findings = [f for f in findings if f.severity.value == sev_filter]
        if cat_filter:
            findings = [f for f in findings if f.category.value == cat_filter]
        if app_filter:
            findings = [f for f in findings if f.app_name == app_filter]
        if adapter_filter:
            findings = [f for f in findings if f.adapter == adapter_filter]
        if fixable_filter:
            engines: dict[str, Engine | None] = {}
            keep = []
            for f in findings:
                eng = engines.get(f.app_name)
                if f.app_name not in engines:
                    eng = _engine_for(f.app_name)
                    engines[f.app_name] = eng
                try:
                    if eng and remediators_for(f, eng.manifest.raw):
                        keep.append(f)
                except Exception:
                    pass
            findings = keep

        filters = {
            "severity": sev_filter,
            "category": cat_filter,
            "app": app_filter,
            "adapter": adapter_filter,
            "fixable": "yes" if fixable_filter else None,
        }
        any_filter = any(filters.values())
        title = "ai-protect findings report"
        if any_filter:
            title += " (filtered)"
        pdf_bytes = generate_pdf(findings, filters=filters, title=title)

        ts = __import__("time").strftime("%Y%m%d-%H%M%S")
        suffix = []
        if app_filter: suffix.append(app_filter)
        if sev_filter: suffix.append(sev_filter)
        if adapter_filter: suffix.append(adapter_filter)
        if cat_filter: suffix.append(cat_filter)
        if fixable_filter: suffix.append("fixable")
        slug = ("-" + "-".join(suffix)) if suffix else ""
        filename = f"findings{slug}-{ts}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.route("/findings.csv")
    def findings_csv():
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        findings = _active_findings(store)
        # Honor the same filters the index page uses so the download matches
        # what the operator is currently looking at.
        sev_filter = request.args.get("severity")
        cat_filter = request.args.get("category")
        app_filter = request.args.get("app")
        adapter_filter = request.args.get("adapter")
        fixable_filter = request.args.get("fixable")
        if sev_filter:
            findings = [f for f in findings if f.severity.value == sev_filter]
        if cat_filter:
            findings = [f for f in findings if f.category.value == cat_filter]
        if app_filter:
            findings = [f for f in findings if f.app_name == app_filter]
        if adapter_filter:
            findings = [f for f in findings if f.adapter == adapter_filter]
        if fixable_filter:
            # Same remediator check the dashboard uses.
            engines: dict[str, Engine | None] = {}
            keep = []
            for f in findings:
                eng = engines.get(f.app_name)
                if f.app_name not in engines:
                    eng = _engine_for(f.app_name)
                    engines[f.app_name] = eng
                try:
                    if eng and remediators_for(f, eng.manifest.raw):
                        keep.append(f)
                except Exception:
                    pass
            findings = keep
        findings.sort(key=lambda f: -f.severity_score)

        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow([
            "finding_id", "detected_at", "severity", "app_name", "tier",
            "adapter", "stage", "category", "title", "description",
            "file", "line", "url",
            "compliance", "remediation", "references",
        ])
        for f in findings:
            ev = f.evidence or {}
            af = f.affected or {}
            file_ = ev.get("file") or af.get("file") or ""
            line = ev.get("line") or ev.get("start_line") or ""
            url = ev.get("url") or af.get("url") or af.get("target") or af.get("endpoint") or ""
            w.writerow([
                f.finding_id,
                f.detected_at,
                f.severity.value,
                f.app_name,
                f.tier,
                f.adapter,
                f.stage,
                f.category.value,
                f.title,
                (f.description or "")[:1000],
                file_,
                line,
                url,
                "; ".join(f.compliance or []),
                (f.remediation or "")[:500],
                "; ".join(f.references or []),
            ])
        ts = __import__("time").strftime("%Y%m%d-%H%M%S")
        suffix = []
        if app_filter: suffix.append(app_filter)
        if sev_filter: suffix.append(sev_filter)
        if adapter_filter: suffix.append(adapter_filter)
        if cat_filter: suffix.append(cat_filter)
        if fixable_filter: suffix.append("fixable")
        slug = ("-" + "-".join(suffix)) if suffix else ""
        filename = f"findings{slug}-{ts}.csv"
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.route("/api/stats")
    def api_stats():
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        return jsonify(_stats(_active_findings(store)))

    @app.route("/about")
    def about():
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        findings = _active_findings(store)
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

    @app.route("/findings/bulk-fix", methods=["POST"])
    def bulk_fix():
        """Run propose → approve → apply for each selected finding.

        Accepts JSON {finding_ids: [...]} or form-encoded finding_ids[].
        Returns JSON {results: [{finding_id, title, app_name, status, change_id,
                                 log, error}, ...]} suitable for inline rendering.
        """
        if request.is_json:
            ids = (request.get_json() or {}).get("finding_ids") or []
        else:
            ids = request.form.getlist("finding_ids") or request.form.getlist("finding_ids[]")
        if not ids:
            return jsonify({"results": [], "error": "no finding_ids supplied"}), 400

        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        all_findings = {f.finding_id: f for f in store.all()}

        results = []
        for fid in ids:
            log_lines: list[str] = []
            outcome = {
                "finding_id": fid,
                "title": "",
                "app_name": "",
                "status": "failed",
                "change_id": None,
                "log": "",
                "error": None,
            }
            f = all_findings.get(fid)
            if not f:
                outcome["error"] = "finding not found in current store"
                outcome["log"] = f"[ERROR] finding_id={fid} not found in {app.config['FINDINGS_PATH']}\n"
                results.append(outcome)
                continue
            outcome["title"] = f.title
            outcome["app_name"] = f.app_name

            eng = _engine_for(f.app_name)
            if not eng:
                outcome["status"] = "no-manifest"
                outcome["error"] = f"no manifest registered for app {f.app_name!r}"
                outcome["log"] = f"[SKIP] no manifest for app={f.app_name!r}; cannot construct Engine\n"
                results.append(outcome)
                continue

            log_lines.append(f"[{f.app_name}] finding={fid[:8]}…  '{f.title[:80]}'")
            log_lines.append(f"  category={f.category.value}  severity={f.severity.value}  adapter={f.adapter}")

            # propose
            try:
                change = eng.propose(fid, actor=DEFAULT_ACTOR)
                outcome["change_id"] = change.change_id
                log_lines.append(f"+ propose            change_id={change.change_id[:8]}… strategy={change.strategy} confidence={change.confidence}")
                log_lines.append(f"  summary: {(change.summary or '').strip()[:200]}")
                if change.test_status:
                    log_lines.append(f"  test_status={change.test_status} ({len(change.tests)} test(s) authored)")
            except EngineError as e:
                outcome["status"] = "no-remediator"
                outcome["error"] = str(e)
                log_lines.append(f"- propose            FAILED: {e}")
                outcome["log"] = "\n".join(log_lines) + "\n"
                results.append(outcome)
                continue
            except Exception as e:
                outcome["error"] = f"propose raised {type(e).__name__}: {e}"
                log_lines.append(f"- propose            CRASHED: {type(e).__name__}: {e}")
                outcome["log"] = "\n".join(log_lines) + "\n"
                results.append(outcome)
                continue

            # approve
            try:
                eng.approve(change.change_id, actor=DEFAULT_ACTOR)
                log_lines.append(f"+ approve            actor={DEFAULT_ACTOR}")
            except EngineError as e:
                outcome["status"] = "approve-failed"
                outcome["error"] = str(e)
                log_lines.append(f"- approve            FAILED: {e}")
                outcome["log"] = "\n".join(log_lines) + "\n"
                results.append(outcome)
                continue

            # apply
            try:
                applied = eng.apply(change.change_id, actor=DEFAULT_ACTOR)
                files_touched = [fe.path for fe in (applied.files or [])]
                log_lines.append(f"+ apply              files={len(files_touched)}")
                for p in files_touched[:8]:
                    log_lines.append(f"    wrote {p}")
                if len(files_touched) > 8:
                    log_lines.append(f"    … and {len(files_touched)-8} more")
                if applied.tests:
                    passed = sum(1 for t in applied.tests if t.post_apply_passed)
                    log_lines.append(
                        f"  post-apply tests: {passed}/{len(applied.tests)} passed  (test_status={applied.test_status})"
                    )
                outcome["status"] = "applied"
                if applied.test_status == "failed":
                    outcome["status"] = "applied-tests-failed"
            except EngineError as e:
                outcome["status"] = "apply-failed"
                outcome["error"] = str(e)
                log_lines.append(f"- apply              FAILED: {e}")
            except Exception as e:
                outcome["status"] = "apply-failed"
                outcome["error"] = f"apply raised {type(e).__name__}: {e}"
                log_lines.append(f"- apply              CRASHED: {type(e).__name__}: {e}")

            outcome["log"] = "\n".join(log_lines) + "\n"
            results.append(outcome)

        # Aggregate counts for the UI banner
        from collections import Counter as _C
        summary = dict(_C(r["status"] for r in results))
        return jsonify({"results": results, "summary": summary, "count": len(results)})

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

    # ============================================================
    # Scan launcher + status
    # ============================================================

    @app.route("/scan")
    def scan_launcher():
        from ..adapters.registry import REGISTRY
        md = Path(app.config["MANIFESTS_DIR"])
        manifests = []
        if md.is_dir():
            for p in sorted(md.glob("*.yml")):
                try:
                    m = Manifest.from_yaml(p)
                    manifests.append({"path": str(p), "name": m.name})
                except Exception:
                    continue
        scans = all_scans()
        for s in scans:
            update_status_from_pid(s)
        return render_template(
            "scan.html",
            manifests=manifests,
            stages=["intake", "design", "build", "preprod", "production"],
            adapters=sorted(REGISTRY.keys()),
            scans=scans[:30],
        )

    @app.route("/scan/start", methods=["POST"])
    def scan_start():
        import subprocess as sp
        manifest_path = request.form.get("manifest")
        stage = request.form.get("stage", "build")
        adapter = request.form.get("adapter") or None
        if adapter in ("", "all"):
            adapter = None
        try:
            m = Manifest.from_yaml(manifest_path)
        except Exception as e:
            return f"Cannot read manifest: {e}", 400
        scan_id = new_scan_id()
        job = ScanJob(
            scan_id=scan_id,
            manifest_path=manifest_path,
            app_name=m.name,
            stage=stage,
            adapter=adapter,
            status="pending",
        )
        write_scan(job)
        from ..remediate.scans import SCAN_LOG_DIR
        SCAN_LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_path = SCAN_LOG_DIR / f"{scan_id}.log"
        # Spawn the runner detached.
        cmd = [
            "python3", "-m", "pipeline.remediate.scan_runner",
            scan_id, manifest_path, stage, adapter or "-",
            app.config["FINDINGS_PATH"],
        ]
        env = os.environ.copy()
        env["PATH"] = "/home/user/bin:/home/user/.local/bin:" + env.get("PATH", "")
        proc = sp.Popen(
            cmd, env=env, stdout=open(log_path, "w"), stderr=sp.STDOUT,
            cwd=str(Path(__file__).resolve().parent.parent.parent),
            start_new_session=True,
        )
        job.pid = proc.pid
        job.log_path = str(log_path)
        job.status = "running"
        write_scan(job)
        return redirect(url_for("scan_status", scan_id=scan_id))

    @app.route("/scan/<scan_id>")
    def scan_status(scan_id):
        job = get_scan(scan_id)
        if not job:
            return "Scan not found", 404
        update_status_from_pid(job)
        log_tail = ""
        if job.log_path and Path(job.log_path).exists():
            try:
                log_tail = Path(job.log_path).read_text()[-4000:]
            except Exception:
                log_tail = ""
        return render_template("scan_status.html", job=job, log_tail=log_tail)

    @app.route("/scan/<scan_id>/stop", methods=["POST"])
    def scan_stop(scan_id):
        """Kill a running scan process. SIGTERM, brief grace window, then SIGKILL.

        Works on the whole process group (scans are spawned with
        start_new_session=True) so subprocesses the adapters spawned don't
        outlive their parent.
        """
        import signal as _signal
        import time as _time
        job = get_scan(scan_id)
        if not job:
            return jsonify({"error": "not found"}), 404
        update_status_from_pid(job)
        if job.status not in ("running", "pending"):
            return jsonify({
                "error": f"scan is not running (status={job.status})",
                "status": job.status,
            }), 400
        if not job.pid:
            return jsonify({"error": "no pid recorded"}), 400

        killed_via = None
        try:
            pgid = os.getpgid(job.pid)
            os.killpg(pgid, _signal.SIGTERM)
            killed_via = "SIGTERM"
        except (ProcessLookupError, PermissionError):
            try:
                os.kill(job.pid, _signal.SIGTERM)
                killed_via = "SIGTERM (single)"
            except (ProcessLookupError, PermissionError):
                pass

        # Grace window — up to 2 seconds for graceful shutdown.
        for _ in range(10):
            try:
                os.kill(job.pid, 0)
                _time.sleep(0.2)
            except OSError:
                break
        else:
            # Still alive — SIGKILL the group.
            try:
                os.killpg(os.getpgid(job.pid), _signal.SIGKILL)
                killed_via = (killed_via or "") + " → SIGKILL"
            except (ProcessLookupError, PermissionError):
                pass

        job.status = "stopped"
        job.ended_at = _time.time()
        job.exit_code = -int(_signal.SIGTERM)  # negative signal number = killed by signal
        write_scan(job)

        return jsonify({
            "scan_id": job.scan_id,
            "status": job.status,
            "ended_at": job.ended_at,
            "exit_code": job.exit_code,
            "killed_via": killed_via or "no signal sent (process already gone)",
        })

    @app.route("/api/scan/<scan_id>")
    def api_scan(scan_id):
        """JSON poll endpoint for the scan status page — feeds AJAX updates
        so the page doesn't have to reload itself every 3 seconds."""
        job = get_scan(scan_id)
        if not job:
            return jsonify({"error": "not found"}), 404
        update_status_from_pid(job)
        log_tail = ""
        if job.log_path and Path(job.log_path).exists():
            try:
                log_tail = Path(job.log_path).read_text()[-4000:]
            except Exception:
                log_tail = ""
        return jsonify({
            "scan_id": job.scan_id,
            "status": job.status,
            "pid": job.pid,
            "exit_code": job.exit_code,
            "findings_before": job.findings_before,
            "findings_after": job.findings_after,
            "ended_at": job.ended_at,
            "log_tail": log_tail,
        })

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


# Change states that mean "the underlying finding is resolved" — these
# fingerprints should NOT count toward the dashboard total.
# APPLIED   = files written + post-apply tests passed (user's expectation: fixed)
# VALIDATED = rescan confirmed the finding is gone
# DEPLOYED  = applied + validated + deployed downstream
# Any later REVERTED change re-opens the finding.
_RESOLVED_STATES = {"applied", "validated", "deployed"}


def _resolved_fingerprints() -> set[str]:
    """Set of finding fingerprints currently resolved by an applied change.

    Honors revert: if a fingerprint has a more-recent REVERTED change than its
    APPLIED/VALIDATED/DEPLOYED change, the finding is re-opened.
    """
    from ..remediate.state import ChangeStore
    latest_by_fp: dict[str, str] = {}  # fingerprint -> most recent state
    for c in sorted(ChangeStore().all(), key=lambda c: c.last_state_at):
        if not c.finding_fingerprint:
            continue
        latest_by_fp[c.finding_fingerprint] = c.state.value
    return {fp for fp, st in latest_by_fp.items() if st in _RESOLVED_STATES}


def _active_findings(store):
    """Dashboard view of findings: deduped by fingerprint (latest per
    fingerprint by detected_at) and stripped of fingerprints resolved by a
    successful Change. This is what the dashboard, CSV, and JSON API should
    show — the append-only store has full history, but the dashboard wants
    current state."""
    resolved = _resolved_fingerprints()
    latest: dict = {}
    for f in sorted(store.all(), key=lambda x: x.detected_at):
        latest[f.fingerprint] = f
    return [f for f in latest.values() if f.fingerprint not in resolved]


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
