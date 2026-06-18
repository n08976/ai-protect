"""Flask web UI — live findings dashboard.

Reads the FindingStore on every request, so adapters can be running in another
process and findings will surface as they're written.

Run:
    python -m pipeline.ui.server --findings /tmp/findings.jsonl --port 8000
"""
from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

import csv
import io

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

from ..adapters.registry import REGISTRY
from ..core.findings import FindingStore, Severity
from ..core.tiering import classify
from ..core.manifest import Manifest
from ..core.policy import STAGES

# Scan ids are interpolated into log file paths and subprocess argv. Constrain
# to a safe charset so a forged id can't traverse paths or inject git/CLI args.
_SAFE_SCAN_ID = re.compile(r"^[A-Za-z0-9._-]+$")
from ..remediate.engine import Engine, EngineError
from ..remediate.registry import remediators_for
from ..remediate.scans import (
    ScanJob, all_scans, emit_event, get_scan, new_scan_id, update_status_from_pid, write_scan,
)
from ..remediate.state import ChangeState, ChangeStore, EventStore
from ..intel.feeds import (
    Feed, FeedStore, FeedFetchStore, IntelStore, VALID_FORMATS, new_feed_id,
)
from ..intel.fetcher import detect_feed_format, fetch_feed, start_poller, validate_feed
from ..intel.status import overall_status
from ..core import settings as user_settings
from .catalog import CATALOG, CATEGORY_ORDER

DEFAULT_ACTOR = "operator@example.com"


def _safe_log_tail(log_path: str, n: int = 4000) -> str:
    """Read the tail of a scan log, refusing any path outside SCAN_LOG_DIR.

    Defense-in-depth on top of the scan_id charset guard: even a forged
    job.log_path can't read arbitrary files.
    """
    from ..remediate.scans import SCAN_LOG_DIR
    try:
        p = Path(log_path).resolve()
        p.relative_to(Path(SCAN_LOG_DIR).resolve())
    except (ValueError, OSError):
        return ""
    try:
        return p.read_text()[-n:]
    except OSError:
        return ""


def create_app(findings_path: str, manifests_dir: str) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.config["FINDINGS_PATH"] = findings_path
    app.config["MANIFESTS_DIR"] = manifests_dir

    @app.template_filter("httpsafe")
    def _httpsafe(u):
        """Return a URL only if it's http(s); else '#'. Blocks javascript:/data:
        URIs in hrefs sourced from feeds/findings (Jinja already HTML-escapes)."""
        u = u or ""
        return u if isinstance(u, str) and (u.startswith("https://") or u.startswith("http://")) else "#"

    # Jinja filter: format any epoch timestamp in the operator's configured TZ.
    # Re-reads config.json each call so a settings change takes effect without
    # restarting the UI.
    app.jinja_env.filters["localtime"] = user_settings.format_epoch

    # Intel feed poller: idempotent — safe to call from create_app() repeatedly.
    start_poller(FeedStore(), FeedFetchStore(), IntelStore())

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
            except Exception:  # nosec B112 — skip a manifest that fails to load; engine lookup must not 500
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
        include_unverified = _include_unverified(request)
        findings = _dashboard_findings(store, include_unverified=include_unverified)
        # Mark each finding with whether ACTUALLY-FIXABLE — not just "has a
        # remediator class". If propose() returns None (e.g. existing pin
        # already satisfies the fix, or no published fix version), the Fix
        # button must not appear; otherwise the operator clicks it and
        # gets "no fix applicable" errors from the Engine.
        engines: dict[str, Engine] = {}
        fixable: dict[str, bool] = {}
        for f in findings:
            eng = engines.get(f.app_name)
            if eng is None:
                eng = _engine_for(f.app_name)
                engines[f.app_name] = eng
            ok = False
            if eng:
                try:
                    for r in remediators_for(f, eng.manifest.raw):
                        try:
                            if r.propose(f, eng.manifest.raw) is not None:
                                ok = True
                                break
                        except Exception:  # nosec B110 — best-effort fixability probe; a broken remediator must not abort
                            pass
                except Exception:  # nosec B110 — best-effort fixability probe; a broken remediator must not abort
                    pass
            fixable[f.finding_id] = ok
        # Filters
        sev_filter = request.args.get("severity")
        cat_filter = request.args.get("category")
        app_filter = request.args.get("app")
        adapter_filter = request.args.get("adapter")
        fixable_filter = request.args.get("fixable")

        all_findings = _dashboard_findings(store, include_unverified=include_unverified)

        # Pill counts shouldn't change based on the filter the pill itself
        # represents — otherwise clicking "critical" under an app filter
        # zeroes every other severity pill. The right semantics is "if I
        # clicked this pill, how many findings would I see?".
        #
        # So we compute four intermediate views:
        #   base_no_sev_fix  — everything filtered EXCEPT severity & fixable
        #                       → severity pill counts come from this set,
        #                         grouped by severity
        #                       → "all" pill count is len(this set)
        #   base_no_fix      — base_no_sev_fix + severity filter applied
        #                       → fixable pill count = items in this set
        #                         that have a remediator
        #   findings         — base_no_fix + fixable filter applied
        #                       → table rows + hero numbers
        def _apply(items, **drops):
            out = items
            if sev_filter and not drops.get("severity"):
                out = [f for f in out if f.severity.value == sev_filter]
            if cat_filter and not drops.get("category"):
                out = [f for f in out if f.category.value == cat_filter]
            if app_filter and not drops.get("app"):
                out = [f for f in out if f.app_name == app_filter]
            if adapter_filter and not drops.get("adapter"):
                out = [f for f in out if f.adapter == adapter_filter]
            if fixable_filter and not drops.get("fixable"):
                out = [f for f in out if fixable.get(f.finding_id)]
            return out

        base_no_sev_fix = _apply(all_findings, severity=True, fixable=True)
        base_no_fix     = _apply(all_findings, fixable=True)
        findings        = _apply(all_findings)

        findings.sort(key=lambda f: (-f.severity_score, f.detected_at), reverse=False)
        findings.sort(key=lambda f: -f.severity_score)

        # Hero stats reflect the table the operator is looking at.
        any_filter = bool(sev_filter or cat_filter or app_filter or adapter_filter or fixable_filter)  # nosemgrep — FP: bool() of request strings, no float/NaN possible
        stats_for_view = _stats(findings)

        # Severity-pill histogram: counts of findings if the user toggled to
        # that severity under the OTHER active filters. Built from
        # base_no_sev_fix so each pill shows "what would I see if I clicked
        # me", independent of the current severity choice.
        from collections import Counter as _C
        pill_severity_counts = _C(f.severity.value for f in base_no_sev_fix)
        pill_all_count = len(base_no_sev_fix)

        # has-fix pill count: items in base_no_fix that have a remediator.
        pill_fixable_count = sum(1 for f in base_no_fix if fixable.get(f.finding_id))

        # Count of hidden unverified intel findings so the toggle pill can
        # show "Show unverified intel (N)". Cheap — we already have all
        # active findings via _active_findings; just count the ones the
        # dashboard filter removed.
        hidden_unverified_count = 0
        if not include_unverified:
            hidden_unverified_count = sum(
                1 for f in _active_findings(store)
                if (f.evidence or {}).get("intel_match_unverified")
            )
        return render_template(
            "index.html",
            findings=findings,
            fixable=fixable,
            fixable_count=pill_fixable_count,
            pill_severity_counts=dict(pill_severity_counts),
            pill_all_count=pill_all_count,
            stats=stats_for_view,
            stats_scope="filtered" if any_filter else "all apps",
            global_total=len(all_findings),
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
            system_status=overall_status(app.config["FINDINGS_PATH"]),
            include_unverified=include_unverified,
            hidden_unverified_count=hidden_unverified_count,
        )

    @app.route("/finding/<finding_id>")
    def finding_detail(finding_id):
        import re as _re
        _cve_re = _re.compile(r"CVE-\d{4}-\d{4,7}", _re.IGNORECASE)
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
                # Auto-resolve provenance: surface the latest auto_resolve_absent
                # Change (if any) so the operator can see when and which scan
                # marked this finding resolved automatically.
                auto_resolve_change = None
                # Latest Change by (app, fingerprint) — broader than for_finding
                # because the auto-resolver writes Changes keyed by fingerprint,
                # and the same fingerprint may have multiple finding_id rows in
                # the append-only store.
                for c in sorted(ChangeStore().all(), key=lambda c: -c.last_state_at):
                    if c.finding_fingerprint == f.fingerprint and c.strategy == "auto_resolve_absent":
                        auto_resolve_change = c
                        break
                # Cross-reference any CVEs mentioned in this finding against the
                # intel store. Intel feeds AUGMENT scanner findings — they do
                # not replace them — so we surface external context next to the
                # scanner's own data, never in place of it.
                blob = " ".join([
                    f.title or "", f.description or "",
                    " ".join(f.references or []),
                    json.dumps(f.evidence) if f.evidence else "",
                ])
                cve_ids = sorted({m.group(0).upper() for m in _cve_re.finditer(blob)})
                related_intel = []
                if cve_ids:
                    intel_store = IntelStore()
                    feeds_by_id = {x.feed_id: x for x in FeedStore().all(include_deleted=True)}
                    for item in intel_store.all():
                        if item.cve_id and item.cve_id.upper() in cve_ids:
                            related_intel.append({
                                "item": item,
                                "feed_name": feeds_by_id.get(item.source_feed_id).name
                                             if feeds_by_id.get(item.source_feed_id) else item.source_feed_id,
                            })
                return render_template(
                    "finding.html", finding=f,
                    remediators=remediators, existing_changes=changes,
                    cve_ids=cve_ids, related_intel=related_intel,
                    auto_resolve_change=auto_resolve_change,
                )
        return "Not found", 404

    @app.route("/api/findings")
    def api_findings():
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        # Active dashboard view: deduped by fingerprint + resolved filtered.
        # ?include_resolved=1 → full append-only history (no dedup, no filter)
        # ?include_unverified=1 → include intel_match_unverified findings
        # (hidden by default to keep automated callers in sync with the UI)
        if request.args.get("include_resolved"):
            return jsonify([f.to_dict() for f in store.all()])
        out = _dashboard_findings(store, include_unverified=_include_unverified(request))
        return jsonify([f.to_dict() for f in out])

    @app.route("/findings.pdf")
    def findings_pdf():
        """Filter-aware PDF report. Same query-param contract as /findings.csv."""
        from .pdf_report import generate_pdf
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        findings = _dashboard_findings(store, include_unverified=_include_unverified(request))
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
                    pass  # nosec B110 — best-effort fixability probe; a broken remediator must not drop the finding
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
        findings = _dashboard_findings(store, include_unverified=_include_unverified(request))
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
                    pass  # nosec B110 — best-effort fixability probe; a broken remediator must not drop the finding
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
        return jsonify(_stats(_dashboard_findings(store, include_unverified=_include_unverified(request))))

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
                    # paths = source_paths or [source_path]; for display use scan_targets()
                    items.append({
                        "name": m.name,
                        "owner": m.owner,
                        "tier": d.tier,
                        "data_sensitivity": m.data_sensitivity,
                        "decision_impact": m.decision_impact,
                        "path": str(p),
                        "scan_targets": m.scan_targets(),
                        "exclude_count": len(m.source_excludes),
                    })
                except Exception as e:
                    items.append({"name": p.stem, "error": str(e), "path": str(p)})
        return render_template("manifests.html", manifests=items)

    # ============================================================
    # Manifest CRUD — UI editor
    # ============================================================

    def _form_to_manifest_data(form) -> dict:
        """Translate flat HTML form fields into the YAML schema dict."""
        def _split_lines(s: str) -> list[str]:
            return [ln.strip() for ln in (s or "").splitlines() if ln.strip()]

        # Models — repeated fields named models-N-name etc.
        models = []
        for i in range(20):
            name = (form.get(f"model-{i}-name") or "").strip()
            if not name:
                continue
            models.append({
                "name": name,
                "provider": (form.get(f"model-{i}-provider") or "").strip(),
                "model": (form.get(f"model-{i}-model") or "").strip(),
                "via_gateway": form.get(f"model-{i}-via_gateway") == "on",
                "baa_covered": form.get(f"model-{i}-baa_covered") == "on",
                "auth_env": (form.get(f"model-{i}-auth_env") or "").strip() or None,
            })

        # MCP servers — same pattern.
        mcps = []
        for i in range(20):
            mname = (form.get(f"mcp-{i}-name") or "").strip()
            if not mname:
                continue
            try:
                tier = int(form.get(f"mcp-{i}-tier") or 2)
            except (TypeError, ValueError):
                tier = 2
            mcps.append({
                "name": mname,
                "tier": tier,
                "data_scope": (form.get(f"mcp-{i}-data_scope") or "internal").strip(),
                # MCP actions are a single text input where the operator
                # types "action1, action2, action3" — split on both commas
                # AND newlines so either separator works. Previous behavior
                # (newline-only) stored ["action1, action2, action3"] as ONE
                # string, which then tripped mcp_scope's per-action checks.
                "actions": [
                    a.strip() for a in
                    (form.get(f"mcp-{i}-actions") or "").replace("\n", ",").split(",")
                    if a.strip()
                ],
                "side_effects": (form.get(f"mcp-{i}-side_effects") or "read_only").strip(),
                "third_party": form.get(f"mcp-{i}-third_party") == "on",
            })

        data = {
            "name": (form.get("name") or "").strip(),
            "owner": (form.get("owner") or "").strip(),
            "on_call": (form.get("on_call") or "").strip() or (form.get("owner") or "").strip(),
            "description": (form.get("description") or "").strip(),
            "data_sensitivity": form.get("data_sensitivity"),
            "decision_impact": form.get("decision_impact"),
            "integration_footprint": form.get("integration_footprint"),
            "user_population": form.get("user_population"),
            "app_aliases":  _split_lines(form.get("app_aliases") or ""),
            "models": models,
            "mcp_servers": mcps,
            "surfaces": {
                "has_user_chat":      form.get("surface_user_chat") == "on",
                "has_email_intake":   form.get("surface_email") == "on",
                "has_document_ingest": form.get("surface_doc") == "on",
                "has_webhook":        form.get("surface_webhook") == "on",
                "has_voice":          form.get("surface_voice") == "on",
            },
            "target": {
                "base_url": (form.get("target_base_url") or "").strip() or None,
                "api_url":  (form.get("target_api_url") or "").strip() or None,
                "test_user_token_env": (form.get("target_test_user_token_env") or "").strip() or None,
                "allow_mutation": form.get("target_allow_mutation") == "on",
                "network_allowed_zones": _split_lines(form.get("target_network_allowed_zones") or ""),
            },
            "expected_actions":     _split_lines(form.get("expected_actions") or ""),
            "expected_data_scopes": _split_lines(form.get("expected_data_scopes") or ""),
            "threat_model_path":    (form.get("threat_model_path") or "").strip() or None,
            "guardrails_path":      (form.get("guardrails_path") or "").strip() or None,
            "source_paths":         _split_lines(form.get("source_paths") or ""),
            "source_excludes":      _split_lines(form.get("source_excludes") or ""),
            "app_aliases":          _split_lines(form.get("app_aliases") or ""),
            "source_provider":      (form.get("source_provider") or "").strip(),
            "github_repo":          (form.get("github_repo") or "").strip(),
            "github_ref":           (form.get("github_ref") or "").strip(),
        }
        # github_clone_depth — only carry through when present and numeric
        depth_raw = (form.get("github_clone_depth") or "").strip()
        if depth_raw:
            try:
                data["github_clone_depth"] = int(depth_raw)
            except ValueError:
                pass
        # Legacy source_path support (UI rarely surfaces it, but we keep
        # the field if the operator deliberately filled it).
        legacy = (form.get("source_path") or "").strip()
        if legacy:
            data["source_path"] = legacy
        # Strip empties in surfaces and target so the YAML stays clean.
        data["surfaces"] = {k: v for k, v in data["surfaces"].items() if v}
        data["target"] = {k: v for k, v in data["target"].items() if v}
        if not data["surfaces"]:
            data.pop("surfaces")
        if not data["target"]:
            data.pop("target")
        # Drop empty source-provider fields so they don't bloat every YAML.
        for k in ("source_provider", "github_repo", "github_ref"):
            if not data.get(k):
                data.pop(k, None)
        if not data.get("app_aliases"):
            data.pop("app_aliases", None)
        return data

    @app.route("/manifests/new", methods=["GET", "POST"])
    def manifest_new():
        from . import manifest_io as mio
        if request.method == "GET":
            return render_template(
                "manifest_form.html",
                mode="new", form=_empty_manifest_form(), errors=[], warnings=[],
                options={
                    "data_sensitivity": mio.DATA_SENSITIVITY_OPTIONS,
                    "decision_impact": mio.DECISION_IMPACT_OPTIONS,
                    "integration_footprint": mio.INTEGRATION_OPTIONS,
                    "user_population": mio.USER_POPULATION_OPTIONS,
                    "side_effects": mio.SIDE_EFFECTS_OPTIONS,
                },
                browse_roots=mio.BROWSE_ROOTS,
                existing_names=mio.list_existing_names(),
            )
        # POST
        data = _form_to_manifest_data(request.form)
        # Name collision check
        if data.get("name") in mio.list_existing_names():
            return render_template(
                "manifest_form.html",
                mode="new", form=data,
                errors=[f"manifest name {data['name']!r} already exists — pick a different name or use Edit"],
                warnings=[],
                options=_form_options(), browse_roots=mio.BROWSE_ROOTS,
                existing_names=mio.list_existing_names(),
            ), 400
        errors = mio.validate_for_save(data)
        if errors:
            return render_template(
                "manifest_form.html",
                mode="new", form=data, errors=errors, warnings=[],
                options=_form_options(), browse_roots=mio.BROWSE_ROOTS,
                existing_names=mio.list_existing_names(),
            ), 400
        warnings = mio.validate_path_warnings(data)
        try:
            mio.save(data["name"], data, overwrite=False)
        except (ValueError, FileExistsError) as e:
            errors.append(str(e))
            return render_template(
                "manifest_form.html",
                mode="new", form=data, errors=errors, warnings=warnings,
                options=_form_options(), browse_roots=mio.BROWSE_ROOTS,
                existing_names=mio.list_existing_names(),
            ), 400
        return redirect(url_for("manifests"))

    @app.route("/manifests/<name>/edit", methods=["GET", "POST"])
    def manifest_edit(name):
        from . import manifest_io as mio
        if request.method == "GET":
            try:
                data = mio.load_raw(name)
            except (FileNotFoundError, ValueError) as e:
                return f"Cannot edit {name!r}: {e}", 404
            return render_template(
                "manifest_form.html",
                mode="edit", form=data, errors=[], warnings=[],
                options=_form_options(), browse_roots=mio.BROWSE_ROOTS,
                existing_names=mio.list_existing_names(),
                original_name=name,
            )
        data = _form_to_manifest_data(request.form)
        # Preserve YAML keys the form doesn't render (e.g. step_up_auth,
        # data_flow, contact_methods — fields shipped by the example
        # manifests but not surfaced by the UI). Without this, every save
        # via /edit silently drops them.
        try:
            existing = mio.load_raw(name)
            for k, v in existing.items():
                if k not in data and not k.startswith("_"):
                    data[k] = v
        except (FileNotFoundError, ValueError):
            pass   # new file or unreadable; nothing to preserve
        # Tell the validator we're editing this specific manifest so its
        # case-fold uniqueness check doesn't flag the manifest as colliding
        # with itself. Underscore-prefixed keys are stripped by save() before
        # YAML serialization, so this stays out of the on-disk file.
        data["_original_name"] = name
        errors = mio.validate_for_save(data)
        if errors:
            return render_template(
                "manifest_form.html",
                mode="edit", form=data, errors=errors, warnings=[],
                options=_form_options(), browse_roots=mio.BROWSE_ROOTS,
                existing_names=mio.list_existing_names(),
                original_name=name,
            ), 400
        warnings = mio.validate_path_warnings(data)
        # Renaming: if the form changed the name, delete the old file after
        # saving the new. mio.delete() uses the same load-by-yaml-name fallback
        # that load_raw does, so it still finds the backing file when the
        # filename diverges from the YAML 'name' field (every shipped example
        # manifest has this — e.g. example_clinical_assistant.yml carries
        # name: clinical-assistant-prototype). FileNotFoundError is suppressed
        # so a missing-source case doesn't roll back the new file we just
        # wrote.
        try:
            mio.save(data["name"], data, overwrite=True)
            if data["name"] != name:
                try:
                    mio.delete(name)
                except FileNotFoundError:
                    pass   # old file already gone, e.g. concurrent edit
        except (ValueError, FileNotFoundError) as e:
            errors.append(str(e))
            return render_template(
                "manifest_form.html",
                mode="edit", form=data, errors=errors, warnings=warnings,
                options=_form_options(), browse_roots=mio.BROWSE_ROOTS,
                existing_names=mio.list_existing_names(),
                original_name=name,
            ), 400
        return redirect(url_for("manifests"))

    @app.route("/manifests/<name>/delete", methods=["POST"])
    def manifest_delete(name):
        from . import manifest_io as mio
        try:
            mio.delete(name)
        except (FileNotFoundError, ValueError) as e:
            return f"Cannot delete {name!r}: {e}", 400
        return redirect(url_for("manifests"))

    @app.route("/api/browse")
    def api_browse():
        from . import manifest_io as mio
        p = request.args.get("path") or os.path.expanduser("~")
        return jsonify(mio.browse_listing(p))

    @app.route("/api/tier/preview")
    def api_tier_preview():
        """Live tier classification for the form's four scoring inputs."""
        data = {
            "name": "preview",
            "owner": "preview@example.com",
            "on_call": "preview@example.com",
            "description": "",
            "data_sensitivity": request.args.get("data_sensitivity", "public"),
            "decision_impact": request.args.get("decision_impact", "advisory"),
            "integration_footprint": request.args.get("integration_footprint", "read_only"),
            "user_population": request.args.get("user_population", "single_user"),
        }
        try:
            m = Manifest.from_dict(data)
            d = classify(m)
            return jsonify(d.to_dict())
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    def _form_options() -> dict:
        from . import manifest_io as mio
        return {
            "data_sensitivity": mio.DATA_SENSITIVITY_OPTIONS,
            "decision_impact": mio.DECISION_IMPACT_OPTIONS,
            "integration_footprint": mio.INTEGRATION_OPTIONS,
            "user_population": mio.USER_POPULATION_OPTIONS,
            "side_effects": mio.SIDE_EFFECTS_OPTIONS,
        }

    def _empty_manifest_form() -> dict:
        return {
            "name": "", "owner": "", "on_call": "", "description": "",
            "data_sensitivity": "confidential",
            "decision_impact": "advisory",
            "integration_footprint": "read_only",
            "user_population": "single_user",
            "models": [], "mcp_servers": [],
            "surfaces": {}, "target": {},
            "expected_actions": [], "expected_data_scopes": [],
            "source_paths": [], "source_excludes": [],
        }

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
                msg = str(e)
                # "no fix applicable" is the Engine's signal that the remediator
                # examined the finding and decided no useful change would help
                # (existing pin already satisfies the fix, no published fix
                # version, etc.). Treat as a benign skip, not an error — the
                # finding is effectively already resolved.
                if "no fix applicable" in msg or "no remediator handles" in msg:
                    outcome["status"] = "no-fix-needed"
                    outcome["error"] = None
                    log_lines.append(f"= skip               {msg}")
                else:
                    outcome["status"] = "no-remediator"
                    outcome["error"] = msg
                    log_lines.append(f"- propose            FAILED: {msg}")
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

    @app.route("/finding/<finding_id>/dismiss", methods=["POST"])
    def finding_dismiss(finding_id):
        """Operator-driven dismissal — synthesizes an applied Change with
        strategy=manual_dismiss. Reason required (recorded in the audit trail).
        Used for unverified intel matches, confirmed false positives, accepted
        risks the change-workflow shouldn't fix."""
        from ..remediate.dismissal import dismiss_finding
        reason = (request.form.get("reason") or "").strip()
        if not reason:
            return "reason is required", 400
        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        finding = next((f for f in store.all() if f.finding_id == finding_id), None)
        if not finding:
            return "Finding not found", 404
        try:
            written = dismiss_finding(finding, reason=reason, actor=DEFAULT_ACTOR)
        except ValueError as e:
            return f"Cannot dismiss: {e}", 400
        # JSON for API callers; redirect for form submits.
        if (request.headers.get("Accept") or "").startswith("application/json") \
                or request.form.get("response") == "json":
            return jsonify({"dismissed": bool(written),
                            "finding_id": finding_id,
                            "fingerprint": finding.fingerprint,
                            "already_resolved": not written})
        return redirect(url_for("finding_detail", finding_id=finding_id))

    @app.route("/findings/bulk-dismiss", methods=["POST"])
    def findings_bulk_dismiss():
        """Bulk dismissal. Accepts either:
          - finding_ids: comma-separated list of finding ids
          - filter spec: adapter / app / severity / category / unverified=on
                         (matches the active-findings view)
        Reason required. Returns JSON {dismissed, candidates, skipped} for
        scripted callers; redirects back to /index for form submits.

        Designed for the "385 unverified intel matches" use case: filter to
        adapter=intel_match&unverified=on and dismiss the lot with one
        well-documented reason."""
        from ..remediate.dismissal import dismiss_finding
        reason = (request.form.get("reason") or "").strip()
        if not reason:
            return jsonify({"error": "reason is required"}), 400

        store = FindingStore(app.config["FINDINGS_PATH"])
        store._cache = None
        candidates = _active_findings(store)

        # Either explicit id list OR filter spec — not both. Explicit list wins
        # when both are supplied so a scripted caller's intent is unambiguous.
        explicit = [t.strip() for t in (request.form.get("finding_ids") or "").split(",") if t.strip()]
        if explicit:
            wanted = set(explicit)
            candidates = [f for f in candidates if f.finding_id in wanted]
        else:
            if (a := (request.form.get("adapter") or "").strip()):
                candidates = [f for f in candidates if f.adapter == a]
            if (a := (request.form.get("app") or "").strip()):
                candidates = [f for f in candidates if f.app_name == a]
            if (s := (request.form.get("severity") or "").strip()):
                candidates = [f for f in candidates if f.severity.value == s]
            if (c := (request.form.get("category") or "").strip()):
                candidates = [f for f in candidates if f.category.value == c]
            if request.form.get("unverified") == "on":
                candidates = [f for f in candidates if (f.evidence or {}).get("intel_match_unverified")]

        dismissed = 0
        skipped = 0
        for f in candidates:
            try:
                if dismiss_finding(f, reason=reason, actor=DEFAULT_ACTOR):
                    dismissed += 1
                else:
                    skipped += 1   # already resolved
            except ValueError:
                skipped += 1
            except Exception:
                skipped += 1

        result = {"dismissed": dismissed, "candidates": len(candidates), "skipped": skipped}
        if (request.headers.get("Accept") or "").startswith("application/json") \
                or request.form.get("response") == "json":
            return jsonify(result)
        # Preserve the operator's filter on redirect so they see the result
        # in the same view they triggered from.
        passthrough = {k: v for k, v in (
            ("severity", request.form.get("severity")),
            ("category", request.form.get("category")),
            ("app", request.form.get("app")),
            ("adapter", request.form.get("adapter")),
        ) if v}
        return redirect(url_for("index", **passthrough))

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

    # NOTE: order matters. Decorators apply innermost-first, so "/scan" is the
    # FIRST-registered rule — which is what url_for('scan_launcher') (no args)
    # builds. Keep "/scan" innermost so every bare scan-launcher link defaults
    # to SAST, not the live/DAST route.
    @app.route("/scan/live")
    @app.route("/scan/source")
    @app.route("/scan")
    def scan_launcher():
        from ..adapters.registry import REGISTRY
        from ..core import scan_modes as sm
        from ..core.adhoc import cleanup_stale_adhoc_manifests

        # Defense-in-depth janitor: prune any ad-hoc temp manifests left
        # behind by crashed runners (older than 7 days). The runner's own
        # try/finally handles the happy path.
        cleanup_stale_adhoc_manifests()

        # Mode: ?mode= takes precedence; /scan/source and /scan/live aliases
        # set their own default. Falls back to SAST when nothing's specified.
        rule = (request.url_rule.rule if request.url_rule else "/scan")
        if rule.endswith("/source"):
            default_mode = sm.MODE_SAST
        elif rule.endswith("/live"):
            default_mode = sm.MODE_DAST
        else:
            default_mode = sm.MODE_SAST
        mode = (request.args.get("mode") or default_mode).lower()
        if mode not in sm.SCAN_MODES:
            mode = sm.MODE_SAST

        md = Path(app.config["MANIFESTS_DIR"])
        manifests = []
        if md.is_dir():
            for p in sorted(md.glob("*.yml")):
                try:
                    m = Manifest.from_yaml(p)
                    # Note: target.base_url surfaced so the UI can preview
                    # "Known app" DAST scans without re-loading the manifest.
                    manifests.append({
                        "path": str(p), "name": m.name,
                        "target_base_url": (m.target.base_url or "") if m.target else "",
                        "allow_mutation": bool(m.target and m.target.allow_mutation),
                    })
                except Exception:
                    continue  # nosec B112 — skip manifests that fail to load; listing must not 500 on one bad file

        adapter_names = list(REGISTRY.keys())
        sast_adapters = sm.adapters_for_mode(sm.MODE_SAST, adapter_names)
        dast_adapters = sm.adapters_for_mode(sm.MODE_DAST, adapter_names)
        pre_flight    = sm.pre_flight_adapters(adapter_names)

        # DAST "safe defaults" — opinionated minimal set that won't burn down
        # a target. Heavy / active / adversary adapters require the explicit
        # opt-in toggle.
        DAST_SAFE_ADAPTERS = ["zap", "nuclei", "mcp_scope"]
        DAST_HEAVY_ADAPTERS = ["zap", "burp", "sqlmap", "metasploit",
                               "atomic", "caldera"]   # opt-in only

        scans = all_scans()
        for s in scans:
            update_status_from_pid(s)
        return render_template(
            "scan.html",
            mode=mode,
            manifests=manifests,
            stages=["intake", "design", "build", "preprod", "production"],
            sast_adapters=sast_adapters,
            dast_adapters=dast_adapters,
            dast_safe_default_adapters=[a for a in DAST_SAFE_ADAPTERS if a in dast_adapters],
            dast_heavy_adapters=[a for a in DAST_HEAVY_ADAPTERS if a in dast_adapters],
            pre_flight_adapters=pre_flight,
            mode_labels=sm.MODE_LABELS,
            mode_descriptions=sm.MODE_DESCRIPTIONS,
            scans=scans[:30],
        )

    @app.route("/scan/start", methods=["POST"])
    def scan_start():
        import subprocess as sp  # nosec B404 — fixed argv, no shell; args validated above
        from ..core import scan_modes as sm
        from ..core import adhoc as adhoc_mod
        from ..core.url_safety import check_url

        # Mode branching: SAST keeps the original (manifest-path-based) flow.
        # DAST adds two sub-modes: known-app (= manifest target) and ad-hoc URL.
        mode = (request.form.get("mode") or sm.MODE_SAST).lower()
        if mode not in sm.SCAN_MODES:
            return f"unknown mode {mode!r} — must be one of {sm.SCAN_MODES}", 400

        stage = request.form.get("stage", "build" if mode == sm.MODE_SAST else "preprod")
        adapter = request.form.get("adapter") or None
        if adapter in ("", "all"):
            adapter = None

        manifest_path = request.form.get("manifest")
        # For DAST with sub-mode=url, build a synthetic manifest in memory and
        # write it to a temp YAML the scan_runner can read. The runner cleans
        # the file up in its finally block.
        dast_sub = (request.form.get("dast_target_kind") or "manifest").lower()
        if mode == sm.MODE_DAST and dast_sub == "url":
            target_url = (request.form.get("target_url") or "").strip()
            allow_internal_scan = (request.form.get("allow_internal_scan") == "on")
            allow_insecure_http = (request.form.get("allow_insecure_http") == "on")
            chk = check_url(
                target_url,
                allow_internal_scan=allow_internal_scan,
                allow_insecure_http=allow_insecure_http,
            )
            if not chk.ok:
                marker = "HARD" if chk.hard_deny else "REFUSED"
                return (f"{marker}: cannot scan {target_url!r}\n  {chk.reason}", 400)
            scan_id = new_scan_id()
            manifest_dict = adhoc_mod.build_adhoc_manifest_dict(
                chk.url, allow_internal_scan=allow_internal_scan,
                allow_insecure_http=allow_insecure_http,
                actor=DEFAULT_ACTOR,
            )
            manifest_path = str(adhoc_mod.write_adhoc_manifest(manifest_dict, scan_id))
        else:
            scan_id = None   # assigned below after the manifest is read

        # --- input validation (these form values flow into argv + a log path) ---
        if stage not in STAGES:
            return f"Unknown stage {stage!r} (expected one of {', '.join(STAGES)})", 400
        if adapter is not None and adapter not in REGISTRY:
            return f"Unknown adapter {adapter!r}", 400
        if not (mode == sm.MODE_DAST and dast_sub == "url"):
            # Operator-supplied manifest path → confine it to the manifests dir
            # (prevents traversal / pointing the runner at an arbitrary file).
            md = Path(app.config["MANIFESTS_DIR"]).resolve()
            try:
                mp = Path(manifest_path or "").resolve()
                mp.relative_to(md)
            except (ValueError, OSError, RuntimeError):
                return f"Refusing manifest path outside {md}: {manifest_path!r}", 400
            manifest_path = str(mp)

        try:
            m = Manifest.from_yaml(manifest_path)
        except Exception as e:
            # If we already wrote a temp adhoc YAML and it failed to parse,
            # clean it up before bailing.
            if mode == sm.MODE_DAST and dast_sub == "url" and scan_id:
                adhoc_mod.cleanup_one(scan_id)
            return f"Cannot read manifest: {e}", 400
        # SAST + DAST/manifest paths still need a scan_id; DAST/url got one above.
        if scan_id is None:
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
            mode,   # 'sast' | 'dast' — DAST skips source materialization entirely
        ]
        env = os.environ.copy()
        env["PATH"] = "/home/user/bin:/home/user/.local/bin:" + env.get("PATH", "")
        proc = sp.Popen(  # nosec B603 — list-form (no shell); stage/adapter/manifest validated above
            cmd, env=env, stdout=open(log_path, "w"), stderr=sp.STDOUT,  # nosemgrep — validated argv, no shell

            cwd=str(Path(__file__).resolve().parent.parent.parent),
            start_new_session=True,
        )
        job.pid = proc.pid
        job.log_path = str(log_path)
        job.status = "running"
        write_scan(job)
        emit_event(job, "scan.started", actor=DEFAULT_ACTOR, kind="rescan")
        return redirect(url_for("scan_status", scan_id=scan_id))

    @app.route("/scan/<scan_id>")
    def scan_status(scan_id):
        if not _SAFE_SCAN_ID.match(scan_id):
            return "Scan not found", 404
        job = get_scan(scan_id)
        if not job:
            return "Scan not found", 404
        update_status_from_pid(job)
        log_tail = ""
        if job.log_path:
            log_tail = _safe_log_tail(job.log_path)
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
        if not _SAFE_SCAN_ID.match(scan_id):
            return jsonify({"error": "not found"}), 404
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
        emit_event(job, "scan.stopped", actor=DEFAULT_ACTOR, killed_via=killed_via or "already-gone")

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
        if not _SAFE_SCAN_ID.match(scan_id):
            return jsonify({"error": "not found"}), 404
        job = get_scan(scan_id)
        if not job:
            return jsonify({"error": "not found"}), 404
        update_status_from_pid(job)
        log_tail = ""
        if job.log_path:
            log_tail = _safe_log_tail(job.log_path)
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

    @app.route("/feeds", methods=["GET"])
    def feeds_page():
        from collections import defaultdict
        store = FeedStore()
        fetch_store = FeedFetchStore()
        feeds = store.all()
        # Auto-group: feeds whose URLs share the same prefix-up-to-last-slash
        # collapse into one expandable section. Threshold of 5 keeps small,
        # hand-curated sets (e.g. three cvedaily root feeds) in the main table
        # and only collapses the bulk clusters (e.g. 800+ per-tag feeds).
        GROUP_THRESHOLD = 5
        buckets: dict[str, list] = defaultdict(list)
        for f in feeds:
            prefix = f.url.rsplit("/", 1)[0] + "/"
            buckets[prefix].append(f)
        ungrouped = []
        groups = []
        for prefix, fs in buckets.items():
            if len(fs) >= GROUP_THRESHOLD:
                ok = sum(1 for x in fs if x.last_status == "ok")
                errored = sum(1 for x in fs if x.last_status not in ("ok", ""))
                never = sum(1 for x in fs if not x.last_fetch_ts)
                last_fetch_ts = max((x.last_fetch_ts or 0) for x in fs) or None
                total_items = sum((x.last_item_count or 0) for x in fs)
                # Sort feeds inside the group by name for stable expansion order.
                fs_sorted = sorted(fs, key=lambda x: x.name.lower())
                groups.append({
                    "prefix": prefix,
                    "feeds": fs_sorted,
                    "count": len(fs),
                    "ok": ok, "errored": errored, "never": never,
                    "last_fetch_ts": last_fetch_ts,
                    "total_items": total_items,
                })
            else:
                ungrouped.extend(fs)
        ungrouped.sort(key=lambda x: x.created_at)
        groups.sort(key=lambda g: -g["count"])   # biggest groups first
        # Per-feed history only for ungrouped — grouped feeds get histories
        # rendered on the per-feed detail/edit page rather than inline in the
        # collapsed view (keeps the response small even with thousands of feeds).
        history_by_id = {f.feed_id: fetch_store.for_feed(f.feed_id, limit=10) for f in ungrouped}
        return render_template(
            "feeds.html",
            ungrouped=ungrouped,
            groups=groups,
            history_by_id=history_by_id,
            formats=VALID_FORMATS,
        )

    @app.route("/feeds", methods=["POST"])
    def feeds_create():
        name = (request.form.get("name") or "").strip()
        url = (request.form.get("url") or "").strip()
        poll = request.form.get("poll_seconds", "3600")
        if not (name and url):
            return "name and url are required", 400
        # Auto-detect format. No dropdown — the server fetches a sample and
        # lets the translator's own peek-parser decide. If the bytes don't
        # match any of our four shapes, surface the parser's reason.
        fmt, http_status, err = detect_feed_format(url)
        if not fmt:
            return f"could not auto-detect feed format (HTTP {http_status}): {err}", 400
        try:
            poll_seconds = max(60, int(poll))
        except ValueError:
            poll_seconds = 3600
        feed = Feed(
            feed_id=new_feed_id(), name=name, url=url,
            format=fmt, poll_seconds=poll_seconds, enabled=True,
        )
        FeedStore().write(feed)
        return redirect(url_for("feeds_page"))

    @app.route("/feeds/<feed_id>/edit", methods=["GET", "POST"])
    def feeds_edit(feed_id):
        store = FeedStore()
        feed = store.get(feed_id)
        if not feed or feed.deleted:
            return "feed not found", 404
        error = None
        if request.method == "POST":
            name = (request.form.get("name") or feed.name).strip()
            url = (request.form.get("url") or feed.url).strip()
            poll = request.form.get("poll_seconds", str(feed.poll_seconds))
            enabled = request.form.get("enabled") == "on"
            try:
                poll_seconds = max(60, int(poll))
            except ValueError:
                poll_seconds = feed.poll_seconds
            new_fmt = feed.format
            # Re-detect format only when the URL changed — saves a network
            # round-trip on edits that only change name/poll/enabled.
            if url != feed.url:
                detected, http_status, err = detect_feed_format(url)
                if not detected:
                    error = f"could not auto-detect format for new URL (HTTP {http_status}): {err}"
                else:
                    new_fmt = detected
            if error is None:
                feed.name = name
                feed.url = url
                feed.poll_seconds = poll_seconds
                feed.enabled = enabled
                feed.format = new_fmt
                store.write(feed)
                return redirect(url_for("feeds_page"))
        return render_template("feed_edit.html", feed=feed, error=error)

    @app.route("/feeds/discover", methods=["GET", "POST"])
    def feeds_discover():
        """Scrape an aggregator page for feed-like links so an operator can
        bulk-import (e.g. https://cvedaily.com/pages/tags/ links to one feed
        per tag). Detection is best-effort: an HTML parser pulls every <a href>,
        we keep links that look like feeds (extension or path hint), then
        auto-detect format per candidate. Operator picks via checkboxes."""
        if request.method == "GET":
            return render_template("feeds_discover.html",
                                   page_url=request.args.get("url", ""), candidates=None)
        page_url = (request.form.get("page_url") or "").strip()
        if not page_url:
            return render_template("feeds_discover.html",
                                   page_url="", candidates=None,
                                   error="enter a page URL")
        # SSRF guard: this URL is fetched server-side, so run it through the
        # same URL-safety policy as DAST targets (deny internal/metadata,
        # require http(s), re-resolve DNS) before urlopen.
        from ..core.url_safety import check_url
        _chk = check_url(page_url)
        if not _chk.ok:
            return render_template("feeds_discover.html", page_url=page_url, candidates=None,
                                   error=f"refusing to fetch {page_url!r}: {_chk.reason}")
        page_url = _chk.url
        from html.parser import HTMLParser
        from urllib.parse import urljoin
        import urllib.request as _u

        class _Links(HTMLParser):
            def __init__(self):
                super().__init__()
                self.hrefs: list[str] = []
                self._a_text: list[str] = []
                self._in_a = False
                self.texts: dict[str, str] = {}

            def handle_starttag(self, tag, attrs):
                if tag != "a":
                    return
                for k, v in attrs:
                    if k == "href" and v:
                        self.hrefs.append(v)
                        self._in_a = True
                        self._a_text = []
                        self._current = v
                        return

            def handle_endtag(self, tag):
                if tag == "a" and self._in_a:
                    self.texts[self._current] = "".join(self._a_text).strip()
                    self._in_a = False

            def handle_data(self, data):
                if self._in_a:
                    self._a_text.append(data)

        try:
            req = _u.Request(page_url, headers={"User-Agent": "ai-protect/1.0 (+feed discovery)"})
            with _u.urlopen(req, timeout=20) as r:  # nosec B310 nosemgrep: dynamic-urllib-use-detected — scheme+host vetted by check_url() above
                html_body = r.read().decode("utf-8", errors="replace")
        except Exception as e:
            return render_template("feeds_discover.html",
                                   page_url=page_url, candidates=None,
                                   error=f"could not fetch page: {type(e).__name__}: {e}")
        parser = _Links()
        try:
            parser.feed(html_body)
        except Exception as e:
            return render_template("feeds_discover.html",
                                   page_url=page_url, candidates=None,
                                   error=f"could not parse page HTML: {e}")
        from concurrent.futures import ThreadPoolExecutor

        existing_urls = {f.url for f in FeedStore().all(include_deleted=True)}
        seen: set[str] = set()
        FEED_HINTS = (".xml", ".atom", ".rss", ".json", "/feed", "/rss", "/atom")
        # First pass: filter to feed-like, dedup by absolute URL, keep the
        # (href, full) pairing so anchor text can be looked up later.
        targets: list[tuple[str, str]] = []
        for href in parser.hrefs:
            full = urljoin(page_url, href)
            if not full.startswith(("http://", "https://")):
                continue
            if not any(h in full.lower() for h in FEED_HINTS):
                continue
            if full in seen:
                continue
            seen.add(full)
            targets.append((href, full))
        # Second pass: detect format in parallel. 32 workers comfortably
        # handles the 800+ per-tag feeds on cvedaily.com in a few seconds;
        # any single hung connection only delays itself thanks to per-call
        # HTTP_TIMEOUT.
        urls = [full for (_h, full) in targets]
        with ThreadPoolExecutor(max_workers=32) as ex:
            detections = list(ex.map(detect_feed_format, urls))
        candidates: list[dict] = []
        for (href, full), (fmt, http_status, err) in zip(targets, detections):
            candidates.append({
                "url": full,
                "anchor_text": parser.texts.get(href, ""),
                "format": fmt,
                "http_status": http_status,
                "error": err,
                "already_added": full in existing_urls,
            })
        return render_template("feeds_discover.html",
                               page_url=page_url, candidates=candidates,
                               error=None)

    @app.route("/feeds/discover/import", methods=["POST"])
    def feeds_discover_import():
        import secrets
        import time as _time
        urls = request.form.getlist("url")
        names = request.form.getlist("name")
        formats = request.form.getlist("format")
        poll = request.form.get("poll_seconds", "3600")
        try:
            poll_seconds = max(60, int(poll))
        except ValueError:
            poll_seconds = 3600
        store = FeedStore()
        existing = {f.url for f in store.all(include_deleted=True)}
        # Stagger first-fetch time across the polling window so a bulk import
        # of 800+ feeds doesn't fire them all on the next 30s tick. Each feed's
        # next-due moment becomes uniformly distributed over the full poll
        # interval starting now.
        now = _time.time()
        created = 0
        for i, url in enumerate(urls):
            url = url.strip()
            if not url or url in existing:
                continue
            name = (names[i] if i < len(names) else "").strip() or url
            fmt = (formats[i] if i < len(formats) else "").strip()
            if fmt not in VALID_FORMATS:
                # detection failed at discovery time — skip; operator can add
                # the URL manually after fixing.
                continue
            feed = Feed(
                feed_id=new_feed_id(), name=name, url=url,
                format=fmt, poll_seconds=poll_seconds, enabled=True,
                # CSPRNG jitter (non-security, but clears weak-PRNG flags): spread initial poll times
                last_fetch_ts=now - secrets.randbelow(max(1, int(poll_seconds))),
            )
            store.write(feed)
            existing.add(url)
            created += 1
        return redirect(url_for("feeds_page"))

    @app.route("/feeds/fetch-all", methods=["POST"])
    def feeds_fetch_all():
        """Force-fetch every enabled feed. Each fetch logs its own row to
        FeedFetchStore so the per-feed history reflects this batch run."""
        store = FeedStore()
        ffs = FeedFetchStore()
        intel = IntelStore()
        results = []
        for feed in store.all():
            if not feed.enabled:
                continue
            r = fetch_feed(feed, store, ffs, intel)
            results.append({
                "feed_id": feed.feed_id, "name": feed.name,
                "status": r.status, "items_count": r.items_count,
                "new_count": r.new_count, "http_status": r.http_status,
                "duration_ms": r.duration_ms, "error": r.error,
            })
        return jsonify({"fetched": len(results), "results": results})

    @app.route("/feeds/<feed_id>/fetch", methods=["POST"])
    def feeds_fetch(feed_id):
        store = FeedStore()
        feed = store.get(feed_id)
        if not feed or feed.deleted:
            return jsonify({"error": "feed not found"}), 404
        result = fetch_feed(feed, store, FeedFetchStore(), IntelStore())
        return jsonify({
            "status": result.status, "items_count": result.items_count,
            "new_count": result.new_count, "duration_ms": result.duration_ms,
            "http_status": result.http_status, "error": result.error,
        })

    @app.route("/feeds/<feed_id>/delete", methods=["POST"])
    def feeds_delete(feed_id):
        store = FeedStore()
        feed = store.get(feed_id)
        if not feed:
            return "feed not found", 404
        feed.deleted = True
        feed.enabled = False
        store.write(feed)
        return redirect(url_for("feeds_page"))

    @app.route("/feeds/<feed_id>/toggle", methods=["POST"])
    def feeds_toggle(feed_id):
        store = FeedStore()
        feed = store.get(feed_id)
        if not feed:
            return "feed not found", 404
        feed.enabled = not feed.enabled
        store.write(feed)
        return redirect(url_for("feeds_page"))

    @app.route("/feeds/validate", methods=["POST"])
    def feeds_validate():
        """Dry-run a candidate feed — no persistence. Used by the Add Feed form
        and the per-feed Re-validate button so operators can see whether the
        translator handles the source as-is, before saving."""
        url = (request.form.get("url") or request.json and request.json.get("url") or "").strip()
        fmt = (request.form.get("format") or request.json and request.json.get("format") or "").strip()
        if not url:
            return jsonify({"ok": False, "error": "url required"}), 400
        return jsonify(validate_feed(url, fmt))

    @app.route("/intel")
    def intel_page():
        store = IntelStore()
        items = store.all()
        feed_filter = request.args.get("feed")
        sev_filter = request.args.get("severity")
        if feed_filter:
            items = [i for i in items if i.source_feed_id == feed_filter]
        if sev_filter:
            items = [i for i in items if i.severity == sev_filter]
        items = items[:500]
        feeds_by_id = {f.feed_id: f for f in FeedStore().all(include_deleted=True)}
        return render_template(
            "intel.html", items=items, feeds_by_id=feeds_by_id,
            feed_filter=feed_filter, sev_filter=sev_filter,
            severities=["critical", "high", "medium", "low", "info"],
        )

    @app.route("/api/status")
    def api_status():
        return jsonify(overall_status(app.config["FINDINGS_PATH"]))

    @app.route("/settings", methods=["GET", "POST"])
    def settings_page():
        from datetime import datetime
        from zoneinfo import ZoneInfo, available_timezones
        errors: dict[str, str] = {}
        ok_msg = None
        active_section = (request.args.get("section") or request.form.get("section")
                          or user_settings.SCHEMA[0].key)

        if request.method == "POST":
            # Collect every known field's value from the form. Free-text override
            # for selects supplies a "<key>_custom" sibling input.
            updates: dict[str, str] = {}
            for section in user_settings.SCHEMA:
                for fld in section.fields:
                    if fld.kind == "checkbox":
                        updates[fld.key] = "on" if request.form.get(fld.key) == "on" else ""
                        continue
                    if fld.kind == "select" and fld.free_text_override:
                        custom = (request.form.get(f"{fld.key}_custom") or "").strip()
                        picked = (request.form.get(fld.key) or "").strip()
                        updates[fld.key] = custom or picked
                        continue
                    if fld.key in request.form:
                        updates[fld.key] = (request.form.get(fld.key) or "").strip()
            errors = user_settings.set_many(updates)
            if not errors:
                ok_msg = f"saved {len(updates)} setting(s)"

        # Live snapshot for re-render — overlay form values on top of saved
        # values so an error in one field doesn't clobber edits in others.
        current = {}
        for section in user_settings.SCHEMA:
            for fld in section.fields:
                if request.method == "POST":
                    current[fld.key] = request.form.get(fld.key, "") or fld.default
                else:
                    current[fld.key] = user_settings.get(fld.key, fld.default)

        # Locale preview — render sample timestamp in the chosen zone / format.
        try:
            sample = datetime.now(
                ZoneInfo(current.get("timezone") or "UTC")
            ).strftime(current.get("date_format") or user_settings.DEFAULT_DATE_FORMAT)
        except Exception:
            sample = "(invalid timezone or format)"

        # JS-side reveal map: { controller_key: { value: [hidden_keys] } }.
        # Built here (not in the template) because Jinja lacks dict comprehensions.
        reveal_map = {
            fld.key: fld.reveal_when
            for section in user_settings.SCHEMA
            for fld in section.fields
            if fld.reveal_when
        }

        return render_template(
            "settings.html",
            schema=user_settings.SCHEMA,
            current=current,
            errors=errors,
            ok=ok_msg,
            active_section=active_section,
            sample=sample,
            all_zones_count=len(available_timezones()),
            reveal_map=reveal_map,
        )

    @app.route("/docs")
    def docs_page():
        """Step-by-step setup guides for every settings field. Anchors here are
        referenced by the help bubbles on /settings (field.help_anchor)."""
        return render_template("docs.html", schema=user_settings.SCHEMA)

    return app


def _allowed_next(state: ChangeState) -> list[str]:
    from ..remediate.state import ALLOWED
    return [s.value for s in ALLOWED.get(state, set())]


# Re-export from the shared dashboard module so existing call sites in this
# file keep working. Logic lives in pipeline/core/dashboard.py and is shared
# with pipeline/remediate/scan_runner.py — keeping the two paths from drifting.
from ..core.dashboard import (
    RESOLVED_STATES as _RESOLVED_STATES,
    alias_map as _alias_map,
    resolved_fingerprints as _resolved_fingerprints,
    active_findings as _active_findings,
)


def _dashboard_findings(store, *, include_unverified: bool) -> list:
    """Dashboard-facing wrapper around _active_findings that hides
    intel_match_unverified findings unless the caller opts back in.

    Why: token-overlap intel matches are unverified by construction and
    grow into 100s per app — drowning out real scanner signal. Hiding by
    default keeps the dashboard scannable. The findings are still in the
    store (audit), still reachable by direct URL (/finding/<id>), and
    still seen by scan_runner / auto_resolve. The "Show unverified
    intel" toggle on /index re-includes them when an operator wants
    to triage.
    """
    out = _active_findings(store)
    if not include_unverified:
        out = [f for f in out if not (f.evidence or {}).get("intel_match_unverified")]
    return out


def _include_unverified(request) -> bool:
    """Read the ?include_unverified= query param; default False so the
    dashboard hides by default. Accepts '1' / 'on' / 'true' (case
    insensitive)."""
    v = (request.args.get("include_unverified") or "").lower()
    return v in ("1", "on", "true", "yes")


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
    # Bind loopback by default (clears bandit B104). Pass --host 0.0.0.0 to
    # expose the UI on all interfaces deliberately.
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()
    app = create_app(args.findings, args.manifests_dir)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
