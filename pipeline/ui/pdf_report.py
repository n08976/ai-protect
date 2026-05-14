"""PDF report generator for findings.

reportlab-based. In-process, no subprocess fanout, suitable for an HTTP route
that fires on a download click. Output is a multi-section report:

    - Cover with filter context, totals, severity breakdown, category breakdown
    - One section per finding (sorted by severity descending) with:
      severity / title / app+tier / adapter / tool source URL (from CATALOG) /
      description / file+line / url / remediation / references / compliance tags
"""
from __future__ import annotations

import io
import time
from typing import Iterable

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer,
    Table, TableStyle,
)

from .catalog import CATALOG


# Match the rest of the UI palette
NAVY = colors.HexColor("#1F3A5F")
NAVY_DK = colors.HexColor("#15293F")
ACCENT = colors.HexColor("#C04A2B")
ALT = colors.HexColor("#F2F5F9")
MUTED = colors.HexColor("#555555")
BORDER = colors.HexColor("#DDE3EB")


SEVERITY_COLORS = {
    "critical": colors.HexColor("#8a2010"),
    "high":     colors.HexColor("#8a4a10"),
    "medium":   colors.HexColor("#8a6c10"),
    "low":      colors.HexColor("#1F3A5F"),
    "info":     colors.HexColor("#555555"),
}
SEVERITY_BGS = {
    "critical": colors.HexColor("#fde7e2"),
    "high":     colors.HexColor("#fbe9d8"),
    "medium":   colors.HexColor("#fdf6dc"),
    "low":      colors.HexColor("#e3eef5"),
    "info":     colors.HexColor("#eeeeee"),
}


def _styles():
    ss = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=ss["Title"], textColor=NAVY,
                                fontSize=20, leading=24, spaceAfter=6,
                                alignment=TA_LEFT, fontName="Helvetica-Bold"),
        "subtitle": ParagraphStyle("subtitle", parent=ss["Normal"], textColor=MUTED,
                                   fontSize=10, leading=14, spaceAfter=14),
        "h1": ParagraphStyle("h1", parent=ss["Heading1"], textColor=NAVY,
                             fontSize=14, leading=18, spaceBefore=12, spaceAfter=4,
                             fontName="Helvetica-Bold"),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"], textColor=NAVY_DK,
                             fontSize=11, leading=14, spaceBefore=8, spaceAfter=2,
                             fontName="Helvetica-Bold"),
        "h3": ParagraphStyle("h3", parent=ss["Heading3"], textColor=MUTED,
                             fontSize=9, leading=11, spaceBefore=4, spaceAfter=2,
                             fontName="Helvetica-Bold",
                             alignment=TA_LEFT),
        "body": ParagraphStyle("body", parent=ss["BodyText"], fontSize=10,
                               leading=13, spaceAfter=2),
        "mono": ParagraphStyle("mono", parent=ss["BodyText"], fontSize=8.5,
                               leading=11, fontName="Courier", textColor=NAVY_DK),
        "small_muted": ParagraphStyle("smallmuted", parent=ss["BodyText"],
                                      fontSize=8.5, leading=11, textColor=MUTED),
        "label": ParagraphStyle("label", parent=ss["BodyText"], fontSize=8.5,
                                leading=11, textColor=MUTED, fontName="Helvetica-Bold"),
    }


def _esc(s) -> str:
    if s is None:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _sev_chip(sev: str, st: dict) -> Table:
    sev = sev or "info"
    chip = Table(
        [[Paragraph(f"<b>{_esc(sev.upper())}</b>",
                    ParagraphStyle("chip", parent=st["body"], fontSize=9,
                                   textColor=SEVERITY_COLORS.get(sev, MUTED),
                                   fontName="Helvetica-Bold"))]],
        colWidths=[0.9 * inch],
    )
    chip.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_BGS.get(sev, BORDER)),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return chip


def _kv_table(rows: list[tuple[str, str]], st: dict, *, label_w: float = 1.05 * inch) -> Table:
    """Two-column key/value table; key is muted-bold, value monospaced where useful."""
    data = []
    for k, v in rows:
        data.append([
            Paragraph(_esc(k), st["label"]),
            Paragraph(_esc(v) if v else "<i>—</i>", st["body"]),
        ])
    t = Table(data, colWidths=[label_w, 5.6 * inch - label_w])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))
    return t


def _tool_source(adapter_name: str) -> tuple[str, str]:
    """Return (display_name, source_url) for the adapter — from CATALOG."""
    meta = CATALOG.get(adapter_name) or {}
    return adapter_name, meta.get("source_url") or ""


def _summary_table(findings: list, st: dict) -> Table:
    from collections import Counter
    sev_counts = Counter(f.severity.value for f in findings)
    cat_counts = Counter(f.category.value for f in findings)
    adapter_counts = Counter(f.adapter for f in findings)
    app_counts = Counter(f.app_name for f in findings)

    def _section(title: str, items: Iterable[tuple[str, int]]) -> Table:
        rows = [[Paragraph(f"<b>{_esc(title)}</b>", st["h3"]), ""]]
        for k, v in items:
            rows.append([Paragraph(_esc(k), st["body"]),
                         Paragraph(f"<b>{v}</b>", st["body"])])
        if len(rows) == 1:
            rows.append([Paragraph("<i>none</i>", st["small_muted"]), ""])
        t = Table(rows, colWidths=[1.55 * inch, 0.45 * inch])
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 2),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2),
            ("TOPPADDING", (0, 0), (-1, -1), 1),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
            ("LINEABOVE", (0, 1), (-1, 1), 0.5, BORDER),
        ]))
        return t

    sev_order = [("critical", "critical"), ("high", "high"), ("medium", "medium"),
                 ("low", "low"), ("info", "info")]
    sev_block = _section("Severity",
                         [(label, sev_counts.get(key, 0)) for key, label in sev_order])
    cat_block = _section("Category", cat_counts.most_common(10))
    adapter_block = _section("Adapter", adapter_counts.most_common(10))
    app_block = _section("App", app_counts.most_common(10))

    # 4-column grid of sub-tables
    grid = Table(
        [[sev_block, cat_block, adapter_block, app_block]],
        colWidths=[2.0 * inch, 2.0 * inch, 2.0 * inch, 1.5 * inch],
    )
    grid.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.4, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BACKGROUND", (0, 0), (-1, -1), ALT),
    ]))
    return grid


def _finding_block(f, st: dict):
    """One per finding: severity chip + title row, then KV details."""
    adapter_name, source_url = _tool_source(f.adapter)
    ev = f.evidence or {}
    af = f.affected or {}

    file_ = ev.get("file") or af.get("file") or ""
    line = ev.get("line") or ev.get("start_line") or ""
    if file_ and line:
        file_line = f"{file_}:{line}"
    elif file_:
        file_line = file_
    else:
        file_line = ""

    url = ev.get("url") or af.get("url") or af.get("target") or af.get("endpoint") or ""
    snippet = (ev.get("snippet") or ev.get("code") or "")[:800]

    # Title row: severity chip + title
    title_row = Table(
        [[_sev_chip(f.severity.value, st),
          Paragraph(f"<b>{_esc(f.title)}</b>", st["h2"])]],
        colWidths=[1.0 * inch, 5.5 * inch],
    )
    title_row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))

    # Source / provenance block
    source_str = adapter_name
    if source_url:
        source_str += f"  ({source_url})"
    rows = [
        ("Finding ID", f.finding_id),
        ("App / Tier", f"{f.app_name}  ·  Tier {f.tier}"),
        ("Tool / Source", source_str),
        ("Stage", f.stage),
        ("Category", f.category.value),
    ]
    if file_line:
        rows.append(("File", file_line))
    if url:
        rows.append(("URL / Target", url))
    if f.compliance:
        rows.append(("Compliance", ", ".join(f.compliance)))
    meta_table = _kv_table(rows, st)

    # Description (Paragraph supports wrapping)
    desc = (f.description or "").strip()
    body_blocks = [meta_table]
    if desc:
        body_blocks += [
            Spacer(1, 4),
            Paragraph("<b>Description</b>", st["h3"]),
            Paragraph(_esc(desc), st["body"]),
        ]
    if snippet:
        body_blocks += [
            Spacer(1, 4),
            Paragraph("<b>Evidence</b>", st["h3"]),
            Paragraph(_esc(snippet).replace("\n", "<br/>"), st["mono"]),
        ]
    if f.remediation:
        body_blocks += [
            Spacer(1, 4),
            Paragraph("<b>Remediation</b>", st["h3"]),
            Paragraph(_esc(f.remediation), st["body"]),
        ]
    if f.references:
        body_blocks += [
            Spacer(1, 4),
            Paragraph("<b>References</b>", st["h3"]),
            Paragraph(
                "<br/>".join(_esc(r) for r in f.references[:6] if r),
                st["mono"],
            ),
        ]

    return KeepTogether([title_row, *body_blocks, Spacer(1, 8),
                         HRFlowable(width="100%", thickness=0.4, color=BORDER),
                         Spacer(1, 6)])


def generate_pdf(findings, *, filters: dict, title: str = "ai-protect findings report") -> bytes:
    """Render a PDF report. Returns the bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.55 * inch, bottomMargin=0.55 * inch,
        title=title, author="ai-protect pipeline",
    )
    st = _styles()
    story = []

    # Header
    story.append(Paragraph(_esc(title), st["title"]))
    ts = time.strftime("%Y-%m-%d %H:%M:%S %Z")
    active = {k: v for k, v in (filters or {}).items() if v}
    if active:
        filt_str = ", ".join(f"{k}={v}" for k, v in active.items())
    else:
        filt_str = "all findings (no filters)"
    story.append(Paragraph(
        f"Generated {_esc(ts)} &nbsp;·&nbsp; <b>filters:</b> {_esc(filt_str)} &nbsp;·&nbsp; "
        f"<b>{len(findings)}</b> finding(s)",
        st["subtitle"],
    ))

    # Summary table
    story.append(Paragraph("Summary", st["h1"]))
    if findings:
        story.append(_summary_table(findings, st))
    else:
        story.append(Paragraph("No findings to report under the current filters.", st["body"]))
    story.append(Spacer(1, 14))

    # Findings — sorted critical → info, then by detected_at desc within
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings_sorted = sorted(
        findings,
        key=lambda f: (-sev_rank.get(f.severity.value, 0), -f.detected_at),
    )

    if findings_sorted:
        story.append(Paragraph(f"Findings ({len(findings_sorted)})", st["h1"]))
        story.append(Spacer(1, 4))
        for f in findings_sorted:
            story.append(_finding_block(f, st))

    doc.build(story)
    return buf.getvalue()
