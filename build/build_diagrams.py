"""Build the 7 SVG diagrams for the companion technical doc.
Palette mirrors v2.1: navy #1F3A5F, takeaway #EAF3FA, callout #FFF4E5,
alt-row #F2F5F9, accent #C04A2B, white #FFFFFF.
"""
import os
import cairosvg

NAVY = "#1F3A5F"
NAVY_DK = "#15293F"
BLUE = "#EAF3FA"
BLUE_DK = "#7BA8CC"
ORANGE = "#FFF4E5"
ORANGE_DK = "#E0A555"
GRAY_LT = "#F2F5F9"
GRAY = "#D6DCE5"
GRAY_DK = "#8A95A8"
ACCENT = "#C04A2B"
ACCENT_LT = "#E89C85"
TEXT = "#222222"
TEXT_LT = "#555555"
WHITE = "#FFFFFF"
GREEN = "#3D8C5C"
GREEN_LT = "#C8E0CF"

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "diagrams")
os.makedirs(OUT, exist_ok=True)

FONT = 'font-family="Arial, Helvetica, sans-serif"'

def hdr(w, h):
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" {FONT}>'

def box(x, y, w, h, fill, stroke=NAVY, sw=1, rx=6):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}" rx="{rx}" ry="{rx}"/>'

def _esc(t):
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def text(x, y, t, size=12, fill=TEXT, anchor="start", weight="normal"):
    return f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" text-anchor="{anchor}" font-weight="{weight}">{_esc(t)}</text>'

def arrow_def():
    return '''<defs>
<marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
<path d="M 0 0 L 10 5 L 0 10 z" fill="#1F3A5F"/></marker>
<marker id="arrL" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
<path d="M 0 0 L 10 5 L 0 10 z" fill="#8A95A8"/></marker>
<marker id="arrA" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
<path d="M 0 0 L 10 5 L 0 10 z" fill="#C04A2B"/></marker>
</defs>'''

# ============================================================
# DIAGRAM 1: Pipeline Overview (full stack)
# ============================================================
def diagram_1():
    W, H = 1200, 760
    s = [hdr(W, H), arrow_def()]
    # Title strip
    s.append(box(0, 0, W, 44, NAVY, NAVY, 0, 0))
    s.append(text(W/2, 28, "AI Security Assurance Pipeline — End-to-End", 18, WHITE, "middle", "bold"))

    # Pipeline stages (top row)
    stages = [
        ("Stage 0", "Discovery &", "Intake"),
        ("Stage 1", "Triage &", "Tiering"),
        ("Stage 2", "Static /", "Pre-Prod"),
        ("Stage 3", "Dynamic", "AppSec"),
        ("Stage 4", "AI", "Red Team"),
        ("Stage 5", "Remed-", "iation"),
        ("Stage 6", "Continuous", "Monitoring"),
        ("Stage 7", "Reporting &", "Notification"),
    ]
    sw = 130; sh = 90; sx0 = 40; sy = 80; gap = 12
    for i, (lab, l1, l2) in enumerate(stages):
        x = sx0 + i*(sw+gap)
        s.append(box(x, sy, sw, sh, BLUE, NAVY, 1.5, 6))
        s.append(text(x+sw/2, sy+22, lab, 11, NAVY_DK, "middle", "bold"))
        s.append(text(x+sw/2, sy+50, l1, 13, TEXT, "middle", "bold"))
        s.append(text(x+sw/2, sy+68, l2, 13, TEXT, "middle", "bold"))
        if i < len(stages)-1:
            ax1 = x+sw+1; ax2 = x+sw+gap-1; ay = sy+sh/2
            s.append(f'<line x1="{ax1}" y1="{ay}" x2="{ax2}" y2="{ay}" stroke="{NAVY}" stroke-width="2" marker-end="url(#arr)"/>')

    # Tool layer (per-stage tools)
    tools = [
        ["ServiceNow", "CASB egress", "Azure Repos scan", "GitHub scan"],
        ["OPA policy", "CMDB tag", "Tier scoring"],
        ["Semgrep", "CodeQL", "Trivy", "ModelScan", "TruffleHog"],
        ["Burp Suite", "Nuclei", "ZAP", "Schemathesis"],
        ["garak", "PyRIT", "ART", "PromptFoo"],
        ["Auto-PR (AzDO/GH)", "WAF push", "Llama Guard", "NeMo Guard"],
        ["Telemetry", "Drift det.", "Re-scan cron"],
        ["Slack/Teams", "Azure Boards / Jira", "Report card"],
    ]
    ty0 = 195; tslot = 22
    for i, items in enumerate(tools):
        x = sx0 + i*(sw+gap)
        s.append(box(x, ty0, sw, len(items)*tslot+14, WHITE, GRAY_DK, 1, 4))
        for j, it in enumerate(items):
            s.append(text(x+sw/2, ty0+18+j*tslot, it, 11, TEXT, "middle"))

    # Orchestrator + Findings + Notify lane
    oy = 430; oh = 70
    s.append(box(40, oy, W-80, oh, ORANGE, ORANGE_DK, 1.5, 8))
    s.append(text(60, oy+25, "ORCHESTRATION & DATA PLANE", 12, NAVY_DK, "start", "bold"))
    s.append(text(60, oy+50, "Azure Pipelines / Argo / Tekton (CI)  •  Kafka event bus  •  DefectDojo (findings, OCSF schema)  •  Vault / Key Vault (secrets)  •  OPA (deploy gates)", 12, TEXT))

    # Sanctioned infrastructure layer (v2.1)
    iy = 530; ih = 90
    s.append(box(40, iy, W-80, ih, NAVY, NAVY_DK, 1.5, 8))
    s.append(text(60, iy+24, "SANCTIONED AI INFRASTRUCTURE  (anchored on v2.1 Operating Model)", 13, WHITE, "start", "bold"))
    parts = [("LLM Gateway", "Claude primary"), ("MCP Farm", "curated registry"), ("Agent Runtime", "SPIFFE ID, scoped"), ("Data Plane", "FHIR / vector / RAG"), ("Telemetry Mesh", "prompts • tools • completions")]
    pw = (W-120)/len(parts); px0 = 60
    for i, (a, b) in enumerate(parts):
        x = px0 + i*pw
        s.append(box(x+5, iy+38, pw-10, 42, "#2C547F", "#456A92", 1, 5))
        s.append(text(x+pw/2, iy+57, a, 12, WHITE, "middle", "bold"))
        s.append(text(x+pw/2, iy+72, b, 10, BLUE, "middle"))

    # Output layer (dashboards)
    dy = 645; dh = 80
    cards = [("Technical Dashboard", "Grafana — coverage, MTTR, jailbreak rate, ATLAS heatmap"),
             ("Executive Dashboard", "Superset/Power BI — risk heatmap, portfolio KPIs, compliance"),
             ("Compliance Evidence", "HIPAA / HITRUST control mapping, audit query")]
    cw = (W-80-2*15)/3; cx0 = 40
    for i, (a, b) in enumerate(cards):
        x = cx0 + i*(cw+15)
        s.append(box(x, dy, cw, dh, BLUE, BLUE_DK, 1.5, 6))
        s.append(text(x+cw/2, dy+24, a, 13, NAVY_DK, "middle", "bold"))
        s.append(text(x+cw/2, dy+50, b, 11, TEXT, "middle"))

    # Connector lines from stages to orchestrator
    for i in range(len(stages)):
        x = sx0 + i*(sw+gap) + sw/2
        s.append(f'<line x1="{x}" y1="{ty0+len(tools[i])*tslot+14}" x2="{x}" y2="{oy}" stroke="{GRAY_DK}" stroke-width="1" stroke-dasharray="3 3"/>')
    # Connectors orchestrator -> infra
    for i in range(len(parts)):
        x = px0 + i*pw + pw/2
        s.append(f'<line x1="{x}" y1="{oy+oh}" x2="{x}" y2="{iy}" stroke="{GRAY_DK}" stroke-width="1" stroke-dasharray="3 3"/>')
    # orchestrator -> dashboards
    for i in range(3):
        x = cx0 + i*(cw+15) + cw/2
        s.append(f'<line x1="{x}" y1="{iy+ih}" x2="{x}" y2="{dy}" stroke="{GRAY_DK}" stroke-width="1" stroke-dasharray="3 3"/>')

    s.append("</svg>")
    return "\n".join(s)

# ============================================================
# DIAGRAM 2: v2.1 mapping
# ============================================================
def diagram_2():
    W, H = 1100, 600
    s = [hdr(W, H), arrow_def()]
    s.append(box(0, 0, W, 42, NAVY, NAVY, 0, 0))
    s.append(text(W/2, 27, "Where this Companion fits with the v2.1 Operating Model", 17, WHITE, "middle", "bold"))

    # Top tier: v2.1 strategic
    sy = 75; sh = 180
    s.append(box(40, sy, W-80, sh, BLUE, BLUE_DK, 2, 8))
    s.append(text(60, sy+28, "v2.1 — STRATEGIC OPERATING MODEL  (already approved deliverable)", 14, NAVY_DK, "start", "bold"))
    blocks = [
        ("Operating Principles", "Paved road > gates · Risk-tiered · Continuous validation"),
        ("Risk Tiering Framework", "Tier 1–4 by data sensitivity, decision impact, integration, users"),
        ("Engagement Model", "Single intake · Self-service T4 · Embedded T1–T2 · Discovery"),
        ("RACI (9 owners)", "AppSec · TI · TH · RT · SCV · AI Gov · Privacy · PlatEng · Biz Owner"),
        ("Phased Roadmap", "Phase 1 modest · Phase 2 tooling+hire · Phase 3 platform"),
    ]
    bw = (W-80-4*12)/5; bx0 = 60
    for i, (a, b) in enumerate(blocks):
        x = bx0 + i*(bw+12); y = sy+50
        s.append(box(x, y, bw, 110, WHITE, BLUE_DK, 1, 6))
        s.append(text(x+bw/2, y+28, a, 12, NAVY_DK, "middle", "bold"))
        # split b into multi-line
        words = b.split(" ")
        lines = []; cur = ""
        for w in words:
            if len(cur)+len(w) > 28: lines.append(cur); cur = w
            else: cur = (cur+" "+w).strip()
        lines.append(cur)
        for j, ln in enumerate(lines[:4]):
            s.append(text(x+bw/2, y+52+j*15, ln, 10, TEXT, "middle"))

    # Connector
    cy1 = sy+sh; cy2 = 320
    for x in (W*0.3, W*0.5, W*0.7):
        s.append(f'<line x1="{x}" y1="{cy1}" x2="{x}" y2="{cy2}" stroke="{NAVY}" stroke-width="2" stroke-dasharray="4 4" marker-end="url(#arr)"/>')
    s.append(text(W/2, (cy1+cy2)/2-4, "operationalized by", 12, NAVY_DK, "middle", "italic"))

    # Bottom tier: this companion
    by = 320; bh = 250
    s.append(box(40, by, W-80, bh, ORANGE, ORANGE_DK, 2, 8))
    s.append(text(60, by+28, "THIS COMPANION — TECHNICAL PIPELINE  (for the offensive security leads)", 14, NAVY_DK, "start", "bold"))
    bot = [
        ("8-Stage Pipeline", "Discovery → Intake → Static → Dynamic → AI Red Team → Remed → Monitor → Report"),
        ("Tooling Per Stage", "Semgrep, CodeQL, Burp, garak, PyRIT, ART, ModelScan, Llama Guard, Presidio…"),
        ("Per-Vertical Builds", "AppSec · Threat Intel · Threat Hunt · Red Team · SCV — capability deltas"),
        ("Dashboards", "Technical (Grafana) · Executive (Superset/Power BI) — mockups inside"),
        ("Phased Tool Rollout", "Honors v2.1 Phase 1 modesty: PoC tooling + existing headcount only"),
        ("Pipeline RACI Extension", "Adds 18 pipeline-specific activities to v2.1's 9-column RACI"),
    ]
    cw = (W-80-2*12)/3; cx0 = 60
    for i, (a, b) in enumerate(bot):
        col = i % 3; row = i // 3
        x = cx0 + col*(cw+12); y = by+55+row*95
        s.append(box(x, y, cw, 80, WHITE, ORANGE_DK, 1, 6))
        s.append(text(x+cw/2, y+24, a, 12, NAVY_DK, "middle", "bold"))
        words = b.split(" ")
        lines = []; cur = ""
        for w in words:
            if len(cur)+len(w) > 50: lines.append(cur); cur = w
            else: cur = (cur+" "+w).strip()
        lines.append(cur)
        for j, ln in enumerate(lines[:3]):
            s.append(text(x+cw/2, y+44+j*15, ln, 10, TEXT, "middle"))

    s.append("</svg>")
    return "\n".join(s)

# ============================================================
# DIAGRAM 3: AI Red Team Kill Chain
# ============================================================
def diagram_3():
    W, H = 1200, 580
    s = [hdr(W, H), arrow_def()]
    s.append(box(0, 0, W, 42, NAVY, NAVY, 0, 0))
    s.append(text(W/2, 27, "AI Red Team Kill Chain — tools, probes, and ATLAS coverage", 17, WHITE, "middle", "bold"))

    stages = [
        ("Recon", "Model fingerprint\nSystem prompt leak\nEndpoint mapping", "garak\nPromptFoo", "AML.T0006\nAML.T0040"),
        ("Single-turn\nJailbreak", "DAN, payload encoding\nrole-play, prompt inject\nencoding/obfuscation", "garak probes\n(promptinject,\ndan, encoding,\nleakreplay)", "AML.T0051\nAML.T0054"),
        ("Multi-turn\nAttack", "Crescendo, drift\nred-team-bot orchestrators\ncontext exhaustion", "PyRIT\norchestrators\n+ converters", "AML.T0051\nAML.T0048"),
        ("Indirect\nInjection", "Poisoned RAG corpus\nemail/doc payloads\ntool-result hijack", "Custom\ncorpus +\nrun via gateway", "AML.T0051.001\nAML.T0070"),
        ("Tool / Agent\nAbuse", "Tool-call fuzzing\nconfused deputy\nexcessive agency", "PyRIT +\ncustom\nharness", "AML.T0053\nAML.T0048"),
        ("Adversarial\nML", "Embedding attacks\nclassifier evasion\nmodel inversion", "ART\nCounterfit\nTextAttack", "AML.T0015\nAML.T0024"),
        ("Persistence /\nExfiltration", "Memory poisoning\nPHI extraction\noff-pipeline pivot", "Custom probes\n+ telemetry\nreplay", "AML.T0010\nAML.T0024"),
    ]
    n = len(stages)
    sw = 150; gap = 12; sx0 = 40
    sy = 80; sh = 70
    for i, (name, _, _, _) in enumerate(stages):
        x = sx0 + i*(sw+gap)
        s.append(box(x, sy, sw, sh, NAVY, NAVY_DK, 1.5, 6))
        for j, ln in enumerate(name.split("\n")):
            s.append(text(x+sw/2, sy+30+j*16, ln, 13, WHITE, "middle", "bold"))
        if i < n-1:
            ax1 = x+sw+1; ax2 = x+sw+gap-1; ay = sy+sh/2
            s.append(f'<line x1="{ax1}" y1="{ay}" x2="{ax2}" y2="{ay}" stroke="{ACCENT}" stroke-width="2.5" marker-end="url(#arrA)"/>')

    # What we test
    py0 = 175; ph = 90
    s.append(text(40, py0-8, "Probes / Tests", 12, NAVY_DK, "start", "bold"))
    for i, (_, probes, _, _) in enumerate(stages):
        x = sx0 + i*(sw+gap)
        s.append(box(x, py0, sw, ph, GRAY_LT, GRAY_DK, 1, 5))
        for j, ln in enumerate(probes.split("\n")):
            s.append(text(x+sw/2, py0+20+j*16, ln, 10, TEXT, "middle"))

    # Tools
    ty0 = 285; th = 90
    s.append(text(40, ty0-8, "Tooling", 12, NAVY_DK, "start", "bold"))
    for i, (_, _, tools, _) in enumerate(stages):
        x = sx0 + i*(sw+gap)
        s.append(box(x, ty0, sw, th, ORANGE, ORANGE_DK, 1, 5))
        for j, ln in enumerate(tools.split("\n")):
            s.append(text(x+sw/2, ty0+20+j*16, ln, 11, NAVY_DK, "middle", "bold"))

    # ATLAS coverage
    ay0 = 395; ah = 70
    s.append(text(40, ay0-8, "MITRE ATLAS technique coverage", 12, NAVY_DK, "start", "bold"))
    for i, (_, _, _, atlas) in enumerate(stages):
        x = sx0 + i*(sw+gap)
        s.append(box(x, ay0, sw, ah, BLUE, BLUE_DK, 1, 5))
        for j, ln in enumerate(atlas.split("\n")):
            s.append(text(x+sw/2, ay0+25+j*16, ln, 11, NAVY_DK, "middle"))

    # Healthcare context band
    hy = 490; hh = 60
    s.append(box(40, hy, W-80, hh, ACCENT, NAVY_DK, 1.5, 6))
    s.append(text(60, hy+24, "HEALTHCARE-SPECIFIC PROBE SET (custom)", 13, WHITE, "start", "bold"))
    s.append(text(60, hy+44, "PHI elicitation  •  Clinical hallucination  •  Off-label drug recs  •  Minimum-necessary violation  •  HIPAA-condition leak  •  BAA-bypass tool calls", 11, WHITE))

    s.append("</svg>")
    return "\n".join(s)

# ============================================================
# DIAGRAM 4: Vertical ownership matrix
# ============================================================
def diagram_4():
    W, H = 1200, 540
    s = [hdr(W, H)]
    s.append(box(0, 0, W, 42, NAVY, NAVY, 0, 0))
    s.append(text(W/2, 27, "Pipeline Ownership Matrix — five verticals × eight stages", 17, WHITE, "middle", "bold"))

    verticals = ["AppSec", "Threat Intel", "Threat Hunt", "Red Team", "Security Control Validation"]
    stages = ["Discovery & Intake", "Triage & Tiering", "Static / Pre-Prod", "Dynamic AppSec", "AI Red Team", "Remediation", "Continuous Monitoring", "Reporting & Notification"]
    # P=primary, S=secondary/support, blank
    # rows = verticals, cols = stages
    matrix = [
        # Disc, Triage, Static, Dyn, AIRT, Remed, Monitor, Report
        ["S", "P", "P",   "P",   "S",   "P",   "S",     "P"  ],  # AppSec
        ["P", "S", "",    "",    "S",   "",    "S",     "S"  ],  # Threat Intel
        ["S", "",  "",    "",    "",    "",    "P",     "S"  ],  # Threat Hunt
        ["",  "S", "",    "S",   "P",   "S",   "S",     "S"  ],  # Red Team
        ["S", "S", "P",   "P",   "P",   "P",   "P",     "S"  ],  # SCV
    ]

    # Layout
    lx = 60; ty0 = 90  # left and top after title
    rh = 64
    headw = 200
    chartw = W - 80 - headw
    cw = chartw / len(stages)

    # column headers
    s.append(box(lx+headw, ty0, chartw, 50, NAVY, NAVY_DK, 1, 6))
    for i, st in enumerate(stages):
        x = lx + headw + i*cw
        # Display short labels split
        words = st.split(" ")
        if len(words) > 2: lines = [" ".join(words[:2]), " ".join(words[2:])]
        else: lines = [st]
        for j, ln in enumerate(lines):
            s.append(text(x+cw/2, ty0+22+j*16, ln, 11, WHITE, "middle", "bold"))

    # rows
    for r, v in enumerate(verticals):
        y = ty0 + 50 + r*rh
        bg = GRAY_LT if r % 2 == 0 else WHITE
        s.append(box(lx, y, headw + chartw, rh, bg, GRAY_DK, 0.5, 0))
        s.append(text(lx+12, y+rh/2+5, v, 13, NAVY_DK, "start", "bold"))
        for c in range(len(stages)):
            x = lx + headw + c*cw
            mark = matrix[r][c]
            if mark == "P":
                s.append(box(x+12, y+10, cw-24, rh-20, ACCENT, ACCENT, 1, 6))
                s.append(text(x+cw/2, y+rh/2+6, "PRIMARY", 11, WHITE, "middle", "bold"))
            elif mark == "S":
                s.append(box(x+12, y+10, cw-24, rh-20, GREEN_LT, GREEN, 1, 6))
                s.append(text(x+cw/2, y+rh/2+6, "Support", 11, NAVY_DK, "middle", "bold"))
            else:
                s.append(text(x+cw/2, y+rh/2+5, "—", 14, GRAY_DK, "middle"))

    # Legend
    ly = ty0 + 50 + len(verticals)*rh + 18
    s.append(box(lx+12, ly, 18, 18, ACCENT, ACCENT, 1, 4))
    s.append(text(lx+38, ly+14, "PRIMARY  — accountable for execution and outcome", 12, TEXT))
    s.append(box(lx+12 + 360, ly, 18, 18, GREEN_LT, GREEN, 1, 4))
    s.append(text(lx+38 + 360, ly+14, "Support  — contributes capability or telemetry", 12, TEXT))
    s.append(text(lx+12 + 720, ly+14, "—  Not directly engaged at this stage", 12, TEXT_LT))

    s.append("</svg>")
    return "\n".join(s)

# ============================================================
# DIAGRAM 5: Technical dashboard mockup
# ============================================================
def diagram_5():
    W, H = 1200, 720
    s = [hdr(W, H)]
    s.append(box(0, 0, W, 42, NAVY, NAVY, 0, 0))
    s.append(text(W/2, 27, "Technical Dashboard — for offensive security operators", 17, WHITE, "middle", "bold"))
    # Sub-header strip (filters)
    s.append(box(0, 42, W, 32, GRAY_LT, GRAY_DK, 0.5, 0))
    filters = ["Time: 30d", "Tier: All", "BU: All", "Tool: All", "Severity: All"]
    fx = 30
    for f in filters:
        s.append(box(fx, 50, 110, 18, WHITE, GRAY_DK, 1, 4))
        s.append(text(fx+55, 63, f, 11, TEXT, "middle"))
        fx += 120

    # KPIs (top row, 4 panels)
    kpi_y = 90; kpi_h = 100
    kpis = [("Asset Coverage", "87%", "+4 wk/wk"),
            ("Open Criticals", "23", "−2 wk/wk"),
            ("MTTR Critical", "6.2 d", "SLA 7 d"),
            ("Jailbreak Rate", "3.1%", "Tier 1 avg")]
    kw = (W-80-3*15)/4
    for i, (a, b, c) in enumerate(kpis):
        x = 40 + i*(kw+15)
        s.append(box(x, kpi_y, kw, kpi_h, WHITE, GRAY_DK, 1, 6))
        s.append(text(x+kw/2, kpi_y+24, a, 12, TEXT_LT, "middle"))
        s.append(text(x+kw/2, kpi_y+62, b, 28, NAVY_DK, "middle", "bold"))
        s.append(text(x+kw/2, kpi_y+88, c, 11, ACCENT if "−" in c or "+" in c else TEXT_LT, "middle"))

    # Findings by severity bar (left)
    p_y = 210; p_h = 240
    s.append(box(40, p_y, 560, p_h, WHITE, GRAY_DK, 1, 6))
    s.append(text(60, p_y+22, "Findings by severity, last 12 weeks", 13, NAVY_DK, "start", "bold"))
    # 12 stacked bars
    bx0 = 70; by0 = p_y+50; bh = 160; bw = 38; gap = 5
    import random; random.seed(7)
    sev_colors = [ACCENT, ORANGE_DK, "#D7B96A", BLUE_DK]  # crit/high/med/low
    for i in range(12):
        crit = random.randint(2, 9)
        high = random.randint(5, 15)
        med = random.randint(8, 20)
        low = random.randint(3, 18)
        total = crit + high + med + low
        scale = bh / 60.0  # max height visual
        ch = crit*scale; hh = high*scale; mh = med*scale; lh = low*scale
        x = bx0 + i*(bw+gap)
        y = by0 + bh
        s.append(f'<rect x="{x}" y="{y-lh}" width="{bw}" height="{lh}" fill="{sev_colors[3]}"/>')
        y -= lh
        s.append(f'<rect x="{x}" y="{y-mh}" width="{bw}" height="{mh}" fill="{sev_colors[2]}"/>')
        y -= mh
        s.append(f'<rect x="{x}" y="{y-hh}" width="{bw}" height="{hh}" fill="{sev_colors[1]}"/>')
        y -= hh
        s.append(f'<rect x="{x}" y="{y-ch}" width="{bw}" height="{ch}" fill="{sev_colors[0]}"/>')
        s.append(text(x+bw/2, by0+bh+14, f"W{i+1}", 9, TEXT_LT, "middle"))
    # Legend
    lg_y = p_y+p_h-30
    lab = [("Critical", sev_colors[0]), ("High", sev_colors[1]), ("Medium", sev_colors[2]), ("Low", sev_colors[3])]
    for i, (l, c) in enumerate(lab):
        x = 70 + i*120
        s.append(box(x, lg_y, 14, 14, c, c, 0, 2))
        s.append(text(x+20, lg_y+11, l, 11, TEXT))

    # MTTR trend (right)
    s.append(box(615, p_y, 545, p_h, WHITE, GRAY_DK, 1, 6))
    s.append(text(635, p_y+22, "MTTR by severity (rolling 30d)", 13, NAVY_DK, "start", "bold"))
    # Two trend lines
    px0 = 645; py0 = p_y+60; pw_w = 500; ph_h = 150
    s.append(f'<line x1="{px0}" y1="{py0+ph_h}" x2="{px0+pw_w}" y2="{py0+ph_h}" stroke="{GRAY_DK}" stroke-width="1"/>')
    s.append(f'<line x1="{px0}" y1="{py0}" x2="{px0}" y2="{py0+ph_h}" stroke="{GRAY_DK}" stroke-width="1"/>')
    # SLA reference line
    sla_y = py0+50
    s.append(f'<line x1="{px0}" y1="{sla_y}" x2="{px0+pw_w}" y2="{sla_y}" stroke="{ACCENT}" stroke-width="1" stroke-dasharray="3 3"/>')
    s.append(text(px0+pw_w-4, sla_y-4, "SLA", 10, ACCENT, "end"))
    pts_c = [120, 110, 95, 100, 90, 85, 78, 82, 75, 70, 68, 62]
    pts_h = [70, 66, 62, 58, 60, 55, 52, 48, 45, 50, 42, 38]
    def line(pts, color):
        seg = []
        for i, v in enumerate(pts):
            x = px0 + i*(pw_w/(len(pts)-1))
            y = py0 + ph_h - v
            seg.append((x, y))
        d = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in seg)
        return f'<path d="{d}" fill="none" stroke="{color}" stroke-width="2.5"/>' + "".join(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{color}"/>' for x, y in seg)
    s.append(line(pts_c, ACCENT))
    s.append(line(pts_h, ORANGE_DK))
    s.append(text(px0, py0-6, "Critical (days)", 11, ACCENT))
    s.append(text(px0+200, py0-6, "High (days)", 11, ORANGE_DK))

    # ATLAS heatmap (left) and top criticals (right)
    a_y = 470; a_h = 230
    s.append(box(40, a_y, 560, a_h, WHITE, GRAY_DK, 1, 6))
    s.append(text(60, a_y+22, "MITRE ATLAS coverage (rows: tactics, cols: techniques)", 13, NAVY_DK, "start", "bold"))
    rows = ["Recon", "Init Access", "ML Model Acc", "Execution", "Persist", "Defense Evas", "Discovery", "Collection", "Impact"]
    cols = 12
    cell_w = 36; cell_h = 17; cx0 = 70; cy0 = a_y+50
    import random
    random.seed(11)
    for r, lab in enumerate(rows):
        s.append(text(cx0-6, cy0+r*cell_h+12, lab, 10, TEXT, "end"))
        for c in range(cols):
            v = random.choice([0,0,1,1,1,2,2,3])
            colors = [GRAY_LT, "#D7E6F0", BLUE_DK, NAVY]
            s.append(f'<rect x="{cx0+c*cell_w}" y="{cy0+r*cell_h}" width="{cell_w-2}" height="{cell_h-2}" fill="{colors[v]}"/>')
    # legend
    lgx = cx0+cols*cell_w + 20
    s.append(text(lgx, cy0+10, "Coverage:", 10, TEXT_LT))
    for i, (l, c) in enumerate([("none", GRAY_LT), ("partial", "#D7E6F0"), ("validated", BLUE_DK), ("automated", NAVY)]):
        s.append(box(lgx, cy0+22+i*22, 14, 14, c, c, 0, 2))
        s.append(text(lgx+20, cy0+33+i*22, l, 10, TEXT))

    # Top open criticals table
    s.append(box(615, a_y, 545, a_h, WHITE, GRAY_DK, 1, 6))
    s.append(text(635, a_y+22, "Top open criticals — by age and tier", 13, NAVY_DK, "start", "bold"))
    cols_h = ["AIID", "Tier", "Finding", "Owner", "Age"]
    col_w = [60, 50, 220, 120, 50]
    th_y = a_y+45; rh2 = 26
    cx = 635
    s.append(box(cx, th_y, sum(col_w), rh2, GRAY_LT, GRAY_DK, 0.5, 0))
    accx = cx
    for i, h in enumerate(cols_h):
        s.append(text(accx+col_w[i]/2, th_y+17, h, 11, NAVY_DK, "middle", "bold"))
        accx += col_w[i]
    rows_data = [
        ("A-1182", "1", "Indirect prompt injection in RAG", "ClinicalCo-Pilot", "11d"),
        ("A-1207", "1", "PHI leak via completion log",     "PriorAuth Bot",   "8d"),
        ("A-1219", "2", "Tool-call confused deputy",       "Schedule Agent",  "6d"),
        ("A-1234", "1", "Pickle RCE in HF model",          "Imaging RAG",     "5d"),
        ("A-1240", "2", "Excessive agency, no rate limit", "Coder Assist",    "3d"),
        ("A-1251", "1", "BAA-bypass egress to OpenAI",     "Patient Comms",   "1d"),
    ]
    for ri, row in enumerate(rows_data):
        ry = th_y + rh2 + ri*rh2
        bg = WHITE if ri % 2 else GRAY_LT
        s.append(box(cx, ry, sum(col_w), rh2, bg, GRAY_DK, 0.3, 0))
        accx = cx
        for ci, val in enumerate(row):
            color = ACCENT if (ci == 1 and val == "1") else TEXT
            weight = "bold" if ci == 1 else "normal"
            s.append(text(accx+col_w[ci]/2, ry+17, val, 11, color, "middle", weight))
            accx += col_w[ci]

    s.append("</svg>")
    return "\n".join(s)

# ============================================================
# DIAGRAM 6: Executive dashboard mockup
# ============================================================
def diagram_6():
    W, H = 1200, 720
    s = [hdr(W, H)]
    s.append(box(0, 0, W, 42, NAVY, NAVY, 0, 0))
    s.append(text(W/2, 27, "Executive Dashboard — for CISO and cyber executive review", 17, WHITE, "middle", "bold"))

    # Top KPI strip
    kpi_y = 70; kpi_h = 110
    kpis = [
        ("Registered AI Assets", "412", "+38 / quarter"),
        ("Tier 1 Coverage", "100%", "all scanned"),
        ("Avoided-harm Demos", "9", "Phase 1 to date"),
        ("Open Critical Risk", "Low", "trending down"),
    ]
    kw = (W-80-3*15)/4
    for i, (a, b, c) in enumerate(kpis):
        x = 40 + i*(kw+15)
        s.append(box(x, kpi_y, kw, kpi_h, NAVY, NAVY_DK, 1, 6))
        s.append(text(x+kw/2, kpi_y+28, a, 13, BLUE, "middle"))
        s.append(text(x+kw/2, kpi_y+72, b, 32, WHITE, "middle", "bold"))
        s.append(text(x+kw/2, kpi_y+98, c, 11, BLUE, "middle"))

    # Risk heatmap (BU x Tier)
    rh_y = 200; rh_h = 240
    s.append(box(40, rh_y, 560, rh_h, WHITE, GRAY_DK, 1, 6))
    s.append(text(60, rh_y+22, "Residual risk heatmap — Business Unit × Tier", 13, NAVY_DK, "start", "bold"))
    bus = ["Clinical", "Imaging", "Pharmacy", "Revenue Cycle", "Care Mgmt", "HR / IT", "Marketing"]
    tiers = ["Tier 1", "Tier 2", "Tier 3", "Tier 4"]
    cell_w = 100; cell_h = 22; cx0 = 180; cy0 = rh_y+55
    # column headers
    for i, t in enumerate(tiers):
        s.append(text(cx0+i*cell_w+cell_w/2, cy0-6, t, 11, NAVY_DK, "middle", "bold"))
    import random; random.seed(3)
    risk_colors = [GREEN_LT, "#F5E0B8", ORANGE_DK, ACCENT]
    for r, bu in enumerate(bus):
        s.append(text(cx0-10, cy0+r*cell_h+15, bu, 11, TEXT, "end"))
        for c in range(len(tiers)):
            v = random.choice([0, 0, 1, 1, 2, 2, 3]) if c < 2 else random.choice([0, 0, 1])
            s.append(f'<rect x="{cx0+c*cell_w}" y="{cy0+r*cell_h}" width="{cell_w-2}" height="{cell_h-2}" fill="{risk_colors[v]}" stroke="{GRAY_DK}" stroke-width="0.3"/>')
            label = ["low", "mod", "elev", "high"][v]
            s.append(text(cx0+c*cell_w+(cell_w-2)/2, cy0+r*cell_h+15, label, 10, NAVY_DK if v < 3 else WHITE, "middle"))
    # legend
    lgy = rh_y+rh_h-30
    for i, (l, c) in enumerate([("Low", risk_colors[0]), ("Moderate", risk_colors[1]), ("Elevated", risk_colors[2]), ("High", risk_colors[3])]):
        x = 60+i*120
        s.append(box(x, lgy, 14, 14, c, GRAY_DK, 0.5, 2))
        s.append(text(x+20, lgy+11, l, 11, TEXT))

    # Trend: vulns intro vs closed
    s.append(box(615, rh_y, 545, rh_h, WHITE, GRAY_DK, 1, 6))
    s.append(text(635, rh_y+22, "Risk introduced vs. risk closed (monthly)", 13, NAVY_DK, "start", "bold"))
    px0 = 645; py0 = rh_y+55; pw = 500; ph = 160
    s.append(f'<line x1="{px0}" y1="{py0+ph}" x2="{px0+pw}" y2="{py0+ph}" stroke="{GRAY_DK}" stroke-width="1"/>')
    s.append(f'<line x1="{px0}" y1="{py0}" x2="{px0}" y2="{py0+ph}" stroke="{GRAY_DK}" stroke-width="1"/>')
    intro = [40, 55, 70, 80, 85, 90, 80, 70, 60, 55, 50]
    closed = [10, 25, 50, 75, 90, 105, 100, 95, 90, 85, 80]
    months = ["M1","M2","M3","M4","M5","M6","M7","M8","M9","M10","M11"]
    bw = pw / (len(intro)*2 + (len(intro)-1))
    gp = bw  # gap between groups
    for i in range(len(intro)):
        gx = px0 + 5 + i*(2*bw + gp)
        ih = intro[i]
        ch = closed[i]
        scale = ph / 120
        s.append(f'<rect x="{gx}" y="{py0+ph-ih*scale}" width="{bw}" height="{ih*scale}" fill="{ACCENT}"/>')
        s.append(f'<rect x="{gx+bw+1}" y="{py0+ph-ch*scale}" width="{bw}" height="{ch*scale}" fill="{GREEN}"/>')
        s.append(text(gx+bw, py0+ph+12, months[i], 9, TEXT_LT, "middle"))
    s.append(box(px0+pw-180, py0-2, 14, 14, ACCENT, ACCENT, 0, 2))
    s.append(text(px0+pw-160, py0+10, "Introduced", 11, TEXT))
    s.append(box(px0+pw-90, py0-2, 14, 14, GREEN, GREEN, 0, 2))
    s.append(text(px0+pw-70, py0+10, "Closed", 11, TEXT))

    # Compliance posture donut + AI portfolio composition
    cy = 460; ch = 240
    s.append(box(40, cy, 380, ch, WHITE, GRAY_DK, 1, 6))
    s.append(text(60, cy+22, "Control coverage — HIPAA / HITRUST", 13, NAVY_DK, "start", "bold"))
    # Donut
    cx_, cy_, R, r = 150, cy+130, 70, 38
    # 78% covered
    import math
    pct = 0.78
    end_angle = -math.pi/2 + 2*math.pi*pct
    sx_, sy_ = cx_+R*math.cos(-math.pi/2), cy_+R*math.sin(-math.pi/2)
    ex_, ey_ = cx_+R*math.cos(end_angle), cy_+R*math.sin(end_angle)
    large = 1 if pct > 0.5 else 0
    s.append(f'<path d="M {cx_} {cy_-R} A {R} {R} 0 {large} 1 {ex_:.2f} {ey_:.2f} L {cx_+r*math.cos(end_angle):.2f} {cy_+r*math.sin(end_angle):.2f} A {r} {r} 0 {large} 0 {cx_} {cy_-r} Z" fill="{GREEN}"/>')
    # remainder (gap)
    s.append(f'<path d="M {ex_:.2f} {ey_:.2f} A {R} {R} 0 {1-large} 1 {cx_} {cy_-R} L {cx_} {cy_-r} A {r} {r} 0 {1-large} 0 {cx_+r*math.cos(end_angle):.2f} {cy_+r*math.sin(end_angle):.2f} Z" fill="{GRAY_LT}"/>')
    s.append(text(cx_, cy_+5, f"{int(pct*100)}%", 26, NAVY_DK, "middle", "bold"))
    s.append(text(cx_, cy_+24, "covered", 11, TEXT_LT, "middle"))
    # legend / breakdown
    lx = 240
    items = [("HIPAA Privacy", 92), ("HIPAA Security", 81), ("HITRUST CSF", 74), ("FDA SaMD readiness", 60)]
    for i, (lab, v) in enumerate(items):
        ly = cy+60 + i*36
        s.append(text(lx, ly+10, lab, 11, TEXT))
        # bar
        s.append(box(lx, ly+15, 130, 10, GRAY_LT, GRAY_DK, 0.3, 4))
        s.append(box(lx, ly+15, 130*v/100, 10, GREEN, GREEN, 0, 4))
        s.append(text(lx+135, ly+24, f"{v}%", 11, TEXT_LT))

    # AI portfolio composition
    s.append(box(435, cy, 360, ch, WHITE, GRAY_DK, 1, 6))
    s.append(text(455, cy+22, "AI portfolio by tier", 13, NAVY_DK, "start", "bold"))
    pie_cx, pie_cy, pieR = 530, cy+130, 75
    tiers_pie = [("Tier 1", 38, ACCENT), ("Tier 2", 92, ORANGE_DK), ("Tier 3", 168, BLUE_DK), ("Tier 4", 114, GREEN)]
    total = sum(v for _, v, _ in tiers_pie)
    angle = -math.pi/2
    for lab, v, c in tiers_pie:
        a = v/total * 2*math.pi
        large = 1 if a > math.pi else 0
        x1 = pie_cx + pieR*math.cos(angle); y1 = pie_cy + pieR*math.sin(angle)
        angle += a
        x2 = pie_cx + pieR*math.cos(angle); y2 = pie_cy + pieR*math.sin(angle)
        s.append(f'<path d="M {pie_cx} {pie_cy} L {x1:.2f} {y1:.2f} A {pieR} {pieR} 0 {large} 1 {x2:.2f} {y2:.2f} Z" fill="{c}"/>')
    # legend
    lx = 645
    for i, (lab, v, c) in enumerate(tiers_pie):
        ly = cy+55 + i*30
        s.append(box(lx, ly, 14, 14, c, c, 0, 2))
        s.append(text(lx+22, ly+12, f"{lab} — {v} apps", 11, TEXT))

    # Top risk concentrations
    s.append(box(810, cy, 350, ch, WHITE, GRAY_DK, 1, 6))
    s.append(text(830, cy+22, "Top 5 risk concentrations", 13, NAVY_DK, "start", "bold"))
    concs = [
        ("ClinicalCo-Pilot", "Tier 1", 95),
        ("PriorAuth Bot",   "Tier 1", 87),
        ("Imaging RAG",     "Tier 1", 72),
        ("Schedule Agent",  "Tier 2", 58),
        ("Patient Comms",   "Tier 1", 55),
    ]
    for i, (n, t, v) in enumerate(concs):
        ly = cy+55 + i*30
        s.append(text(830, ly+12, n, 11, TEXT, "start", "bold"))
        s.append(text(960, ly+12, t, 10, ACCENT if t == "Tier 1" else ORANGE_DK, "start", "bold"))
        s.append(box(830, ly+18, 280, 8, GRAY_LT, GRAY_DK, 0.3, 4))
        s.append(box(830, ly+18, 280*v/100, 8, ACCENT, ACCENT, 0, 4))

    s.append("</svg>")
    return "\n".join(s)

# ============================================================
# DIAGRAM 7: Phase rollout swim lane
# ============================================================
def diagram_7():
    W, H = 1200, 760
    s = [hdr(W, H)]
    s.append(box(0, 0, W, 42, NAVY, NAVY, 0, 0))
    s.append(text(W/2, 27, "Phased Tool & Capability Rollout — five verticals × three phases", 17, WHITE, "middle", "bold"))

    verticals = ["AppSec", "Threat Intel", "Threat Hunt", "Red Team", "SCV"]
    phases = [
        ("Phase 1 (M0–3)", "Modest — existing headcount + PoC tooling"),
        ("Phase 2 (M3–9)",  "Tooling scale-up + selective specialist hire"),
        ("Phase 3 (M9–18)", "Platform-grade, automated, paved-road default"),
    ]
    # content per (vertical, phase)
    content = {
        ("AppSec", 0): ["Prompt-injection Semgrep ruleset", "Llama Guard PoC at gateway", "Paved-road template v0", "ModelScan in CI (Azure Pipelines)"],
        ("AppSec", 1): ["Burp Enterprise API integration", "Custom RAG threat-modeling guide", "Auto-PR remediation for deps", "Healthcare prompt linter v1"],
        ("AppSec", 2): ["Self-service threat-modeling assistant", "Inherited-controls report card", "Continuous SBOM + attestation"],

        ("Threat Intel", 0): ["AI threat feed taxonomy", "Jailbreak intel weekly report", "BAA inventory baseline"],
        ("Threat Intel", 1): ["Adversarial-ML research stream", "Provider-incident watch (Claude, MCP)", "Healthcare-AI TTP catalog"],
        ("Threat Intel", 2): ["Threat-informed scan tuning loop", "Auto-replay of new jailbreaks against assets"],

        ("Threat Hunt", 0): ["Telemetry gap analysis", "First 3 hunt hypotheses (prompt, tool-call, egress)", "Hunt notebook templates"],
        ("Threat Hunt", 1): ["Live agent-action analytics", "Drift detection on jailbreak rate", "Hunt against shadow-AI signals"],
        ("Threat Hunt", 2): ["Continuous hunting on prompt corpus", "Detection-as-code for AI patterns"],

        ("Red Team", 0): ["garak baseline scans", "PyRIT PoC orchestrator", "1 demo red team on a Tier-1 app", "MCP onboarding red-team v0"],
        ("Red Team", 1): ["Healthcare custom probes", "Indirect-injection corpus", "ATLAS coverage tracking", "Tool-abuse fuzz harness"],
        ("Red Team", 2): ["Continuous AI red team campaigns", "Automated re-test on regression", "Adversarial-ML platform (ART)"],

        ("SCV", 0): ["Catalog v2.1 controls vs. AI threat model", "Egress-control validation playbook", "Gateway bypass detection"],
        ("SCV", 1): ["Continuous control validation runner", "Guardrail effectiveness measurement", "Identity & scope validation per agent"],
        ("SCV", 2): ["Self-service control attestation", "Real-time control drift alerts"],
    }

    # Layout
    headw = 130
    chartw = W - 80 - headw
    cw = chartw / 3
    # column headers
    cy_ = 80
    for i, (lab, sub) in enumerate(phases):
        x = 40 + headw + i*cw
        s.append(box(x+6, cy_, cw-12, 50, NAVY, NAVY_DK, 1, 6))
        s.append(text(x+cw/2, cy_+22, lab, 14, WHITE, "middle", "bold"))
        s.append(text(x+cw/2, cy_+40, sub, 11, BLUE, "middle"))
    # phase legend strip
    s.append(box(40, cy_+58, headw-6, 50, GRAY_LT, GRAY_DK, 1, 6))
    s.append(text(40+headw/2-3, cy_+78, "Vertical", 12, NAVY_DK, "middle", "bold"))
    s.append(text(40+headw/2-3, cy_+95, "↓", 14, NAVY_DK, "middle"))

    # rows
    rh = 110
    for r, v in enumerate(verticals):
        y = cy_ + 110 + r*(rh+8)
        s.append(box(40, y, headw-6, rh, NAVY, NAVY_DK, 1, 6))
        s.append(text(40+headw/2-3, y+rh/2+5, v, 13, WHITE, "middle", "bold"))
        for c in range(3):
            x = 40 + headw + c*cw + 6
            items = content[(v, c)]
            color = [BLUE, ORANGE, GREEN_LT][c]
            edge = [BLUE_DK, ORANGE_DK, GREEN][c]
            s.append(box(x, y, cw-12, rh, color, edge, 1, 6))
            for j, it in enumerate(items[:5]):
                s.append(text(x+10, y+18+j*18, "• " + it, 10, TEXT))

    # Bottom note
    s.append(box(40, H-50, W-80, 32, ORANGE, ORANGE_DK, 1, 6))
    s.append(text(60, H-30, "Phase 1 honors v2.1's modesty constraint: no new headcount; demo red team is the asset that earns the Phase 2 ask.", 12, NAVY_DK, "start", "italic"))

    s.append("</svg>")
    return "\n".join(s)


# ============================================================
# Build all
# ============================================================
diagrams = {
    "01_pipeline_overview.svg": diagram_1(),
    "02_v21_mapping.svg": diagram_2(),
    "03_ai_redteam_killchain.svg": diagram_3(),
    "04_vertical_ownership.svg": diagram_4(),
    "05_dashboard_technical.svg": diagram_5(),
    "06_dashboard_executive.svg": diagram_6(),
    "07_phase_rollout.svg": diagram_7(),
}

for fn, content in diagrams.items():
    path = os.path.join(OUT, fn)
    with open(path, "w") as f:
        f.write(content)
    # Also rasterize to PNG (since python-docx can't take SVG natively)
    png = path.replace(".svg", ".png")
    cairosvg.svg2png(bytestring=content.encode(), write_to=png, output_width=1800)
    print(f"  wrote {fn} ({len(content)} chars) + PNG")

print(f"\nAll {len(diagrams)} diagrams built in ./{OUT}/")
