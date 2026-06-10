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
def diagram_1(highlight=False):
    W, H = 1200, 880
    s = [hdr(W, H), arrow_def()]
    # Two highlight sets for the health- variant:
    #   HL      = environment tooling ALREADY in place (orange accent). The whole
    #             "ENTERPRISE SECURITY ENVIRONMENT" band + dashboards are also orange.
    #   HL_NEW  = tools ai-protect INTRODUCES (green accent) — the new SAST/DAST/
    #             AI-red-team/remediation capabilities this brings.
    HL = {"GitHub scan", "Azure Repos scan", "Armis (assets)", "Mend.io (SAST/SCA)",
          "Burp Suite", "Rapid7 InsightVM", "WAF (Palo Alto)", "Teams",
          "Azure Boards / Jira"} if highlight else set()
    GRN = "#1E8E4E"; GRN_FILL = "#D8F0DF"; GRN_TXT = "#15692F"  # new tools introduced by ai-protect
    HL_NEW = {"OPA policy", "Tier scoring",
              "Semgrep", "CodeQL", "Trivy", "ModelScan", "TruffleHog",
              "Nuclei", "ZAP", "Schemathesis",
              "garak", "PyRIT", "ART", "PromptFoo",
              "Auto-PR (AzDO/GH)", "Llama Guard", "NeMo Guard",
              "Telemetry", "Drift det.", "Re-scan cron", "Report card"} if highlight else set()
    # Title strip
    s.append(box(0, 0, W, 44, NAVY, NAVY, 0, 0))
    title = ("AI Security Assurance Pipeline — Environment Tooling Highlighted"
             if highlight else "AI Security Assurance Pipeline — End-to-End")
    s.append(text(W/2, 28, title, 18, WHITE, "middle", "bold"))
    if highlight:
        s.append(text(40, 65, "KEY:", 11, TEXT, "start", "bold"))
        s.append(box(80, 54, 14, 13, GRN_FILL, GRN, 1.4, 2))
        s.append(text(100, 65, "New tools introduced with ai-protect", 11, TEXT, "start"))
        s.append(box(380, 54, 14, 13, ORANGE, ACCENT, 1.4, 2))
        s.append(text(400, 65, "Existing systems for integration", 11, TEXT, "start"))
        s.append(text(W-40, 65, "within a stage: grouped by category, not sequential", 9, TEXT_LT, "end"))

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
        ["ServiceNow", "CASB egress", "Azure Repos scan", "GitHub scan", "Armis (assets)"],
        ["OPA policy", "CMDB tag", "Tier scoring"],
        ["Semgrep", "CodeQL", "Trivy", "ModelScan", "TruffleHog", "Mend.io (SAST/SCA)"],
        ["Burp Suite", "Nuclei", "ZAP", "Schemathesis", "Rapid7 InsightVM"],
        ["garak", "PyRIT", "ART", "PromptFoo"],
        ["Auto-PR (AzDO/GH)", "WAF (Palo Alto)", "Llama Guard", "NeMo Guard"],
        ["Telemetry", "Drift det.", "Re-scan cron"],
        ["Slack", "Teams", "Azure Boards / Jira", "Report card"],
    ]
    ty0 = 195; tslot = 22; ggap = 7
    def _grp(it):                        # green (new) -> orange (existing) -> plain
        return 0 if it in HL_NEW else (1 if it in HL else 2)
    box_bottoms = []
    for i, items in enumerate(tools):
        x = sx0 + i*(sw+gap)
        if highlight:                    # group chips by category for a cleaner read
            items = sorted(items, key=_grp)
        ntrans = sum(1 for k in range(1, len(items)) if _grp(items[k]) != _grp(items[k-1])) if highlight else 0
        bh = len(items)*tslot + 14 + ntrans*ggap
        box_bottoms.append(ty0 + bh)
        s.append(box(x, ty0, sw, bh, WHITE, GRAY_DK, 1, 4))
        yoff = 0; prev = None
        for j, it in enumerate(items):
            if highlight and prev is not None and _grp(it) != prev:
                yoff += ggap            # small gap between category groups
            prev = _grp(it)
            yy = ty0 + 18 + j*tslot + yoff
            if it in HL:                 # already in place — orange
                s.append(box(x+5, yy-13, sw-10, 18, ORANGE, ACCENT, 1, 3))
                tcol, tw = ACCENT, "bold"
            elif it in HL_NEW:           # introduced by ai-protect — green
                s.append(box(x+5, yy-13, sw-10, 18, GRN_FILL, GRN, 1, 3))
                tcol, tw = GRN_TXT, "bold"
            else:
                tcol, tw = TEXT, "normal"
            s.append(text(x+sw/2, yy, it, 11, tcol, "middle", tw))

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

    # Enterprise security environment (Microsoft-aligned) — the stack the pipeline plugs into.
    # Entirely provided-tooling, so the whole band is accent-highlighted in the health- variant.
    ey = 635; eh = 110
    s.append(box(40, ey, W-80, eh, "#243B55", ACCENT if highlight else NAVY_DK, 2.5 if highlight else 1.5, 8))
    s.append(text(60, ey+24, "ENTERPRISE SECURITY ENVIRONMENT  (Microsoft-aligned)"
                  + ("   ★ provided environment tooling" if highlight else ""), 13, WHITE, "start", "bold"))
    env = [
        ("Endpoint / XDR", "Microsoft Defender"),
        ("SIEM / SOAR", "Microsoft Sentinel"),
        ("Threat Intel", "Google TI · OpenCTI · MS Defender TI"),
        ("Email Security", "Abnormal"),
        ("Network / Cloud", "Palo Alto NGFW / Prisma"),
        ("AI Surfaces", "M365 / GitHub Copilot"),
        ("Collaboration", "Microsoft Teams"),
    ]
    ew = (W-120)/len(env); ex0 = 60
    sb_fill = ORANGE if highlight else "#2C547F"
    sb_edge = ACCENT if highlight else "#456A92"
    a_col = ACCENT if highlight else WHITE
    b_col = TEXT if highlight else BLUE
    for i, (a, b) in enumerate(env):
        x = ex0 + i*ew
        s.append(box(x+5, ey+38, ew-10, 60, sb_fill, sb_edge, 2 if highlight else 1, 5))
        s.append(text(x+ew/2, ey+57, a, 11, a_col, "middle", "bold"))
        # wrap the vendor sub-label to up to 2 lines inside the box
        words = b.split(" "); lines = []; cur = ""
        for w in words:
            if len(cur) + len(w) + 1 > 20:
                lines.append(cur); cur = w
            else:
                cur = (cur + " " + w).strip()
        if cur:
            lines.append(cur)
        for k, ln in enumerate(lines[:2]):
            s.append(text(x+ew/2, ey+74+k*13, ln, 9, b_col, "middle"))

    # Output layer (dashboards)
    dy = 765; dh = 80
    cards = [("Technical Dashboard", "Grafana — coverage, MTTR, jailbreak rate, ATLAS heatmap"),
             ("Executive Dashboard", "Superset/Power BI — risk heatmap, portfolio KPIs, compliance"),
             ("Compliance Evidence", "HIPAA / HITRUST control mapping, audit query")]
    cw = (W-80-2*15)/3; cx0 = 40
    dash_hl = {"Technical Dashboard", "Executive Dashboard"} if highlight else set()
    for i, (a, b) in enumerate(cards):
        x = cx0 + i*(cw+15)
        chl = a in dash_hl
        s.append(box(x, dy, cw, dh, ORANGE if chl else BLUE, ACCENT if chl else BLUE_DK, 2.5 if chl else 1.5, 6))
        s.append(text(x+cw/2, dy+24, a, 13, ACCENT if chl else NAVY_DK, "middle", "bold"))
        s.append(text(x+cw/2, dy+50, b, 11, TEXT, "middle"))

    # Connector lines from stages to orchestrator
    for i in range(len(stages)):
        x = sx0 + i*(sw+gap) + sw/2
        s.append(f'<line x1="{x}" y1="{box_bottoms[i]}" x2="{x}" y2="{oy}" stroke="{GRAY_DK}" stroke-width="1" stroke-dasharray="3 3"/>')
    # Connectors orchestrator -> infra
    for i in range(len(parts)):
        x = px0 + i*pw + pw/2
        s.append(f'<line x1="{x}" y1="{oy+oh}" x2="{x}" y2="{iy}" stroke="{GRAY_DK}" stroke-width="1" stroke-dasharray="3 3"/>')
    # infra -> enterprise environment band
    for i in range(len(env)):
        x = ex0 + i*ew + ew/2
        s.append(f'<line x1="{x}" y1="{iy+ih}" x2="{x}" y2="{ey}" stroke="{GRAY_DK}" stroke-width="1" stroke-dasharray="3 3"/>')
    # enterprise band -> dashboards
    for i in range(3):
        x = cx0 + i*(cw+15) + cw/2
        s.append(f'<line x1="{x}" y1="{ey+eh}" x2="{x}" y2="{dy}" stroke="{GRAY_DK}" stroke-width="1" stroke-dasharray="3 3"/>')

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
# DIAGRAM 8: Empowered AI building on the ai-protect paved road
# ============================================================
def diagram_8():
    W, H = 1240, 766
    PURPLE = "#6D52C9"; PURPLE_LT = "#ECE6FA"
    s = [hdr(W, H), arrow_def()]
    s.append('<defs>'
             '<marker id="arrG" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#3D8C5C"/></marker>'
             '<marker id="arrAm" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#E0A555"/></marker>'
             '<marker id="arrP" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#6D52C9"/></marker>'
             '</defs>')
    # Title + subtitle
    s.append(box(0, 0, W, 50, NAVY, NAVY, 0, 0))
    s.append(text(W/2, 22, "The Paved Road: Empowered AI Building, Governed by ai-protect", 17, WHITE, "middle", "bold"))
    s.append(text(W/2, 40, "Citizen builders take an idea to production with Claude — ai-protect auto-scans every SDLC stage and escalates to a human only when the risk tier earns it.   “Paved road > gates.”", 10, BLUE, "middle"))

    margin = 18; lane_w = 192; flow_x0 = margin + lane_w + 6
    flow_w = W - margin - flow_x0
    ncol = 6; col_w = flow_w/ncol
    col_names = ["IDEA", "BUILD WITH AI", "INTAKE + TIER", "SCAN  SAST/DAST/AI-RT", "GATE / APPROVE", "DEPLOY + MONITOR"]
    def cx(c):
        return flow_x0 + c*col_w + col_w/2

    # Column header strip + faint column separators down through the lanes
    chy = 58; chh = 20; sep_bottom = 560
    for c in range(ncol):
        x = flow_x0 + c*col_w
        s.append(box(x+2, chy, col_w-4, chh, GRAY_LT, GRAY, 1, 4))
        s.append(text(x+col_w/2, chy+14, col_names[c], 8.5, NAVY_DK, "middle", "bold"))
        if c > 0:
            s.append(f'<line x1="{flow_x0+c*col_w}" y1="{chy+chh+2}" x2="{flow_x0+c*col_w}" y2="{sep_bottom}" stroke="{GRAY}" stroke-width="1" stroke-dasharray="2 5"/>')

    # Persona / actor swimlanes
    lanes = [
        ("Citizen Builder", "non-dev employee", "#F7F9FB", 80, 104, "#2C547F"),
        ("AppSec / Security", "human — Tier 1-2 only", "#FCF3E6", 188, 104, "#9C6A1E"),
        ("Platform & AI Gov", "owns the paved road", "#EEF4FA", 296, 104, "#2C547F"),
        ("ai-protect automation", "auto — no human", "#E7F3EB", 404, 156, "#2E6B45"),
    ]
    for (ttl, sub, bg, y, h, lab) in lanes:
        s.append(box(margin, y, W-2*margin, h, bg, GRAY, 1, 6))
        s.append(box(margin, y, lane_w, h, lab, NAVY_DK, 1, 6))
        s.append(text(margin+lane_w/2, y+h/2-3, ttl, 11, WHITE, "middle", "bold"))
        s.append(text(margin+lane_w/2, y+h/2+13, sub, 8.5, "#E6EEF6", "middle"))
    s.append(box(margin, 404, W-2*margin, 156, "none", GREEN, 2.5, 6))  # accent the guardrail lane

    def wrap(t, n):
        words = t.split(" "); lines = []; cur = ""
        for w in words:
            if len(cur)+len(w)+1 > n:
                lines.append(cur); cur = w
            else:
                cur = (cur+" "+w).strip()
        if cur:
            lines.append(cur)
        return lines

    def node(c, y, h, label, sub, emph, lane="other", span=1):
        w = col_w*0.88 + (span-1)*col_w
        x = cx(c) + (span-1)*col_w/2
        if emph == "gate":
            fill, edge, tcol = (ORANGE, ORANGE_DK, "#5a3d08") if lane == "appsec" else (GREEN_LT, GREEN, "#1c3a26")
        elif emph == "ai":
            fill, edge, tcol = PURPLE_LT, PURPLE, "#2a1f55"
        elif emph == "highlight":
            fill, edge, tcol = ORANGE, ACCENT, ACCENT
        else:
            fill, edge, tcol = WHITE, GRAY_DK, TEXT
        sw = 2 if emph in ("gate", "highlight") else 1.2
        s.append(box(x-w/2, y, w, h, fill, edge, sw, 5))
        ly = y+17
        for ln in wrap(label, 20)[:2]:
            s.append(text(x, ly, ln, 10, tcol, "middle", "bold")); ly += 12
        for ln in wrap(sub, 30)[:2]:
            s.append(text(x, ly+1, ln, 7.5, TEXT_LT, "middle")); ly += 10
        return x

    # --- Citizen Builder lane ---
    by = 100; bh = 64
    node(0, by, bh, "Idea / business need", "automation · app · agent · SaaS replacement", "highlight")
    node(1, by, bh, "Build with Claude", "+ Copilot · paved-road template", "ai")
    node(2, by, bh, "Fill scan manifest", "open Azure DevOps PR", "normal")
    node(3, by, bh, "Fix from findings card", "apply auto-change · re-push", "normal")
    node(5, by, bh, "Self-serve deploy", "Tier 3-4 · no human in the loop", "normal")

    # --- AppSec / Security lane (only where risk earns a human) ---
    ay = 208; ah = 64
    s.append(text(cx(1), ay+30, "no human gate on most of the road", 9, TEXT_LT, "middle", "italic"))
    node(3, ay, ah, "Manual AI red team", "forced for Tier 1-2", "normal", "appsec")
    node(4, ay, ah, "Approve / reject change", "human OR automated-policy approval · Teams", "gate", "appsec")
    node(5, ay, ah, "Triage Defender/Sentinel", "act on prod signal", "normal", "appsec")

    # --- Platform & AI Governance lane ---
    gy = 316; gh = 64
    node(0, gy, gh, "Paved-road templates", "blessed starting points", "normal")
    node(1, gy, gh, "Sanctioned LLM gateway", "Claude primary + Copilot", "ai")
    node(2, gy, gh, "Tier policy + manifest schema", "PHI / clinical / external → Tier 1", "normal")
    node(5, gy, gh, "Sanctioned deploy ring", "only approved builds released", "gate")

    # --- ai-protect automation lane (8-stage pipeline, every commit) ---
    r1 = 424; r2 = 492; rh = 60
    s.append(text(cx(0), 474, "8-stage pipeline runs", 9, "#2E6B45", "middle", "bold"))
    s.append(text(cx(0), 487, "on every commit  →", 9, "#2E6B45", "middle", "bold"))
    node(2, r1, rh, "Discovery / Intake", "manifest validator · G1", "gate")
    node(2, r2, rh, "Triage → Tier 1-4", "app RISK tier (1=highest) · ★ FORK", "highlight")
    node(3, r1, rh, "Static SAST + secrets", "blocks Critical / High findings · G2", "gate")
    node(3, r2, rh, "Dynamic DAST + AI Red Team", "blocks Critical / High · garak/PyRIT · G3", "gate")
    node(4, r1, rh, "Auto-remediate", "findings → proposed changes", "ai")
    node(4, r2, rh, "Tier 3-4 auto-approve", "all blocking pass · G4", "gate")
    node(5, r1, rh*2+8, "Continuous monitoring + Reporting", "re-tier on drift / KEV intel · audit trail", "highlight")

    # --- Foundation strip ---
    fy = 580; fh = 78
    s.append(box(margin, fy, W-2*margin, fh, "#EDF0F4", NAVY_DK, 1.2, 6))
    s.append(text(margin+12, fy+16, "MICROSOFT & SANCTIONED AI RAILS   (the paved infrastructure — using it IS the enforcement)", 10, NAVY_DK, "start", "bold"))
    found = [("MCP farm + agent runtime", "vetted tools · sandboxed"),
             ("Azure DevOps Repos / Boards / Pipelines", "manifest in · CI gates run here"),
             ("Defender + Sentinel", "runtime telemetry"),
             ("Microsoft Teams", "approvals + alerts")]
    fw = (W-2*margin-24)/4
    for i, (a, b) in enumerate(found):
        x = margin+12 + i*fw
        s.append(box(x+4, fy+26, fw-8, fh-34, WHITE, "#456A92", 1, 5))
        s.append(text(x+fw/2, fy+44, a, 9, NAVY_DK, "middle", "bold"))
        s.append(text(x+fw/2, fy+58, b, 7.5, TEXT_LT, "middle"))

    # --- Flow arrows ---
    bm = by+bh/2  # builder mid
    for a, b in [(0, 1), (1, 2), (2, 3)]:
        s.append(f'<line x1="{cx(a)+col_w*0.45}" y1="{bm}" x2="{cx(b)-col_w*0.45}" y2="{bm}" stroke="{NAVY}" stroke-width="1.6" marker-end="url(#arr)"/>')
    # handoff DOWN: builder manifest (c2) -> ai-protect intake
    s.append(f'<line x1="{cx(2)}" y1="{by+bh}" x2="{cx(2)}" y2="{r1}" stroke="{GRAY_DK}" stroke-width="1.4" stroke-dasharray="4 3" marker-end="url(#arr)"/>')
    # remediation UP: ai-protect auto-remediate (c4) -> builder fix (c3)
    s.append(f'<path d="M {cx(4)} {r1} C {cx(4)} 300, {cx(3)} 300, {cx(3)} {by+bh}" fill="none" stroke="{PURPLE}" stroke-width="1.5" stroke-dasharray="4 3" marker-end="url(#arrP)"/>')
    # TIER FORK (gate column): green auto straight to deploy; amber human up to AppSec
    s.append(f'<path d="M {cx(4)+col_w*0.36} {r2+rh/2} C {cx(5)-col_w*0.15} {r2+rh/2}, {cx(5)} 360, {cx(5)} {by+bh}" fill="none" stroke="{GREEN}" stroke-width="2.2" marker-end="url(#arrG)"/>')
    s.append(f'<line x1="{cx(4)}" y1="{r1}" x2="{cx(4)}" y2="{ay+ah}" stroke="{ORANGE_DK}" stroke-width="2.2" marker-end="url(#arrAm)"/>')
    s.append(f'<path d="M {cx(4)+col_w*0.4} {ay+ah/2} C {cx(5)-col_w*0.1} {ay+ah/2}, {cx(5)} 300, {cx(5)} {gy}" fill="none" stroke="{ORANGE_DK}" stroke-width="1.6" marker-end="url(#arrAm)"/>')
    # continuous-validation loop-back: monitor (c5) -> triage (c2)
    s.append(f'<path d="M {cx(5)} 560 V 570 H {cx(2)} V {r2+rh}" fill="none" stroke="{GREEN}" stroke-width="1.6" stroke-dasharray="5 3" marker-end="url(#arrG)"/>')
    s.append(text((cx(2)+cx(5))/2, 567, "↺ continuous validation — re-tier on drift / new KEV intel", 8.5, "#2E6B45", "middle", "bold"))

    # --- Legend (auto-wraps to a second row if needed) ---
    ly = 676
    s.append(text(margin, ly+12, "Legend:", 9, TEXT, "start", "bold"))
    leg = [(GREEN_LT, GREEN, "AUTO gate — machine-enforced"),
           (GREEN_LT, GREEN, "Severity gate — auto-blocks Critical/High findings (G2/G3)"),
           (ORANGE, ORANGE_DK, "Human / auto-policy approval — Tier 1-2"),
           (PURPLE_LT, PURPLE, "AI surface (Claude / Copilot)"),
           (ORANGE, ACCENT, "key callout / tier fork")]
    lx = margin + 52; row = 0
    for fill, edge, lab in leg:
        w_est = 32 + len(lab)*5.3
        if lx + w_est > W - margin:
            row += 1; lx = margin + 52
        yy = ly + row*18
        s.append(box(lx, yy+3, 14, 11, fill, edge, 1.4, 2))
        s.append(text(lx+19, yy+12, lab, 9, TEXT, "start"))
        lx += w_est
    s.append(text(margin, ly + (row+1)*18 + 12, "Rows = WHO acts (Builder · AppSec · Governance · ai-protect)", 9, TEXT_LT, "start"))

    # --- Tier key (app risk tier that drives the fork) ---
    tky = ly + (row+2)*18 + 6
    s.append(box(margin, tky, W-2*margin, 20, GRAY_LT, GRAY, 1, 4))
    s.append(text(margin+8, tky+14, "TIER = app risk, drives the fork:", 9, NAVY_DK, "start", "bold"))
    s.append(text(margin+200, tky+14,
                  "1 = PHI / clinical / external-facing (highest)   ·   2 = sensitive internal action / write-back   ·   "
                  "3 = internal advisory, broad reach   ·   4 = low-impact assistive (lowest)", 9, TEXT, "start"))

    s.append("</svg>")
    return "\n".join(s)


# ============================================================
# DIAGRAM: health-01 presentation variant (high-level deck)
# ============================================================
def diagram_health_presentation():
    DY = 18
    W, H = 1200, 808
    s = [hdr(W, H), arrow_def()]
    FB = "#7A3FB5"  # continuous-feedback loop colour
    s.append(f'<defs><marker id="arrFb2" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="{FB}"/></marker></defs>')
    GRN = "#1E8E4E"; GRN_FILL = "#D8F0DF"; GRN_TXT = "#15692F"
    # human-in-the-loop levels: (border, fill, label)
    LV = {
        "auto":      ("#1E8E4E", "#D8F0DF", "AUTOMATED"),
        "optional":  ("#C77D11", "#FBEBD2", "HUMAN OPTIONAL"),
        "mandatory": ("#B0392B", "#F6DAD5", "HUMAN REQUIRED"),
    }
    HL = {"GitHub scan", "Azure Repos scan", "Armis (assets)", "Mend.io (SAST/SCA)",
          "Burp Suite", "Rapid7 InsightVM", "WAF (Palo Alto)", "Teams",
          "Azure Boards", "Jira", "Mend", "Burp"}            # existing — orange
    HL_NEW = {"OPA policy", "Tier scoring", "Semgrep", "CodeQL", "Trivy", "ModelScan",
              "TruffleHog", "Nuclei", "ZAP", "Schemathesis", "garak", "PyRIT", "ART",
              "PromptFoo", "Auto-PR (AzDO/GH)", "Llama Guard", "NeMo Guard",
              "Telemetry", "Drift det.", "Re-scan cron", "Report card"}   # new — green

    def _grp(it):    # orange (existing) at TOP -> green (new) -> plain at BOTTOM (e.g. CMDB tag)
        return 0 if it in HL else (1 if it in HL_NEW else 2)

    # ---- title + legends ----
    s.append(box(0, 0, W, 44, NAVY, NAVY, 0, 0))
    s.append(text(W/2, 27, "AI Security Assurance Pipeline — Tooling, Automation & New Stages",
                  17, WHITE, "middle", "bold"))
    # single legend line: tooling key + NEW-stage badge + human-in-the-loop
    y0 = 62; swy = 52
    lx = 40
    s.append(text(lx, y0, "KEY:", 10, TEXT, "start", "bold")); lx += 36
    s.append(box(lx, swy, 13, 12, ORANGE, ACCENT, 1.4, 2))
    s.append(text(lx+18, y0, "Existing", 10, TEXT, "start")); lx += 18 + 8*6.2 + 8
    s.append(box(lx, swy, 13, 12, GRN_FILL, GRN, 1.4, 2))
    s.append(text(lx+18, y0, "New tool", 10, TEXT, "start")); lx += 18 + 8*6.2 + 10
    s.append(box(lx, swy-1, 28, 14, GRN, GRN, 1, 3))
    s.append(text(lx+14, y0, "NEW", 8, WHITE, "middle", "bold"))
    s.append(text(lx+32, y0, "= new stage", 10, TEXT, "start")); lx += 32 + 11*6.2 + 20
    s.append(text(lx, y0, "HUMAN-IN-THE-LOOP:", 10, TEXT, "start", "bold")); lx += 18*6.6 + 10
    for lvl, lab in (("auto", "Automated"), ("optional", "Human optional"),
                     ("mandatory", "Human required")):
        bd, fl, _ = LV[lvl]
        s.append(box(lx, swy, 14, 12, fl, bd, 1.6, 3))
        s.append(text(lx+19, y0, lab, 10, TEXT, "start"))
        lx += 19 + len(lab)*5.9 + 12

    # ---- stages (with NEW badge + human-in-the-loop pill) ----
    stages = [("Stage 0", "Discovery &", "Intake"), ("Stage 1", "Triage &", "Tiering"),
              ("Stage 2", "Pre-Prod", ""), ("Stage 3", "Dynamic", "AppSec"),
              ("Stage 4", "AI", "Red Team"), ("Stage 5", "Remediation", ""),
              ("Stage 6", "Continuous", "Monitoring"), ("Stage 7", "Reporting &", "Notification")]
    # Stage 5 is tier-gated: human required (Tier 1-2) OR optional/auto (Tier 3-4) → show both.
    auto_by_stage = ["auto", "auto", "auto", "auto", "optional",
                     ["mandatory", "optional"], "auto", "auto"]
    new_stages = {1, 4, 6}
    sw = 130; sh = 96; sx0 = 40; sy = 80 + DY; gap = 12
    for i, (lab, l1, l2) in enumerate(stages):
        x = sx0 + i*(sw+gap)
        s.append(box(x, sy, sw, sh, BLUE, NAVY, 1.5, 6))
        s.append(text(x+sw/2, sy+23, lab, 16, NAVY_DK, "middle", "bold"))   # Stage N — largest in box
        if l2:
            s.append(text(x+sw/2, sy+43, l1, 12, TEXT, "middle", "bold"))
            s.append(text(x+sw/2, sy+58, l2, 12, TEXT, "middle", "bold"))
        else:                                    # single-word stage — center it on one line
            s.append(text(x+sw/2, sy+51, l1, 12, TEXT, "middle", "bold"))
        if i in new_stages:                                  # NEW badge (top-left)
            s.append(box(x+4, sy+4, 32, 14, GRN, GRN, 1, 3))
            s.append(text(x+20, sy+14, "NEW", 9, WHITE, "middle", "bold"))
        levels = auto_by_stage[i]                            # human-in-the-loop pill(s) (bottom)
        if isinstance(levels, str):
            levels = [levels]
        SHORT = {"AUTOMATED": "AUTOMATED", "HUMAN OPTIONAL": "OPTIONAL", "HUMAN REQUIRED": "REQUIRED"}
        pwid = (sw-14)/len(levels)
        for pi, lvl in enumerate(levels):
            bd, fl, plab = LV[lvl]
            px = x+7 + pi*pwid
            split = len(levels) > 1
            s.append(box(px, sy+74, pwid-(2 if split else 0), 15, fl, bd, 1.4, 3))
            lab = SHORT[plab] if split else plab
            s.append(text(px+(pwid-(2 if split else 0))/2, sy+85, lab,
                          7 if split else 7.5, bd, "middle", "bold"))
        if i < len(stages)-1:
            s.append(f'<line x1="{x+sw+1}" y1="{sy+sh/2}" x2="{x+sw+gap-1}" y2="{sy+sh/2}" '
                     f'stroke="{NAVY}" stroke-width="2" marker-end="url(#arr)"/>')

    # ---- continuous production-assurance feedback loop (over the stage row) ----
    # AI red-team / SAST / DAST keep running against ai-production and reopen the 7 stages.
    sx0_ = sx0; x0c = sx0 + sw/2; x7c = sx0 + 7*(sw+gap) + sw/2; fly = sy - 14
    s.append(f'<path d="M {x7c} {sy-1} L {x7c} {fly} L {x0c} {fly} L {x0c} {sy-1}" '
             f'fill="none" stroke="{FB}" stroke-width="2.3" stroke-dasharray="7 4" marker-end="url(#arrFb2)"/>')
    s.append(text(W/2, fly-6, "CONTINUOUS PRODUCTION ASSURANCE — AI red-team · SAST · DAST re-test ai-production and reopen Stage 0–7",
                  10.5, FB, "middle", "bold"))

    # ---- tool layer (orange top / green bottom) ----
    tools = [
        ["ServiceNow", "Azure Repos scan", "GitHub scan", "Armis (assets)"],            # 0 (no CASB)
        ["OPA policy", "CMDB tag", "Tier scoring"],                                      # 1
        ["Semgrep", "CodeQL", "Trivy", "ModelScan", "TruffleHog", "Mend.io (SAST/SCA)"], # 2
        ["Burp Suite", "Nuclei", "ZAP", "Schemathesis", "Rapid7 InsightVM"],            # 3
        ["garak", "PyRIT", "ART", "PromptFoo"],                                          # 4
        ["Auto-PR (AzDO/GH)", "WAF (Palo Alto)", "Llama Guard", "NeMo Guard"],           # 5
        ["Telemetry", "Drift det.", "Re-scan cron", "Mend", "Burp"],                     # 6 (+Mend,Burp)
        ["Teams", "Azure Boards", "Jira", "Report card"],                                # 7 (no Slack; split)
    ]
    ty0 = 195 + DY; tslot = 22; ggap = 7
    box_bottoms = []
    for i, items in enumerate(tools):
        x = sx0 + i*(sw+gap)
        items = sorted(items, key=_grp)
        ntrans = sum(1 for k in range(1, len(items)) if _grp(items[k]) != _grp(items[k-1]))
        bh = len(items)*tslot + 14 + ntrans*ggap
        box_bottoms.append(ty0 + bh)
        s.append(box(x, ty0, sw, bh, WHITE, GRAY_DK, 1, 4))
        yoff = 0; prev = None
        for j, it in enumerate(items):
            if prev is not None and _grp(it) != prev:
                yoff += ggap
            prev = _grp(it)
            yy = ty0 + 18 + j*tslot + yoff
            if it in HL:
                s.append(box(x+5, yy-13, sw-10, 18, ORANGE, ACCENT, 1, 3)); tc, tw = ACCENT, "bold"
            elif it in HL_NEW:
                s.append(box(x+5, yy-13, sw-10, 18, GRN_FILL, GRN, 1, 3)); tc, tw = GRN_TXT, "bold"
            else:
                tc, tw = TEXT, "normal"
            s.append(text(x+sw/2, yy, it, 11, tc, "middle", tw))

    # ---- orchestration / infra / enterprise band / dashboards (shifted by DY) ----
    oy = 382; oh = 90   # navy band (same scheme as Sanctioned), pulled up under the tool boxes
    s.append(box(40, oy, W-80, oh, NAVY, NAVY_DK, 1.5, 8))
    s.append(text(W/2, oy+24, "ORCHESTRATION & DATA PLANE", 13, WHITE, "middle", "bold"))
    # Azure Pipelines is available today (existing) -> orange pill like the workflow items;
    # the rest is new ai-protect orchestration -> navy sub-boxes.
    orch = [("Azure Pipelines", "CI — available today", True), ("Argo / Tekton", "pipeline CI", False),
            ("Kafka", "event bus", False), ("DefectDojo", "findings · OCSF", False),
            ("Vault / Key Vault", "secrets", False), ("OPA", "deploy gates", False)]
    ow = (W-120)/len(orch); ox0 = 60
    for i, (a, b, existing) in enumerate(orch):
        x = ox0 + i*ow
        if existing:
            s.append(box(x+5, oy+38, ow-10, 42, ORANGE, ACCENT, 2, 5))
            s.append(text(x+ow/2, oy+56, a, 11, ACCENT, "middle", "bold"))
            s.append(text(x+ow/2, oy+72, b, 10.5, TEXT, "middle", "bold"))
        else:
            s.append(box(x+5, oy+38, ow-10, 42, "#2C547F", "#456A92", 1, 5))
            s.append(text(x+ow/2, oy+56, a, 11, WHITE, "middle", "bold"))
            s.append(text(x+ow/2, oy+72, b, 10.5, "#DCEBFA", "middle", "bold"))

    iy = 484; ih = 90
    s.append(box(40, iy, W-80, ih, NAVY, NAVY_DK, 1.5, 8))
    s.append(text(W/2, iy+24, "SANCTIONED AI INFRASTRUCTURE  (anchored on v2.1 Operating Model)", 13, WHITE, "middle", "bold"))
    parts = [("LLM Gateway", ["Claude primary", "+ secondary LLM"]), ("MCP Farm", ["curated registry"]),
             ("Agent Runtime", ["SPIFFE ID, scoped"]), ("Data Plane", ["FHIR / vector / RAG"]),
             ("Telemetry Mesh", ["prompts • tools • completions"])]
    pw = (W-120)/len(parts); px0 = 60
    for i, (a, subs) in enumerate(parts):
        x = px0 + i*pw
        s.append(box(x+5, iy+38, pw-10, 42, "#2C547F", "#456A92", 1, 5))
        s.append(text(x+pw/2, iy+54, a, 12, WHITE, "middle", "bold"))
        for k, sub in enumerate(subs[:2]):
            s.append(text(x+pw/2, iy+68+k*12, sub, 11, "#DCEBFA", "middle", "bold"))

    ey = 586; eh = 110
    s.append(box(40, ey, W-80, eh, "#243B55", ACCENT, 2.5, 8))
    s.append(text(W/2, ey+24, "ENTERPRISE SECURITY ENVIRONMENT  (Microsoft-aligned)   ★ provided environment tooling", 13, WHITE, "middle", "bold"))
    env = [("Endpoint / XDR", "Microsoft Defender"), ("SIEM / SOAR", "Microsoft Sentinel"),
           ("Threat Intel", "Google TI · OpenCTI · MS Defender TI"), ("Email Security", "Abnormal"),
           ("Network / Cloud", "Palo Alto NGFW / Prisma"), ("AI Surfaces", "Claude · Copilot"),
           ("Collaboration", "Microsoft Teams")]
    ew = (W-120)/len(env); ex0 = 60
    for i, (a, b) in enumerate(env):
        x = ex0 + i*ew
        s.append(box(x+5, ey+38, ew-10, 60, ORANGE, ACCENT, 2, 5))
        s.append(text(x+ew/2, ey+57, a, 11, ACCENT, "middle", "bold"))
        words = b.split(" "); lines = []; cur = ""
        for w in words:
            if len(cur)+len(w)+1 > 20:
                lines.append(cur); cur = w
            else:
                cur = (cur+" "+w).strip()
        if cur:
            lines.append(cur)
        for k, ln in enumerate(lines[:2]):
            s.append(text(x+ew/2, ey+74+k*13, ln, 10, "#3a2a14", "middle", "bold"))

    dy = 710; dh = 80
    # dark-blue cards (same scheme as the bands); Power BI is existing -> orange pill.
    cards = [("Technical Dashboard", "Grafana — coverage, MTTR, jailbreak rate, ATLAS heatmap", None),
             ("Executive Dashboard", "risk heatmap, portfolio KPIs, compliance", "Power BI"),
             ("Compliance Evidence", "HIPAA / HITRUST control mapping, audit query", None)]
    cw = (W-80-2*15)/3; cx0 = 40
    for i, (a, b, existing) in enumerate(cards):
        x = cx0 + i*(cw+15)
        s.append(box(x, dy, cw, dh, NAVY, NAVY_DK, 1.5, 6))
        s.append(text(x+cw/2, dy+22, a, 13, WHITE, "middle", "bold"))
        if existing:
            s.append(box(x+cw/2-36, dy+32, 72, 16, ORANGE, ACCENT, 1.5, 3))
            s.append(text(x+cw/2, dy+43, existing, 10, ACCENT, "middle", "bold"))
            s.append(text(x+cw/2, dy+63, b, 11, "#DCEBFA", "middle", "bold"))
        else:
            s.append(text(x+cw/2, dy+48, b, 11, "#DCEBFA", "middle", "bold"))

    # ---- connectors ----
    for i in range(len(stages)):
        x = sx0 + i*(sw+gap) + sw/2
        s.append(f'<line x1="{x}" y1="{box_bottoms[i]}" x2="{x}" y2="{oy}" stroke="{GRAY_DK}" stroke-width="1" stroke-dasharray="3 3"/>')
    for i in range(len(parts)):
        x = px0 + i*pw + pw/2
        s.append(f'<line x1="{x}" y1="{oy+oh}" x2="{x}" y2="{iy}" stroke="{GRAY_DK}" stroke-width="1" stroke-dasharray="3 3"/>')
    for i in range(len(env)):
        x = ex0 + i*ew + ew/2
        s.append(f'<line x1="{x}" y1="{iy+ih}" x2="{x}" y2="{ey}" stroke="{GRAY_DK}" stroke-width="1" stroke-dasharray="3 3"/>')
    for i in range(3):
        x = cx0 + i*(cw+15) + cw/2
        s.append(f'<line x1="{x}" y1="{ey+eh}" x2="{x}" y2="{dy}" stroke="{GRAY_DK}" stroke-width="1" stroke-dasharray="3 3"/>')

    s.append("</svg>")
    return "\n".join(s)


# ============================================================
# DIAGRAM: AI organizational transformation (presentation)
# ============================================================
def diagram_ai_transformation():
    W, H = 1280, 568
    s = [hdr(W, H), arrow_def()]
    GRN = "#1E8E4E"; GRN_FILL = "#D8F0DF"; GRN_TXT = "#15692F"
    PROD = "#13643A"; PROD_FILL = "#DCF0E4"
    FB = "#7A3FB5"  # continuous-feedback loop colour
    s.append('<defs>'
             '<marker id="arrGr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#1E8E4E"/></marker>'
             f'<marker id="arrFb" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="{FB}"/></marker>'
             '</defs>')
    s.append(box(0, 0, W, 52, NAVY, NAVY, 0, 0))
    s.append(text(W/2, 22, "AI Organizational Transformation — Empowered Building → Governed AI-Production", 18, WHITE, "middle", "bold"))
    s.append(text(W/2, 43, "Anyone can build with AI; everything ships through one governed pipeline into the sanctioned ai-production zone.", 13.5, WHITE, "middle", "bold"))

    # ---- Zone A: controlled build environment ----
    ax, ay, aw, ah = 22, 84, 304, 330
    s.append(box(ax, ay, aw, ah, "#F2F5F9", NAVY, 1.5, 8))
    s.append(text(ax+aw/2, ay+22, "CONTROLLED BUILD ENVIRONMENT", 12, NAVY_DK, "middle", "bold"))
    s.append(text(ax+aw/2, ay+38, "sanctioned · governed · paved road", 11, TEXT_LT, "middle", "bold"))
    builders = ["Clinical ops", "Finance", "Revenue cycle", "Marketing", "Analytics", "Support"]
    bw, bh = 132, 50
    bx0 = ax+14; by0 = ay+52
    builder_pts = []
    for i, name in enumerate(builders):
        c = i % 2; r = i // 2
        bx = bx0 + c*(bw+8); byy = by0 + r*(bh+8)
        s.append(box(bx, byy, bw, bh, WHITE, GRAY_DK, 1, 5))
        s.append(text(bx+bw/2, byy+19, "Citizen Builder", 9, NAVY_DK, "middle", "bold"))
        s.append(text(bx+bw/2, byy+34, name, 10, TEXT, "middle", "bold"))
        builder_pts.append((bx+bw, byy+bh/2))
    s.append(text(ax+aw/2, by0+3*(bh+8)+5, "builds: automations · apps · agents · SaaS replacements", 10, TEXT_LT, "middle", "bold"))
    s.append(box(ax+14, ay+ah-40, aw-28, 30, GRN_FILL, GRN, 1.2, 5))
    s.append(text(ax+aw/2, ay+ah-20, "Build with Claude (primary) · Copilot · paved-road templates", 9.5, GRN_TXT, "middle", "bold"))

    # ---- Node B: single sanctioned commit ----
    nx, ny, nw, nh = 364, 250, 152, 116
    s.append(box(nx, ny, nw, nh, ORANGE, ACCENT, 2.5, 8))
    s.append(text(nx+nw/2, ny+24, "SINGLE", 12, ACCENT, "middle", "bold"))
    s.append(text(nx+nw/2, ny+41, "SANCTIONED COMMIT", 10.5, ACCENT, "middle", "bold"))
    s.append(text(nx+nw/2, ny+68, "Azure Repos", 11, TEXT, "middle", "bold"))
    s.append(text(nx+nw/2, ny+87, "all AI code lands here", 10.5, TEXT_LT, "middle", "bold"))
    cbx, cby = nx, ny+nh/2
    for (px, py) in builder_pts:
        s.append(f'<path d="M {px} {py} C {px+40} {py}, {cbx-46} {cby}, {cbx-2} {cby}" fill="none" stroke="{GRAY_DK}" stroke-width="1.3" marker-end="url(#arr)"/>')

    # ---- Zone C: ai-protect pipeline (Stage 0 -> Stage 7) ----
    px_, py_, pw_, ph_ = 548, 234, 468, 150
    s.append(box(px_, py_, pw_, ph_, "#243B55", GRN, 2.5, 8))
    s.append(text(px_+pw_/2, py_+25, "ai-protect PIPELINE", 16, WHITE, "middle", "bold"))
    s.append(text(px_+pw_/2, py_+43, "scan → fix → verify → gate  (tier-aware: auto or human approval)", 11.5, BLUE, "middle", "bold"))
    n = 8; rr = 14; spacing = (pw_-60)/(n-1); s0x = px_+30; cy = py_+92
    for st in range(n):
        cx = s0x + st*spacing
        if st < n-1:
            s.append(f'<line x1="{cx+rr}" y1="{cy}" x2="{cx+spacing-rr}" y2="{cy}" stroke="{BLUE}" stroke-width="2" marker-end="url(#arr)"/>')
        s.append(f'<circle cx="{cx}" cy="{cy}" r="{rr}" fill="{GRN_FILL}" stroke="{GRN}" stroke-width="2"/>')
        s.append(text(cx, cy+4, str(st), 12, GRN_TXT, "middle", "bold"))
    for cxl, lbl in ((px_+74, "Stage 0 kicks off"), (px_+pw_-74, "Stage 7 completes")):
        s.append(box(cxl-62, cy+24, 124, 20, GRN_FILL, GRN, 1, 10))
        s.append(text(cxl, cy+38, lbl, 10, "#000000", "middle", "bold"))
    s.append(f'<line x1="{nx+nw}" y1="{cby}" x2="{px_-2}" y2="{cy}" stroke="{ACCENT}" stroke-width="2.5" marker-end="url(#arrA)"/>')
    s.append(text((nx+nw+px_)/2, py_-14, "commit", 11.5, ACCENT, "middle", "bold"))
    s.append(text((nx+nw+px_)/2, py_-1, "kicks off", 11.5, ACCENT, "middle", "bold"))

    # ---- Zone D: ai-production environment + continuous assurance ----
    dx, dyy, dw, dh = 1082, 240, 176, 158
    s.append(box(dx, dyy, dw, dh, PROD_FILL, PROD, 3, 10))
    s.append(text(dx+dw/2, dyy+24, "AI-PRODUCTION", 15, PROD, "middle", "bold"))
    s.append(text(dx+dw/2, dyy+41, "ENVIRONMENT", 12, PROD, "middle", "bold"))
    s.append(text(dx+dw/2, dyy+58, "sanctioned network zone", 10, TEXT, "middle", "bold"))
    cax, cay, caw, cah = dx+10, dyy+68, dw-20, 82
    s.append(box(cax, cay, caw, cah, GRN_FILL, GRN, 1.4, 6))
    s.append(text(cax+caw/2, cay+17, "● CONTINUOUS ASSURANCE", 9.5, GRN_TXT, "middle", "bold"))
    s.append(text(cax+caw/2, cay+35, "AI red-team", 10.5, TEXT, "middle", "bold"))
    s.append(text(cax+caw/2, cay+51, "SAST · DAST", 10.5, TEXT, "middle", "bold"))
    s.append(text(cax+caw/2, cay+69, "always-on, in production", 8.5, TEXT_LT, "middle", "bold"))
    s.append(f'<line x1="{px_+pw_}" y1="{cy}" x2="{dx-2}" y2="{dyy+34}" stroke="{GRN}" stroke-width="2.5" marker-end="url(#arrGr)"/>')
    s.append(text((px_+pw_+dx)/2, py_-14, "launch /", 11.5, GRN_TXT, "middle", "bold"))
    s.append(text((px_+pw_+dx)/2, py_-1, "deploy", 11.5, GRN_TXT, "middle", "bold"))

    # ---- Continuous feedback loop: production findings reopen the 7 stages ----
    fy = 418                                   # feedback lane (below pipeline / production)
    pcx = px_+pw_/2
    s.append(f'<path d="M {dx+dw/2} {dyy+dh} L {dx+dw/2} {fy} L {pcx} {fy} L {pcx} {py_+ph_+2}" '
             f'fill="none" stroke="{FB}" stroke-width="2.4" stroke-dasharray="7 4" marker-end="url(#arrFb)"/>')
    s.append(text((pcx+dx+dw/2)/2, fy-7, "continuous findings reopen Stage 0–7   ·   rescan → re-gate → remediate",
                  10, FB, "middle", "bold"))

    # ---- Legend: tier-aware gate ----
    lx, ly, lw, lh = 22, 448, W-44, 100
    s.append(box(lx, ly, lw, lh, GRAY_LT, NAVY, 1.5, 8))
    s.append(text(lx+14, ly+22, "TIER-AWARE GATE", 12, NAVY_DK, "start", "bold"))
    s.append(text(lx+150, ly+22, "— the same pipeline runs for every build; the tier decides whether it ships automatically or waits for a human.",
                  10.5, TEXT_LT, "start", "bold"))
    tiers = [
        ("#F7DAD2", ACCENT, ACCENT, "TIER 1 · Critical", "regulated · PHI · customer-facing", "→ HUMAN APPROVAL to ship"),
        ("#FFF1DD", ORANGE_DK, "#9A5B12", "TIER 2 · High", "sensitive data or broad reach", "→ HUMAN APPROVAL to ship"),
        ("#EAF3FA", NAVY, NAVY_DK, "TIER 3 · Moderate", "internal · limited blast radius", "→ AUTO-GATE when scan is clean"),
        (GRN_FILL, GRN, GRN_TXT, "TIER 4 · Low", "prototype · sandbox", "→ AUTO-GATE on pass"),
    ]
    cw = (lw - 28 - 3*12) / 4
    for i, (fill, stroke, txt, head, scope, decision) in enumerate(tiers):
        cx = lx + 14 + i*(cw+12); cyy = ly+32
        s.append(box(cx, cyy, cw, 56, fill, stroke, 1.4, 6))
        s.append(text(cx+12, cyy+20, head, 11.5, txt, "start", "bold"))
        s.append(text(cx+12, cyy+36, scope, 10.5, TEXT, "start", "bold"))
        s.append(text(cx+12, cyy+51, decision, 10.5, txt, "start", "bold"))

    s.append("</svg>")
    return "\n".join(s)


# ============================================================
# Build all
# ============================================================
diagrams = {
    "01_pipeline_overview.svg": diagram_1(),
    "ai_organizational_transformation.svg": diagram_ai_transformation(),
    "health-01_pipeline_overview_presentation.svg": diagram_health_presentation(),
    # Health-environment variant: same overview with the provided enterprise
    # tooling (Defender, Sentinel, Google TI / OpenCTI / MS Defender TI, Armis,
    # Rapid7, Palo Alto, Mend.io, Abnormal, Copilot, Teams, GitHub) highlighted.
    "health-01_pipeline_overview.svg": diagram_1(highlight=True),
    "02_v21_mapping.svg": diagram_2(),
    "03_ai_redteam_killchain.svg": diagram_3(),
    "04_vertical_ownership.svg": diagram_4(),
    "05_dashboard_technical.svg": diagram_5(),
    "06_dashboard_executive.svg": diagram_6(),
    "07_phase_rollout.svg": diagram_7(),
    "08_ai_empowerment_paved_road.svg": diagram_8(),
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
