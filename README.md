# ai-protect

[![PyPI](https://img.shields.io/pypi/v/ai-protect.svg)](https://pypi.org/project/ai-protect/)
[![Python](https://img.shields.io/pypi/pyversions/ai-protect.svg)](https://pypi.org/project/ai-protect/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> ## 📣 ai-protect is now on PyPI
>
> **`v0.1.1` — the first public release is live.** Install it in one line:
> ```bash
> pipx install ai-protect
> ```
> 48 security scanner adapters (SAST · DAST · AI red-team) with graceful degradation, a zero-config first run, a Flask findings dashboard, CVE intel feeds, and a batteries-included Docker image — all MIT-licensed. Jump to the [Quickstart](#quickstart--run-it-locally), or run `ai-protect doctor` to see what lights up on your machine.

Offensive security operating model for the enterprise AI transformation in a major healthcare organization. This repository contains the strategic proposal, two single-page distribution variants, the technical companion that operationalizes the proposal, the seven SVG diagrams that appear inside them, and the build scripts that generate every document deterministically from source.

The work is anchored on a single strategic reframe: offensive security as the **empirical truth function for AI risk** — the team that proves what does and does not work, while every other voice in the AI conversation (vendors, sponsors, even AI governance) has incentives to be optimistic.

> **Two things live in this repo:** a **runnable security tool** (the `ai_protect/` package — install and use it below) and the **strategy** that shaped it (everything after the Quickstart). Just want to try the tool? Start here.

## Quickstart — run it locally

```bash
pipx install ai-protect      # installs the `ai-protect` + `ai-protect-ui` commands

ai-protect doctor            # what works on your machine — and what needs installing
ai-protect-ui                # dashboard → http://localhost:8000
```

[`pipx`](https://pipx.pypa.io) is recommended — it installs the CLI in its own isolated
environment and works out of the box on Ubuntu/Debian and macOS, where a bare `pip install`
is blocked by [PEP 668](https://peps.python.org/pep-0668/) "externally-managed-environment".
No pipx yet? Install it for your OS (`sudo apt install pipx`, `brew install pipx`) — see the
[pipx install guide](https://pipx.pypa.io/stable/installation/). Inside a virtualenv or conda
env, plain `pip install ai-protect` works too.

Prefer to run from source (for development)?

```bash
git clone https://github.com/n08976/ai-protect && cd ai-protect
python3 -m venv .venv && source .venv/bin/activate
pip install .
ai-protect tier ai_protect/manifests/SAMPLE-clinical-assistant-prototype.yml
```

No configuration required. Everything is written under `~/.ai-protect/`, and nothing
leaves your machine except the CVE/threat feeds you opt into. Scanners that need an
external tool (nuclei, trufflehog, garak, …) are skipped automatically until you
install them — **`ai-protect doctor`** shows exactly which ones and how. The
built-in policy and AI checks work with zero setup. See [The pipeline](#the-pipeline-ai_protect)
for the full tour.

### …or run it with Docker (scanners pre-installed)

No Python setup, no tool installs. The image bakes in the SAST / secrets / SCA /
container scanners (semgrep, bandit, gosec, trufflehog, detect-secrets,
pip-audit, checkov, trivy, grype, syft, …) so they report **live** out of the box.

```bash
docker compose up --build        # UI at http://localhost:8000, plus a ZAP DAST daemon
# or just the app, no DAST:
docker run --rm -p 8000:8000 -v ai-protect-data:/home/aip/.ai-protect ai-protect
```

`docker compose` also starts a ZAP daemon wired in automatically (the app finds it
at `http://zap:8090`), so dynamic web scans work too. Check what's live inside the
image with `docker compose run --rm ai-protect ai-protect doctor`. Findings and
config persist in the `ai-protect-data` volume. Credentialed adapters (Burp,
Metasploit, CodeQL, garak/pyrit) stay opt-in.

---

## Why this exists

The organization is in the middle of a "fast and furious" AI transformation. IT is leading the initial rollout; business departments are next. Within twelve months, hundreds of AI-enabled and self-developed applications will exist across the enterprise, many handling PHI, many deploying outside the formal SDLC. Citizen developers — non-developer employees building AI agents and tools through low-code platforms and AI assistants — are the dominant developer population.

Pre-deployment human review cannot scale to that surface area. If offensive security continues to operate as a gatekeeper, it will be routed around. The alternative posture this body of work proposes:

- **Paved road over policed road.** Build the secure path so it is the easy path. Sanctioned LLM gateway, vetted MCP server registry, managed agent runtime, secure-by-default templates. Adoption is the enforcement mechanism.
- **Risk-tiered engagement.** Four tiers anchored on data sensitivity (PHI, PII, financial, public), decision impact (advisory, automated action, clinical influence), integration footprint (read-only, write-back, agent tool use), and user population (single user, team, enterprise, external). Human depth concentrates on Tier 1–2; Tier 3–4 ride automated assurance.
- **Continuous validation.** Replace point-in-time pre-deploy review with continuous post-deployment validation, threat hunting, and control testing across the five offensive security functions.

In healthcare, an AI-mediated PHI exposure or a manipulated clinical-adjacent system carries breach-notification, HIPAA, FDA-adjacent (SaMD reclassification), and patient-safety consequences. The window to shape the operating model is now, while AI governance patterns are still being set.

---

## Audience and how to use the artifacts

| Artifact | Audience | When to use it |
| --- | --- | --- |
| **`docs/operating_model_v2_1.docx`** | CISO, cyber executive leadership | The strategic anchor. Read this first. ~25 pages with embedded diagrams, executive summary, current state, proposed model, risk-tiering, AI infrastructure control plan, RACI, phased roadmap, asks. |
| **`docs/exec_brief_v1.{docx,pdf}`** | Board, risk committee, peer execs (CISO uses upward) | Single-page executive brief. Leads with the thesis, "what we will do" vs. "what we need from the executive team," twelve-month success criteria, and why-now closing. |
| **`docs/one_pager_v1.{docx,pdf}`** | AI governance, privacy, platform engineering, compliance — wider distribution | Single-page summary of v2.1. The shift, three operating principles, four-tier risk model, six-layer sanctioned AI infrastructure, four-phase roadmap, the seven asks. |
| **`docs/pipeline_companion_v1.{docx,pdf}`** | Offensive security leads (the five vertical owners) | The technical companion to v2.1. Eight-stage AI assurance pipeline, per-vertical capability builds across the five functions, eighteen-row RACI extension, dashboard surfaces, phased tooling rollout. |
| **`diagrams/*.svg` + `*.png`** | Reused inside companion + slide decks | Eight diagrams: pipeline overview, v2.1 mapping, AI red-team kill chain, vertical ownership, technical dashboard, executive dashboard, phased rollout, and the empowered-AI paved-road (citizen builders + Claude governed by ai-protect). Plus a `health-` highlighted variant of the pipeline overview emphasizing the environment tooling. SVG for editing; PNG (1800px wide) for embedding. |

> **Reading order for someone new:** `exec_brief_v1.pdf` → `one_pager_v1.pdf` → `operating_model_v2_1.docx` → `pipeline_companion_v1.pdf`.

---

## The five offensive security verticals

Every artifact in this repo addresses each of these explicitly — the operating model is not an AppSec or Red Team plan in disguise.

- **Application Security (AppSec)** — accountable for the AI security discipline as a whole: tiering, threat modeling, citizen developer enablement, prompt-injection scanning, model-SBOM checks, the operating model itself.
- **Threat Intelligence** — vendor and model risk surveillance, jailbreak/prompt-injection technique tracking, MCP supply-chain provenance, sector-specific AI threat reporting.
- **Threat Hunt** — hunting hypotheses driven by unified AI telemetry: prompt anomalies, tool-call drift, retrieval poisoning, agent decision divergence, shadow-AI surfacing in egress logs.
- **Red Team** — adversarial validation across all tiers, with depth scaled to tier. Manual red team for Tier 1–2; automated red team (garak, PyRIT) for Tier 3; demonstration red team exercise as the highest-leverage Phase 1 deliverable.
- **Security Control Validation (SCV)** — continuous control validation for AI: gateway policy enforcement, MCP scope enforcement, agent quotas and kill-switches, eval-suite regression, network egress allow-list completeness.

---

## Sanctioned AI infrastructure (six layers)

The technical commitments inside v2.1 that the companion engineers against. Platform Engineering operates the controls; offensive security defines policy.

1. **AI gateway** — the only sanctioned path to Claude and approved foundation models. Authentication and authorization, data-classification routing (PHI may only be sent to BAA-covered endpoints), prompt-side DLP and PHI redaction, output filtering, per-workload quotas, comprehensive logging. Direct API access from applications, scripts, notebooks, or developer endpoints is prohibited.
2. **MCP server farm** — curated registry, no bring-your-own. Each MCP carries a tier and data label; tier inheritance flows from MCP to any agent that uses it (a clinical-data MCP makes the calling agent Tier 1). Scoped, short-lived tokens. Action enumeration with side-effect classification.
3. **Agent runtime farm** — managed workloads with workload identity (SPIFFE-style), tool allow-list (default deny), validated eval suite, sandboxed execution, runtime quotas, kill-switch, annual recertification. Agents outside this farm cannot reach the gateway, MCP farm, or data plane. **The Stage-2 Scope step in agent registration is the single highest-leverage control in the entire infrastructure.**
4. **AI-aware SDLC** — five stages (Intake → Design → Build → Pre-Production → Production) with automated checks at every tier and gates calibrated to tier. Tier 1–2 require AI governance and privacy review at intake, signed-off threat model at design, manual red team at pre-prod.
5. **Network provisioning** — per-tier subnets, mTLS east-west via service mesh, TLS-inspecting egress to model APIs, default-deny allow-list, end-user shadow-AI block at corporate proxy. Cross-tier lateral movement and bypass paths are validated quarterly by SCV.
6. **Unified AI telemetry** — prompts, completions, tool calls, retrieval queries, agent decisions, policy events with identity context. Flows to SIEM, hunt platform, control validation platform, and application-owner dashboards. Without this layer, hunt and IR are blind.

The sanctioned model stack assumes **Claude (Anthropic)** as the primary sanctioned foundation model family, with private-deploy or BAA-covered endpoints used for any PHI handling. Multi-vendor is not ruled out, but Claude is the default.

---

## Risk-tiering framework

Applications classified by data sensitivity, decision impact, integration footprint, and user population. The intake form scores all four; an AppSec partner confirms or escalates.

| Tier | Profile | Engagement |
| --- | --- | --- |
| **Tier 1** | PHI / clinical / external-facing | Embedded AppSec partner from design, manual threat model, manual red team, continuous control validation |
| **Tier 2** | Sensitive internal action / write-back to systems of record | Embedded review, manual red team for material changes, continuous monitoring |
| **Tier 3** | Internal advisory with broad reach | Async checklist review, automated red team (garak, PyRIT), continuous monitoring |
| **Tier 4** | Low-impact assistive | Paved-road template, automated scanning, baseline logging, no human review unless flags fire |

Re-tier on material change, incident or near-miss, regulatory change, or annual recertification.

---

## Phased capability roadmap (18 months)

| Phase | Focus | Notes |
| --- | --- | --- |
| **Phase 1 — Demonstrate** | Existing headcount, reprioritized toward AI. Tooling proof-of-concept (open-source: garak, PyRIT, Semgrep, Trivy, ModelScan). Operating-model and demonstration red team exercise. | Phase 1 is intentionally executable inside existing headcount and operating budget — endorsement, not funding, is the unblocking decision. The demonstration red team is the single highest-leverage move; it reframes every later budget conversation in terms of avoided harm rather than abstract risk. |
| **Phase 2 — Build the paved road** | AI gateway, MCP farm, agent runtime, AI-aware SDLC integration. Selective specialist hiring. Paved-road UX as a first-class concern. | Interlocking — none works well alone, and collectively they make the operating model enforceable. |
| **Phase 3 — Measure** | Continuous control validation for AI; metrics for board and risk-committee reporting; sharpened ask informed by data. | This is where the quarterly state-of-AI-security report becomes data-rich. |
| **Phase 4 — Institutionalize** | Quarterly state-of-AI-security cadence; durable RACI; the seat at the table outlives organizational change. | About durability — making sure the seat survives org changes. |

---

## What we are asking for

The seven asks in v2.1, restated tersely. Same wording carried into the one-pager and exec brief.

1. **Operating model approval** — endorsement of the shift from gatekeeper to embedded advisor and continuous validator, with risk-tiered engagement as the standard.
2. **Risk-tiering framework adoption** — endorsement of the four-tier classification, socialized with AI governance, privacy, and compliance.
3. **AI infrastructure control plan endorsement** — sponsorship of the gateway, MCP farm, agent runtime, AI-aware SDLC, and network provisioning approach in cross-functional conversations with platform engineering and AI governance.
4. **RACI ratification** — offensive security accountable for AI security discipline; platform engineering accountable for control operations.
5. **Phase 1 authorization** — authorization to proceed within existing headcount and operating budget, with funded training and tooling proof-of-concepts.
6. **Executive air cover** — active sponsorship in AI transformation forums, AI governance committee meetings, and conversations with business unit leaders.
7. **Reporting cadence commitment** — quarterly state-of-AI-security report to the cyber executive team and risk committee, beginning end of Phase 1.

---

## Healthcare regulatory considerations

Every recommendation in this repo assumes the healthcare context. These constraints raise the floor on "acceptable risk" significantly compared to a general enterprise.

- **HIPAA / HITECH** — PHI handling, breach notification, minimum-necessary access. PHI may only be sent to BAA-covered model endpoints; the gateway enforces this at the data-classification layer.
- **HITRUST** — control coverage and audit evidence expected. Findings schema maps controls to HIPAA/HITRUST so audit evidence is queryable.
- **FDA SaMD** — clinical decision support tools may be regulated as Software as a Medical Device. Citizen-developer agents that touch clinical data or workflows trigger SaMD reclassification review with Regulatory Affairs.
- **BAA inventory** — third-party AI services touching PHI need executed Business Associate Agreements; gateway enforces routing.
- **Patient safety** — clinical hallucination, off-label drug recommendations, biased clinical decisioning are real harms, not theoretical. Default to Presidio + clinical NER for output scrubbing.

---

## The pipeline (`ai_protect/`)

The runnable counterpart to v2.1 and the technical companion. An AI app or agent registers a YAML manifest, the pipeline tier-classifies it, then routes it to the right tools at the right tier × stage. Every adapter normalizes output to the same finding schema; every finding auto-tags HIPAA / HITRUST / NIST AI RMF / MITRE ATLAS controls. See **[`ai_protect/README.md`](ai_protect/README.md)** for the full architecture and adapter catalog.

**Tools wired in today** — 48 adapters: **SAST 23 · DAST 20 · pre-flight policy 3 · production telemetry 2** (`ai_protect/adapters/`):

- **AI-native:** [NVIDIA garak](https://github.com/NVIDIA/garak), [Microsoft PyRIT](https://github.com/Azure/PyRIT), built-in `mcp_scope` validator (the highest-leverage control in v2.1), built-in `eval_suite` (hallucination / bias / jailbreak gates).
- **Classical pen test:** [PortSwigger Burp Suite](https://portswigger.net/burp) (REST), [Rapid7 Metasploit](https://github.com/rapid7/metasploit-framework) (RPC, auxiliary by default), [Red Canary Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (MITRE ATT&CK technique emulation against the agent runtime host).
- **From [RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools):** [Nuclei](https://github.com/projectdiscovery/nuclei), [TruffleHog](https://github.com/trufflesecurity/trufflehog).
- **Built-in policy gates:** `manifest_validator` (intake), `threat_model_check` (design, Tier 1-2), `telemetry_drift` (production).

**From a checkout (no install — for development):** the [Quickstart](#quickstart--run-it-locally) above installs the `ai-protect` command; the equivalents below run straight from a clone via `python -m`.

```bash
pip install -r ai_protect/requirements.txt

# What works on this machine, and what each missing tool needs
python -m ai_protect.cli doctor

# Tier-classify a sample app
python -m ai_protect.cli tier ai_protect/manifests/SAMPLE-clinical-assistant-prototype.yml

# Run preprod gates end-to-end (degrades gracefully when external tools aren't installed).
# Findings default to the durable data home (~/.ai-protect/findings.jsonl) — no flag needed.
python -m ai_protect.cli run \
    ai_protect/manifests/SAMPLE-clinical-assistant-prototype.yml --stage preprod

# Dashboards
python -m ai_protect.cli report --kind executive
python -m ai_protect.cli report --kind technical

# What runs where
python -m ai_protect.cli adapters
python -m ai_protect.cli policy --tier 1 --stage preprod

# Tests
python -m pytest ai_protect/tests/ -q

# Web UI + background feed poller (one process). Zero-config — reads the same
# durable findings store. See ai_protect/README.md → Web UI.
python -m ai_protect.ui.server          # open http://localhost:8000/
```

The pipeline ships with three example manifests covering the spread: Tier 1 clinical assistant, Tier 3 HR-policy advisor, Tier 4 single-user code summarizer. Adapters that need an external tool (garak, nuclei, etc.) raise `AdapterUnavailable` and are skipped non-fatally — install the tools you actually plan to exercise.

**Web UI.** The Flask app under `ai_protect/ui/` is more than a dashboard:

- **Scan modes (SAST / DAST split)** — `/scan` has a top-level segmented control. Source code (SAST) keeps the original manifest + stage + adapter form; Live target (DAST) adds a Known-app / Arbitrary-URL sub-tab with URL safety guards (hard-deny cloud metadata + non-`http(s)` schemes + embedded creds; default-deny RFC1918 / loopback / link-local etc. with typed-confirmation override; DNS re-resolved every check; HTTPS by default). DAST execution is constrained by a typed `DastConfig` carrier — rate-limit, concurrency, hard timebox, scope-prefix enforcement for crawlers (ZAP, nuclei, katana, burp).
- **Scanning from GitHub** — `/settings → Source providers` configures public / PAT / GitHub-App auth, per-scan or cached clone, github.com or GHES. Manifest declares `source_provider: github` + `github_repo` + `github_ref`; the orchestrator clones to a temp dir or persistent cache before adapter dispatch and cleans up via try/finally even on adapter errors.
- **Intel feeds + system status lamp** — background poller fetches external CVE / threat feeds (CISA KEV, cvedaily.com per-tag feeds, cvefeed.io, custom JSON/Atom/RSS/XML). Overall green/yellow/red lamp on the home page (worst-of feeds, scans, findings-store health).
- **Intel-scan integration** — feeds participate in scans two ways: (a) **Enrichment** stamps intel context onto every scanner finding before persist; CVEs on CISA KEV ratchet up to CRITICAL. (b) **Detection** — an `intel_match` adapter cross-references manifest-declared assets against the intel store and emits findings the structured scanners didn't catch.
- **Auto-resolve on re-scan absence** — when a re-scan's `status=ok` adapters don't re-emit a previously-emitted fingerprint, the system automatically writes a Change with `state=applied` and `strategy=auto_resolve_absent`. Scanner is treated as ground truth. Guards: adapter scope, stage scope, honor-revert, skip-already-resolved.
- **Schema-driven settings + /docs** — `/settings` is generated from `ai_protect/core/settings.py`'s `SCHEMA` (5 sections / 20+ fields, progressive disclosure for nested choices). Every help bubble links to a step-by-step setup walkthrough on `/docs` (PAT creation, GitHub App + installation-id retrieval, GHES URL format, DAST safety matrix, auto-resolve guards, etc.).

See [`ai_protect/README.md`](ai_protect/README.md) for the full picture: routes, classification, URL safety, source providers, auto-resolve, intel feeds, scan-mode tools, and the JSON API.

---

## Repository layout

```
ai-protect/
├── README.md                       # This file
├── .gitignore
├── ai_protect/                       # The runnable AI assurance pipeline
│   ├── README.md                   # Pipeline architecture, adapter catalog, extension guide
│   ├── cli.py
│   ├── requirements.txt
│   ├── core/                       # manifest, tiering, findings, compliance, policy, orchestrator,
│   │                               # intel_enrichment (KEV ratchet), auto_resolve (re-scan absence),
│   │                               # scan_modes (SAST/DAST), url_safety, adhoc, dast_config, settings
│   ├── adapters/                   # garak, pyrit, atomic, burp, metasploit, mcp_scope, nuclei,
│   │                               # zap, recon, sqlmap, trufflehog, intel_match (manifest×intel), ...
│   ├── sources/                    # remote-source providers — local (passthrough) + github
│   │                               # (PAT or App, github.com or GHES, per-scan or cached clone)
│   ├── intel/                      # CVE / threat feed ingestion: feeds, translators (atom/rss/xml/json),
│   │                               # fetcher + background poller, status (green/yellow/red lamp)
│   ├── ui/                         # Flask dashboard: findings, /feeds, /feeds/discover, /intel,
│   │                               # /settings (schema-driven), /docs (step-by-step setup),
│   │                               # /history, /scan (SAST/DAST split), /api/status, /api/findings
│   ├── reporting/                  # technical + executive dashboards
│   ├── manifests/                  # example app declarations (Tier 1 / 3 / 4)
│   ├── fixtures/                   # threat-model exemplars
│   └── tests/
├── docs/                           # Generated artifacts (committed for distribution)
│   ├── operating_model_v2_1.docx
│   ├── one_pager_v1.docx
│   ├── one_pager_v1.pdf
│   ├── exec_brief_v1.docx
│   ├── exec_brief_v1.pdf
│   ├── pipeline_companion_v1.docx
│   └── pipeline_companion_v1.pdf
├── build/                          # Deterministic build scripts
│   ├── build_diagrams.py           # Builds the 8 SVGs + PNGs (+ health- overview variant) in diagrams/
│   ├── build_doc.py                # Builds pipeline_companion_v1.docx
│   ├── build_onepagers.py          # Builds one_pager_v1.docx + exec_brief_v1.docx
│   └── requirements.txt            # python-docx, cairosvg
├── .github/workflows/
│   └── ai-protect.yml              # CI: tier-classify + scan every example manifest, upload findings, gate on blocking failures
└── diagrams/                       # 8 SVG diagrams + PNG renders (1800px wide) + health- highlighted overview
    ├── 01_pipeline_overview.{svg,png}
    ├── 02_v21_mapping.{svg,png}
    ├── 03_ai_redteam_killchain.{svg,png}
    ├── 04_vertical_ownership.{svg,png}
    ├── 05_dashboard_technical.{svg,png}
    ├── 06_dashboard_executive.{svg,png}
    └── 07_phase_rollout.{svg,png}
```

---

## Building from source

All artifacts can be regenerated deterministically. The build scripts use repo-relative paths via `__file__` resolution, so you can run them from anywhere.

### Prerequisites

```bash
# Python deps for docx + svg rendering
pip install -r build/requirements.txt

# LibreOffice for converting docx to pdf (optional — only needed for PDF output)
sudo apt-get install -y libreoffice
```

### Build the one-pager and executive brief

```bash
python3 build/build_onepagers.py
```

Outputs:
- `docs/one_pager_v1.docx` — full distribution one-pager
- `docs/exec_brief_v1.docx` — board / risk-committee executive brief

### Build the technical companion

Diagrams must exist before the companion is built (it embeds PNG renders).

```bash
python3 build/build_diagrams.py     # writes diagrams/*.svg + diagrams/*.png
python3 build/build_doc.py          # writes docs/pipeline_companion_v1.docx
```

### Convert any docx to pdf

```bash
libreoffice --headless --convert-to pdf docs/one_pager_v1.docx --outdir docs/
libreoffice --headless --convert-to pdf docs/exec_brief_v1.docx --outdir docs/
libreoffice --headless --convert-to pdf docs/pipeline_companion_v1.docx --outdir docs/
```

### Rebuild everything

```bash
python3 build/build_diagrams.py
python3 build/build_onepagers.py
python3 build/build_doc.py
libreoffice --headless --convert-to pdf docs/one_pager_v1.docx docs/exec_brief_v1.docx docs/pipeline_companion_v1.docx --outdir docs/
```

> The v2.1 operating model itself (`docs/operating_model_v2_1.docx`) is the strategic anchor and is committed as a binary; it is not regenerated by the build scripts here. The companion, one-pager, and exec brief all derive from and are consistent with v2.1.

---

## Visual style guide

Every artifact mirrors the same palette and typography so the family of documents is visually coherent.

| Element | Value |
| --- | --- |
| Body font | Calibri |
| Navy (headings, table headers) | `#1F3A5F` |
| Accent (rules, bullets, eyebrows) | `#C04A2B` |
| Takeaway box (light blue) | `#EAF3FA` |
| Callout box (warm orange) | `#FFF4E5` |
| Alt row shading | `#F2F5F9` |
| Body text | `#222222` |
| Muted text | `#555555` |

Conventions:
- **Takeaway boxes** (light blue) hold the strategic frame or distilled point.
- **Callout boxes** (warm orange) hold the ask, risks, or "why now" rationale.
- **Navy-banded data tables** with alternating row shading carry structured content (tiering, RACI, roadmap).
- Bullets use the accent-colored `•` glyph rather than Word's default.
- Bold leads (e.g., **"Paved road over gates** —") on bulleted definitions; running text after the em-dash.

---

## Versioning

- `operating_model_v2_1.docx` is the strategic proposal at v2.1 (current).
- `one_pager_v1.docx`, `exec_brief_v1.docx`, `pipeline_companion_v1.docx` are v1 distillations that derive from v2.1.

When v2.1 changes, the v1 distillations should be regenerated (and their version bumped). Do not let the family drift out of sync.

---

## Software sources catalogue

Single reference for every tool source that has been raised, reviewed, or wired into this project. Use this section as the canonical list when adding, removing, or replacing software in the pipeline.

### Environment integrations (Microsoft-aligned)

The enterprise security stack this pipeline plugs into in the target (Microsoft-centric) environment. These are existing platforms the pipeline integrates with or feeds — not adapters shipped in this repo. They are rendered on `diagrams/01_pipeline_overview.*`, with a highlighted variant at `diagrams/health-01_pipeline_overview.*` that emphasizes exactly these tools.

| Tool | Category | Where it maps in the pipeline |
| --- | --- | --- |
| Microsoft Defender (XDR/EDR) | Endpoint / XDR | Continuous monitoring — detection telemetry, ATT&CK coverage validation (pairs with atomic/caldera) |
| Microsoft Sentinel | SIEM / SOAR | Continuous monitoring — findings + telemetry sink, alerting, response automation |
| Microsoft Defender Threat Intelligence | Threat intel | Intel feeds — IOC/actor enrichment into the intel-match detection path |
| Google Threat Intelligence (Mandiant) | Threat intel | Intel feeds — CVE/actor enrichment |
| OpenCTI | Threat intel | Intel feeds — STIX aggregation / threat-intel platform |
| Armis | Asset visibility | Discovery & Intake — asset/device inventory for scope |
| Rapid7 (InsightVM) | Vuln management | Dynamic AppSec — infra/host vulnerability scanning |
| Palo Alto (NGFW / Prisma) | Network / Cloud | Remediation (WAF push) + network/cloud guardrails |
| MEND.io | SAST / SCA | Static / build — SAST + dependency & license scanning (alongside Semgrep/Trivy/Grype/OSV) |
| Abnormal | Email security | Email-intake surface protection (anti-phishing/BEC) |
| GitHub (+ Advanced Security) | Source / SAST | Source-repo scan (Stage 0) + CodeQL code scanning |
| M365 / GitHub Copilot | AI surface | Monitored AI surface — target for red-team + telemetry |
| Microsoft Teams | Collaboration | Reporting & Notification channel |

### Initial seed list (provided by the offensive security director)

The starting tool set named at project kickoff. These were the foundation for the pipeline build.

| Tool | Source |
| --- | --- |
| Burp Suite | https://portswigger.net/burp |
| Metasploit Framework | https://github.com/rapid7/metasploit-framework |
| NVIDIA garak | https://github.com/NVIDIA/garak |
| Microsoft PyRIT | https://github.com/Azure/PyRIT |
| Red Canary Atomic Red Team | https://github.com/redcanaryco/atomic-red-team |
| RedTeam-Tools (catalog) | https://github.com/A-poc/RedTeam-Tools |
| Automated Red Team lab (training) | https://redteams.ai/topics/labs/intermediate/lab-automated-red-team |

### Red-team catalog repositories (reviewed for picks)

Curated awesome-list / red-team-tradecraft repositories the user referenced. Picks from these were evaluated against pipeline-fit (SAST / DAST / autonomous scanner shape) and the local-vulnerabilities scope. Use these as future browse points when looking for additions.

| Catalog | Source |
| --- | --- |
| Awesome-Red-Teaming | https://github.com/0xMrNiko/Awesome-Red-Teaming |
| RedTeam-Resources | https://github.com/J0hnbX/RedTeam-Resources |
| RedTeamTools | https://github.com/MantisSTS/RedTeamTools |
| Red-Blueteam-party | https://github.com/A0RX/Red-Blueteam-party |
| redTeaming | https://github.com/idchoppers/redTeaming |
| irredteam.github.io | https://github.com/irredteam/irredteam.github.io |
| RedTeam-Tools | https://github.com/A-poc/RedTeam-Tools |
| Red-Teaming-Toolkit (infosecn1nja) | https://github.com/infosecn1nja/Red-Teaming-Toolkit |
| HexStrike-AI MCP (150+ offensive tools as MCP) | https://github.com/0x4m4/hexstrike-ai |

> **HexStrike-AI MCP evaluation (2026-06).** Reviewed as a possible integration.
> Verdict: do **not** wire the MCP server itself — it's an autonomous LLM-driven
> orchestrator that shells out over an HTTP command-execution surface and returns
> raw tool output, which conflicts with this pipeline's manifest-gated, scope-safe,
> normalized-`Finding` model (it would duplicate the orchestrator and bypass the
> safety gates). Its SAST/DAST tools were already largely covered here (Checkov,
> Trivy, Nuclei, SQLMap, ZAP, Burp). We mined it for the genuine DAST gaps and
> wired those as local adapters instead: `nikto`, `dalfox`, `wpscan`, `commix`,
> `nosqli` (subbed for NoSQLMap), `tplmap` — see the Dynamic·web·network table above.

### Wired-in adapters (current state)

Adapters present in `ai_protect/adapters/` and live in the policy table. Group by category matches the `/about` page in the live UI.

#### Policy gates (built-in and runtime)

| Adapter | Source |
| --- | --- |
| `manifest_validator` | (built-in) — `ai_protect/adapters/manifest_validator.py` |
| `threat_model_check` | (built-in) — `ai_protect/adapters/threat_model_check.py` |
| `mcp_scope` | (built-in) — `ai_protect/adapters/mcp_scope.py` |
| `guardrails` (NeMo) | https://github.com/NVIDIA/NeMo-Guardrails |

#### Static analysis · secrets · dependencies

| Adapter | Source |
| --- | --- |
| `trufflehog` | https://github.com/trufflesecurity/trufflehog |
| `gitleaks` | https://github.com/gitleaks/gitleaks |
| `detect_secrets` | https://github.com/Yelp/detect-secrets |
| `semgrep` | https://github.com/semgrep/semgrep |
| `bandit` | https://github.com/PyCQA/bandit |
| `gosec` | https://github.com/securego/gosec |
| `owasp_noir` | https://github.com/owasp-noir/noir |
| `agentic_radar` | https://github.com/splx-ai/agentic-radar |
| `bearer` | https://github.com/Bearer/bearer |
| `codeql` | https://github.com/github/codeql-cli-binaries |
| `njsscan` | https://github.com/ajinabraham/njsscan |
| `pip_audit` | https://github.com/pypa/pip-audit |
| `dependency_check` (OWASP) | https://github.com/dependency-check/DependencyCheck |
| `trivy` | https://github.com/aquasecurity/trivy |
| `checkov` | https://github.com/bridgecrewio/checkov |
| `syft` | https://github.com/anchore/syft |
| `grype` | https://github.com/anchore/grype |
| `osv_scanner` | https://github.com/google/osv-scanner |
| `modelscan` | https://github.com/protectai/modelscan |
| `presidio` | https://github.com/microsoft/presidio |
| `hadolint` | https://github.com/hadolint/hadolint |

#### Dynamic · web · network

| Adapter | Source |
| --- | --- |
| `nuclei` | https://github.com/projectdiscovery/nuclei |
| `burp` | https://portswigger.net/burp |
| `zap` (OWASP ZAP) | https://github.com/zaproxy/zaproxy |
| `metasploit` | https://github.com/rapid7/metasploit-framework |
| `atomic` (Atomic Red Team) | https://github.com/redcanaryco/atomic-red-team |
| `caldera` (MITRE) | https://github.com/mitre/caldera |
| `ride` (Adobe) | https://github.com/adobe/ride |
| `recon` chain | https://github.com/projectdiscovery/subfinder · https://github.com/projectdiscovery/httpx · https://github.com/projectdiscovery/naabu · https://github.com/projectdiscovery/katana |
| `sqlmap` | https://github.com/sqlmapproject/sqlmap |
| `nikto` | https://github.com/sullo/nikto |
| `dalfox` | https://github.com/hahwul/dalfox |
| `wpscan` | https://github.com/wpscanteam/wpscan |
| `commix` | https://github.com/commixproject/commix |
| `nosqli` | https://github.com/Charlie-belmer/nosqli |
| `tplmap` | https://github.com/epinna/tplmap |
| `dockle` | https://github.com/goodwithtech/dockle |

> The six rows above (`nikto` … `tplmap`) were added after evaluating the
> **[HexStrike-AI MCP server](https://github.com/0x4m4/hexstrike-ai)** (150+ offensive
> tools exposed to an LLM agent). We did **not** integrate the MCP server itself —
> it's a parallel autonomous orchestrator returning raw output over an HTTP
> command-execution surface, which conflicts with this pipeline's manifest-gated,
> normalized-`Finding` model. Instead we mined its tool list for genuine DAST gaps
> and wrote thin local adapters on the existing contract. The NoSQL slot was scoped
> to NoSQLMap but swapped to **nosqli** (NoSQLMap is Python-2-only and interactive,
> so it cannot run headless in a scan). See `ai_protect/README.md` for install paths.

#### AI red team · eval

| Adapter | Source |
| --- | --- |
| `garak` | https://github.com/NVIDIA/garak |
| `pyrit` | https://github.com/Azure/PyRIT |
| `promptfoo` | https://github.com/promptfoo/promptfoo |
| `deepeval` (fallback for promptfoo adapter) | https://github.com/confident-ai/deepeval |
| `eval_suite` | (built-in) — `ai_protect/adapters/eval_suite.py` |

#### Production · telemetry

| Adapter | Source |
| --- | --- |
| `telemetry_drift` | (built-in) — `ai_protect/adapters/telemetry_drift.py` |
| `anomaly_detector` (alias) | (built-in) — `ai_protect/adapters/telemetry_drift.py` |

#### Findings management / export — findings sinks

Findings ship to external destinations through a small, pluggable **sink** layer (`ai_protect/integrations/`). A sink implements `FindingsSink` (`is_configured()` + `push()`), registers in `ai_protect/integrations/registry.py`, and is then reachable from `cli run --sink <name>`, the standalone exporter, and the `cli sinks` listing — no orchestrator or CLI changes. DefectDojo is the first concrete sink; the same seam fits SARIF/OCSF files, ServiceNow, or a webhook next.

| Sink | Source |
| --- | --- |
| DefectDojo (open source) | `ai_protect/integrations/defectdojo/` — `config` · `serialize` · `client` · `sink` |

Normalized findings push to an open-source [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) instance (aggregation, triage, waivers, trend tracking) via its **Generic Findings Import** API:

```bash
# Preview exactly what would be sent (no creds, no network):
python -m ai_protect.cli defectdojo --app commercial --min-severity high --dry-run

# Standalone export of the findings store:
export DEFECTDOJO_URL=https://defectdojo.internal
export DEFECTDOJO_API_TOKEN=...        # DefectDojo → API v2 Key; inject from Vault/Key Vault
python -m ai_protect.cli defectdojo --product commercial --engagement "ai-protect preprod"

# Or push automatically right after a scan:
python -m ai_protect.cli run .ai-protect/manifest.yml --stage preprod --sink defectdojo

# See which sinks are configured:
python -m ai_protect.cli sinks
```

**Config resolves from CLI args → environment → `/settings`** (so CI injects creds from Vault/Key Vault while a local operator configures it once in the dashboard's *Findings sinks* section). Per-app product/engagement names come from the manifest:

```yaml
# .ai-protect/manifest.yml
integrations:
  defectdojo:
    product: "Commercial Ads MCP"
    engagement: "ai-protect preprod"
```

Each finding carries a stable `unique_id_from_tool` (the pipeline fingerprint), so repeated `reimport-scan` pushes reconcile against the prior test — a re-scan updates the same findings in place instead of creating duplicates. We also send `close_old_findings` so DefectDojo can mitigate findings no longer reported once they're remediated (this close-reconcile depends on the instance's deduplication settings). `auto_create_context=true` together with `product_type_name` creates the product/engagement on first push. The reusable `assure.yml` CI gate pushes automatically when `DEFECTDOJO_URL` + `DEFECTDOJO_API_TOKEN` secrets are provided.

### Reviewed but not yet wired

Tools that have been evaluated and are documented for future wiring. Each line is a pre-baked candidate — when scope changes (cloud presence, AD-integrated workloads, K8s deployment, mobile surface), add them as adapters under `ai_protect/adapters/` and register in `ai_protect/adapters/registry.py` + `ai_protect/core/policy.py`.

#### AD attack-path / network identity (out of scope today; pull in once AI workloads are AD-integrated)

| Tool | Source |
| --- | --- |
| BloodHound + SharpHound | https://github.com/SpecterOps/BloodHound |
| Impacket | https://github.com/fortra/impacket |
| NetExec (nxc) | https://github.com/Pennyw0rth/NetExec |
| kerbrute | https://github.com/ropnop/kerbrute |
| Responder | https://github.com/lgandx/Responder |
| RustHound (faster BloodHound collector) | https://github.com/g0h4n/RustHound |

#### Phishing / Threat Hunt vertical

| Tool | Source |
| --- | --- |
| Gophish | https://github.com/gophish/gophish |
| Evilginx2 | https://github.com/kgretzky/evilginx2 |
| SpiderFoot | https://github.com/smicallef/spiderfoot |

#### Cloud / Kubernetes (pull in once Platform Engineering deploys to cloud)

| Tool | Source |
| --- | --- |
| Prowler | https://github.com/prowler-cloud/prowler |
| ScoutSuite | https://github.com/nccgroup/ScoutSuite |
| kube-bench | https://github.com/aquasecurity/kube-bench |
| kube-hunter | https://github.com/aquasecurity/kube-hunter |
| Falco (runtime) | https://github.com/falcosecurity/falco |
| Deepfence ThreatMapper | https://github.com/deepfence/ThreatMapper |

#### Recon depth (complement existing `recon` adapter)

| Tool | Source |
| --- | --- |
| ffuf | https://github.com/ffuf/ffuf |
| feroxbuster | https://github.com/epi052/feroxbuster |
| gobuster | https://github.com/OJ/gobuster |
| dirsearch | https://github.com/maurosoria/dirsearch |
| kiterunner (API discovery) | https://github.com/assetnote/kiterunner |
| subzy (subdomain takeover) | https://github.com/PentestPad/subzy |
| reconftw | https://github.com/six2dez/reconftw |
| BBOT | https://github.com/blacklanternsecurity/bbot |
| Amass (OWASP) | https://github.com/OWASP/Amass |
| Gato (GitHub enumeration — supply-chain) | https://github.com/praetorian-inc/gato |
| AttackSurfaceMapper | https://github.com/superhedgy/AttackSurfaceMapper |
| theHarvester | https://github.com/laramies/theHarvester |

#### Web / API DAST (alternates and complements to wired Nuclei + ZAP + Burp)

Pipeline-shape: scan a URL or API surface, return structured findings. Already-wired Nuclei + ZAP + Burp + sqlmap cover most of the surface; these are alternates worth knowing about for second-opinion runs or where one of the wired tools doesn't fit (e.g., REST/JSON-only fuzzing).

| Tool | Source | Note |
| --- | --- | --- |
| Nikto | https://github.com/sullo/nikto | Long-standing web server scanner; pairs with Nuclei. |
| OpenVAS / Greenbone Community Edition (GVM) | https://github.com/greenbone/openvas-scanner | Heavyweight network vuln scanner; fit for infra-side DAST around the agent runtime. |
| Wapiti | https://github.com/wapiti-scanner/wapiti | Actively maintained CLI web DAST; ZAP/Nuclei complement. |
| Ride (Adobe REST/JSON fuzzer) | https://github.com/adobe/ride | Apache 2; payload fuzzing for REST APIs — relevant for AI gateway and MCP server surfaces. |
| purpleteam (OWASP) | https://github.com/purpleteam-labs/purpleteam | Modern OWASP DAST orchestrator (CLI + SaaS); AGPLv3. |

> **Catalogue source — Lalatenduswain/Dynamic-Application-Security-Testing-DAST-Tools** (https://github.com/Lalatenduswain/Dynamic-Application-Security-Testing-DAST-Tools-Cybersec-Tools-and-scanner). Already-wired from that list: Nuclei, ZAP. **Reviewed and skipped (abandoned upstream):** Arachni (last release 2017), GoLismero (2014), Grabber (2007), Grendel-Scan (~2012), Vega (2014). **Marginal vs. wired stack and not pursued:** w3af (low activity, redundant with ZAP/Burp/Nuclei), Sec-helpers (script grab-bag, not a DAST tool). Commercial-only entries (Burp Pro/Enterprise, Rapid7 Nexpose, etc.) are out of catalogue scope here.

#### Adversary emulation frameworks (SCV-shape candidates)

Pipeline-shape: declare a TTP / playbook, run autonomously, emit a structured result. Complement Atomic Red Team (which is technique-by-technique) by chaining techniques into autonomous campaigns. Strong fit for the Security Control Validation vertical and for the v2.1 Phase 1 demonstration red team scaffolding. (Caldera was promoted from this list to wired-in.)

| Tool | Source |
| --- | --- |
| Stratus Red Team (DataDog, cloud-native) | https://github.com/DataDog/stratus-red-team |
| Network Flight Simulator (alphasoc) | https://github.com/alphasoc/flightsim |
| TTPForge (Meta) | https://github.com/facebookincubator/TTPForge |
| APTSimulator | https://github.com/NextronSystems/APTSimulator |
| RTA (Endgame) | https://github.com/endgameinc/RTA |
| Metta (Uber) | https://github.com/uber-common/metta |

#### C2 frameworks (operator engagement, not pipeline-shaped)

Useful for the v2.1 Phase 1 demonstration red team exercise. Not wiring as adapters because they're interactive operator platforms.

| Tool | Source |
| --- | --- |
| Sliver | https://github.com/BishopFox/sliver |
| Mythic | https://github.com/its-a-feature/Mythic |
| Havoc | https://github.com/HavocFramework/Havoc |
| Empire | https://github.com/BC-SECURITY/Empire |
| Cobalt Strike | https://www.cobaltstrike.com (commercial) |
| Brute Ratel | https://bruteratel.com (commercial) |

#### AI-specific (defer / niche)

| Tool | Source | Note |
| --- | --- | --- |
| LLM Guard | https://github.com/protectai/llm-guard | Defensive runtime filter |
| Rebuff | https://github.com/protectai/rebuff | Prompt-injection detection |
| Plexiglass | https://github.com/Adversa-AI/plexiglass | LLM safety evaluation |
| Counterfit | https://github.com/Azure/counterfit | Microsoft AI red team toolkit (older; PyRIT supersedes) |
| Adversarial Robustness Toolbox (ART) | https://github.com/Trusted-AI/adversarial-robustness-toolbox | Adversarial example generation |
| AdvBox | https://github.com/advboxes/AdvBox | Adversarial attack toolbox |
| Inspect (UK AISI) | https://github.com/UKGovernmentBEIS/inspect_ai | Newer eval framework |
| FuzzyAI | https://github.com/cyberark/FuzzyAI | CyberArk; genetic-algorithm + mutation fuzzing for novel LLM vulnerabilities (ASCII-art prompts, Unicode smuggling). Discovery shape, not known-attack regression. |
| promptmap2 | https://github.com/utkusen/promptmap | Utku Şen; specialized prompt-injection scanner with dual-AI architecture; single- and multi-turn testing against system prompts. |

#### Offensive AI agents (dual-use research / Tier 3 candidates)

Autonomous LLM agents that perform pentesting tasks end-to-end. Strategically interesting for two reasons: (1) candidates for **Tier 3 automated red team** if quality validates against garak/PyRIT baselines; (2) exemplars of the citizen-developer-built agent class the offensive security team will need to evaluate as parallels emerge inside the org. Treat with the same scrutiny v2.1 applies to internal AI agents — scoped identity, gateway routing, kill-switch, eval suite. Several are Claude-targeted, which aligns with the sanctioned model stack.

| Tool | Source | Note |
| --- | --- | --- |
| PentAGI | https://github.com/vxcontrol/pentagi | Autonomous penetration testing LLM agent |
| HexStrike AI | https://github.com/0x4m4/hexstrike-ai | Automated pentesting agent |
| CAI (Cybersecurity AI) | https://github.com/aliasrobotics/CAI | AI security framework |
| RedAmon | https://github.com/samugit83/redamon | AI red team automation |
| raptor | https://github.com/gadievron/raptor | Claude-based offensive agent |

> **Catalogue source — promptfoo, "Top 5 open-source AI red-teaming tools (2025)"** — https://www.promptfoo.dev/blog/top-5-open-source-ai-red-teaming-tools-2025/. Three of its picks (Promptfoo, PyRIT, Garak) are already wired in adapters above. **FuzzyAI** and **promptmap2** are added here as reviewed-not-wired. **Honorable mentions** worth future evaluation: **Viper** (general adversarial simulation platform with visual UI and AI-augmented operations) and **Woodpecker** by Operant AI (unified Kubernetes red-team + AI model-testing engine) — verify upstream URLs before wiring.

#### Static analysis additions (language- or platform-specific, defer until in scope)

Reviewed from the OWASP Source Code Analysis Tools community page. Deferred because the language or framework isn't currently inside the AI workload surface — pull in if/when MCP servers, agent tooling, or business apps land in these stacks.

| Tool | Source | Languages / Note |
| --- | --- | --- |
| Brakeman | https://github.com/presidentbeef/brakeman | Ruby on Rails |
| Dawnscanner | https://rubygems.org/gems/dawnscanner | Ruby / Sinatra / Padrino |
| sobelow | https://github.com/nccgroup/sobelow | Phoenix (Elixir) |
| clj-holmes | https://github.com/clj-holmes/clj-holmes | Clojure |
| Psalm (security) | https://psalm.dev/docs/security_analysis/ | PHP — Vimeo's Psalm with security mode |
| Progpilot | https://github.com/designsecurity/progpilot | PHP — XSS / SQLi taint analysis |
| PHPStan | https://phpstan.org/ | PHP static analysis |
| phpcs-security-audit | https://github.com/FloeDesignTechnologies/phpcs-security-audit | PHP_CodeSniffer security ruleset |
| parse | https://github.com/psecio/parse | PHP |
| OWASP ASST | https://github.com/OWASP/ASST | PHP + MySQL OWASP Top 10 |
| L3X | https://github.com/VulnPlanet/l3x | Rust + Solidity (pattern + AI) |
| Flawfinder | https://www.dwheeler.com/flawfinder/ | C / C++ |
| Splint | https://www.splint.org/ | C |
| FindSecBugs (SpotBugs plugin) | https://find-sec-bugs.github.io/ | Java — secondary opinion to Semgrep + CodeQL |
| SpotBugs | https://spotbugs.github.io/ | Java — host for FindSecBugs |
| MobSF | https://github.com/MobSF/Mobile-Security-Framework-MobSF | Mobile (Android/iOS) — already in Mobile bucket |
| mobsfscan | https://github.com/MobSF/mobsfscan | Mobile (Java/Kotlin/Swift/Obj-C) |
| binskim (Microsoft) | https://github.com/Microsoft/binskim | Windows PE / ELF binary SAST |
| NaiveSystems Analyze | https://github.com/naivesystems/analyze | C / C++ / Java functional safety |
| Pyre (Meta) | https://pyre-check.org/ | Python type-check + limited security taint |

#### Heavyweight / orchestration SAST platforms (defer)

Org-scale platforms that overlap or wrap what's already wired (Semgrep, CodeQL, Bandit, Bearer, Trivy). Worth knowing about for second-opinion deployments or when the org standardizes on a single SAST platform.

| Tool | Source | Note |
| --- | --- | --- |
| joern (code property graph) | https://joern.io/ | Multi-lang CPG (C/C++/Java/JS/Python/Kotlin/PHP/Go/Ruby/Swift/C#); heavyweight but powerful. |
| SonarQube Community Edition | https://www.sonarsource.com/products/sonarqube/downloads/success-download-community-edition/ | LGPLv3, the free/OSS edition. 15+ languages (Java, JS/TS, Python, C#, PHP, Kotlin, Go, Ruby, Scala, etc.). Server platform — Java + Postgres; results consumed via REST API. Org-scale SAST candidate. |
| Fluid Attack's Scanner | https://github.com/fluidattacks/scanner | SAST + DAST + SCA combo; claims perfect OWASP Benchmark. |
| HuskyCI | https://github.com/globocom/huskyCI | Orchestrates other security scanners; meta-tool overlapping with this pipeline's role. |
| ShiftLeft Scan (sast-scan) | https://github.com/ShiftLeftSecurity/sast-scan | DevSecOps platform bundling open scanners. |
| AWS Automated Security Helper | https://github.com/aws-samples/automated-security-helper | Multi-tool AWS wrapper (CFN/Terraform/Python/JS). |
| HefestoAI | https://github.com/artvepa80/Agents-Hefesto | AI-powered code-quality guardian for AI-generated code; emerging category. |
| Graudit | https://github.com/wireghoul/graudit/ | Lightweight grep-based; superseded by Semgrep for pipeline use. |
| nodejsscan | https://github.com/ajinabraham/nodejsscan | Web UI version of njsscan (already wired); use the wired one. |
| nancy | https://github.com/sonatype-nexus-community/nancy | Go dependency CVE; covered by Grype + OSV-Scanner already. |
| talisman (Thoughtworks) | https://thoughtworks.github.io/talisman/ | Pre-commit secret scanner; covered by TruffleHog + Gitleaks + detect-secrets. |
| LunaTrace | https://www.lunasec.io/ | SBOM/SCA; overlap with Syft + Grype. |
| GolangCI-Lint (gosec aggregator) | https://golangci-lint.run/ | Go linter aggregator embedding gosec — wired via gosec adapter directly. |

#### OpenAPI / API-spec security (defer)

OpenAPI/Swagger contract auditing — relevant for AI gateway and MCP server specs once the org standardizes on the contract-first approach.

| Tool | Source | Note |
| --- | --- | --- |
| APIsecurity.io Security Audit | https://apisecurity.io | Online OpenAPI/Swagger static analysis. |
| 42Crunch VS Code OpenAPI Editor | https://marketplace.visualstudio.com/items?itemName=42Crunch.vscode-openapi | IDE-side spec linting + security audit. |

> **Catalogue source — OWASP Source Code Analysis Tools community page** (https://owasp.org/www-community/Source_Code_Analysis_Tools). Already-wired matches: Bandit, Bearer, Grype, Semgrep, Syft. **Wired this round:** gosec, OWASP Noir, SplxAI Agentic Radar, Adobe Ride. **Reviewed and skipped (abandoned upstream):** FindBugs (legacy, replaced by SpotBugs), Microsoft PREFast (last update 2006), VisualCodeGrepper (SourceForge, abandoned), Google CodeSearchDiggity (depends on retired Google Code Search). **Reviewed and skipped (commercial-leaning despite list inclusion):** PVS-Studio, ParaSoft, Spectral / SpectralOps, HCL AppScan CodeSweep family, Puma Scan Professional, .NET Code Analysis (FxCop successor), GitHub Advanced Security (uses CodeQL — already wired directly).

#### Mobile / wireless / specialty (out of scope today)

| Tool | Source |
| --- | --- |
| MobSF | https://github.com/MobSF/Mobile-Security-Framework-MobSF |
| aircrack-ng | https://github.com/aircrack-ng/aircrack-ng |
| Kismet | https://github.com/kismetwireless/kismet |
| Hashcat | https://github.com/hashcat/hashcat |
| John the Ripper | https://github.com/openwall/john |

### Methodology references (reviewed, no tool additions)

External writeups reviewed for tool ideas. These sources are about *integration patterns* (CI/CD, GitHub Actions, shift-left workflows) rather than tool catalogues. Recording the URL so the catalogue is auditable.

| Source | URL | Outcome |
| --- | --- | --- |
| johal.in — "CI/CD Pipeline Security: Integrating SAST and DAST Tools in GitHub Actions Workflows (2025)" | https://johal.in/ci-cd-pipeline-security-integrating-sast-and-dast-tools-in-github-actions-workflows-2025/ | Site blocks bot fetch (403); content extracted from search snippets only. Free/OSS tools mentioned: ZAP, CodeQL — both already wired. Commercial tools mentioned (out of catalogue scope): Fortify, Veracode, Checkmarx, WebInspect, Acunetix, Snyk. **Net adapter additions: zero.** Article *did* prompt the GitHub Actions wiring at `.github/workflows/ai-protect.yml`. |
| primeop/Secure-SDLC-DevSecOps-Pipeline — runnable GHA reference for containerized SAST + DAST + SCA | https://github.com/primeop/Secure-SDLC-DevSecOps-Pipeline | Tools integrated: Semgrep, SonarQube, ZAP, Burp, Trivy, Syft — **all already wired or catalogued**. Pattern of interest: tool-specific Docker images invoked from GHA jobs (rather than `pip install` of the scanner). 26 commits, 0 stars, no license declared, early-stage. **Net adapter additions: zero. Net pattern takeaway: candidate Docker shape for the daemon-style adapters (ZAP, Burp, Caldera, Metasploit, Sonar) — see "Containerization plan" below.** |

### Containerization plan (deferred)

The pipeline itself is `pip install` + CLI today, which is the right default — most wired adapters are CLI tools that work fine off `$PATH`. But a handful of adapters are **daemon-shape** services that benefit materially from containerization, both for reproducibility and for CI ephemerality:

- **ZAP** — `ghcr.io/zaproxy/zaproxy:stable` is the canonical distribution; we already document `docker run` in the adapter docstring.
- **Burp Suite Enterprise** — vendor ships an image; the REST API the adapter uses is the same.
- **Caldera (MITRE)** — runs as a server (`mitre/caldera` Docker image); operations are submitted via REST.
- **Metasploit** — daemon mode behind RPC; metasploit-framework image exists.
- **SonarQube** — when wired, will run as a containerized server.
- **Sandboxed mutation tools** (atomic, sqlmap exploit modules) — strong fit for ephemeral container hosts so the agent runtime doesn't accumulate state.

The realistic minimum viable container story is therefore a `docker-compose.yml` that brings up the daemon services (ZAP + Caldera + Sonar + maybe Burp) and a thin `Dockerfile` that pins the pipeline runner Python environment. CLI scanners (semgrep, bandit, trufflehog, gosec, etc.) keep being installed into the runner image rather than getting their own containers — the per-tool-image pattern primeop uses adds operational cost without much benefit for those.

This is recorded as deferred — pull in when the team actually wants ephemeral CI scans or when Platform Engineering asks for a containerized deployment artifact.

### Agent-skills library (future investigation, deferred)

**[mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)** — a community collection of ~754 agent "skill" files (YAML-frontmatter markdown procedures conforming to the agentskills.io standard, Apache-2.0). **Community project, not official Anthropic.** Not pipeline-adapter material — these are procedural knowledge documents an agent (Claude Code, Cursor, etc.) discovers and executes, not scanners that emit findings.

Where it would fit if integrated:

- **Claude Code skills for the five verticals** — curate down (754 is far too many to load wholesale) to Threat Hunt (~55 skills), Red Team (~24), Incident Response (~25), Digital Forensics (~37), Malware Analysis (~39), Threat Intel. Drop the curated subset into `~/.claude/skills/`. Entry point: `npx skills add mukul975/Anthropic-Cybersecurity-Skills`.
- **Remediation side of the pipeline, not the scanning side** — for findings that need judgment rather than a deterministic one-line patch (e.g. a Bearer critical that warrants an investigation), an agent following an IR / threat-hunt skill is the right shape. Future hook in `ai_protect/remediate/`, not `ai_protect/adapters/`.
- **Phase 1 playbook-as-code scaffold** — provides a template structure (prerequisites → workflow → verification) with MITRE ATT&CK / ATLAS / NIST CSF 2.0 / D3FEND / NIST AI RMF mappings already wired, which lines up with HIPAA/HITRUST audit-evidence needs (those map through NIST). A starting library for codifying the team's own playbooks, not a finished product.

Caveats to resolve before integrating: **zero healthcare-specific skills** (no HIPAA breach containment, no PHI minimum-necessary audit, no medical-device forensics — the team would fill that gap); community-maintained, so fine for procedural scaffolding but not for anything cited as compliance evidence without vetting; v1.2.0 as of April 2026, 6.2k stars.

### Tools reviewed and not pursued

Single-tool repositories evaluated and explicitly skipped. Recorded so the catalogue stays auditable and so the same source isn't re-evaluated.

| Source | URL | Reason skipped |
| --- | --- | --- |
| alekzandren/Automated_Vulnerability_Scanner (PySec-Hybrid) | https://github.com/alekzandren/Automated_Vulnerability_Scanner | Educational-grade Python-only AST scanner (`eval`/`exec`/`os.system` detection). 2 stars, 11 commits, 0 forks. Strict subset of what wired-in `bandit` already covers, with much smaller community validation. MIT licensed; not maintained at production grade. |

### How to add a new tool

1. Pick the source from the catalogues above (or add a new one to the relevant table here first).
2. Install the binary or pip package; add to `~/bin/` or `~/.local/bin/`.
3. Create `ai_protect/adapters/<name>.py` subclassing `Adapter`.
4. Register in `ai_protect/adapters/registry.py` and add a `ai_protect/ui/catalog.py` entry.
5. Add the call to the relevant `ai_protect/core/policy.py` tier × stage.
6. Add a test in `ai_protect/tests/`.
7. Update this section of the README so the source is recorded.

---

## Resuming a Claude Code session in this project

This project's Claude Code config lives under `/home/user/.claude/projects/ai-protect` (not the default `~/.claude`). To resume a prior session in a new terminal:

```bash
cd /home/user/.claude/projects/ai-protect && export CLAUDE_CONFIG_DIR=/home/user/.claude/projects/ai-protect PATH=$HOME/bin:$HOME/.local/bin:$PATH && claude --resume --dangerously-skip-permissions --add-dir /home/user/ai-protect --add-dir /opt/app
```

What each flag does:
- `CLAUDE_CONFIG_DIR=/home/user/.claude/projects/ai-protect` — points Claude at the project-scoped config + session storage (where conversations for this project actually live).
- `PATH=$HOME/bin:$HOME/.local/bin:$PATH` — makes the installed pipeline tools (nuclei, trufflehog, gitleaks, trivy, syft, grype, bearer, hadolint, dockle, ProjectDiscovery binaries, plus pip-installed garak / bandit / semgrep / sqlmap / njsscan / detect-secrets) available immediately.
- `claude --resume` — interactive picker over saved conversations; pick the one you want.
- `--dangerously-skip-permissions` — bypasses tool permission prompts (one-time confirmation at startup).
- `--add-dir /home/user/ai-protect --add-dir /opt/app` — grants tool access to the repo and the scan target without per-file prompts.

Optional: persist the config-dir for any future shell:

```bash
echo 'export CLAUDE_CONFIG_DIR=/home/user/.claude/projects/ai-protect' >> ~/.bashrc
```

---

## License and distribution

Internal — Offensive Security. Prepared by the Office of the Director, Offensive Security. Not for external distribution without explicit approval from the CISO.
