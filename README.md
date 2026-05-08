# ai-protect

Offensive security operating model for the enterprise AI transformation in a major healthcare organization. This repository contains the strategic proposal, two single-page distribution variants, the technical companion that operationalizes the proposal, the seven SVG diagrams that appear inside them, and the build scripts that generate every document deterministically from source.

The work is anchored on a single strategic reframe: offensive security as the **empirical truth function for AI risk** — the team that proves what does and does not work, while every other voice in the AI conversation (vendors, sponsors, even AI governance) has incentives to be optimistic.

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
| **`diagrams/*.svg` + `*.png`** | Reused inside companion + slide decks | Seven diagrams: pipeline overview, v2.1 mapping, AI red-team kill chain, vertical ownership, technical dashboard, executive dashboard, phased rollout. SVG for editing; PNG (1800px wide) for embedding. |

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

## The pipeline (`pipeline/`)

The runnable counterpart to v2.1 and the technical companion. An AI app or agent registers a YAML manifest, the pipeline tier-classifies it, then routes it to the right tools at the right tier × stage. Every adapter normalizes output to the same finding schema; every finding auto-tags HIPAA / HITRUST / NIST AI RMF / MITRE ATLAS controls. See **[`pipeline/README.md`](pipeline/README.md)** for the full architecture and adapter catalog.

**Tools wired in today** (`pipeline/adapters/`):

- **AI-native:** [NVIDIA garak](https://github.com/NVIDIA/garak), [Microsoft PyRIT](https://github.com/Azure/PyRIT), built-in `mcp_scope` validator (the highest-leverage control in v2.1), built-in `eval_suite` (hallucination / bias / jailbreak gates).
- **Classical pen test:** [PortSwigger Burp Suite](https://portswigger.net/burp) (REST), [Rapid7 Metasploit](https://github.com/rapid7/metasploit-framework) (RPC, auxiliary by default), [Red Canary Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (MITRE ATT&CK technique emulation against the agent runtime host).
- **From [RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools):** [Nuclei](https://github.com/projectdiscovery/nuclei), [TruffleHog](https://github.com/trufflesecurity/trufflehog).
- **Built-in policy gates:** `manifest_validator` (intake), `threat_model_check` (design, Tier 1-2), `telemetry_drift` (production).

**Quickstart:**

```bash
pip install -r pipeline/requirements.txt

# Tier-classify
python -m pipeline.cli tier pipeline/manifests/example_clinical_assistant.yml

# Run preprod gates end-to-end (degrades gracefully when external tools aren't installed)
python -m pipeline.cli --findings /tmp/findings.jsonl run \
    pipeline/manifests/example_clinical_assistant.yml --stage preprod

# Dashboards
python -m pipeline.cli --findings /tmp/findings.jsonl report --kind executive
python -m pipeline.cli --findings /tmp/findings.jsonl report --kind technical

# What runs where
python -m pipeline.cli adapters
python -m pipeline.cli policy --tier 1 --stage preprod

# Tests
python -m pytest pipeline/tests/ -q
```

The pipeline ships with three example manifests covering the spread: Tier 1 clinical assistant, Tier 3 HR-policy advisor, Tier 4 single-user code summarizer. Adapters that need an external tool (garak, nuclei, etc.) raise `AdapterUnavailable` and are skipped non-fatally — install the tools you actually plan to exercise.

---

## Repository layout

```
ai-protect/
├── README.md                       # This file
├── .gitignore
├── pipeline/                       # The runnable AI assurance pipeline
│   ├── README.md                   # Pipeline architecture, adapter catalog, extension guide
│   ├── cli.py
│   ├── requirements.txt
│   ├── core/                       # manifest, tiering, findings, compliance, policy, orchestrator
│   ├── adapters/                   # garak, pyrit, atomic, burp, metasploit, mcp_scope, nuclei, trufflehog, ...
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
│   ├── build_diagrams.py           # Builds the 7 SVGs + PNGs in diagrams/
│   ├── build_doc.py                # Builds pipeline_companion_v1.docx
│   ├── build_onepagers.py          # Builds one_pager_v1.docx + exec_brief_v1.docx
│   └── requirements.txt            # python-docx, cairosvg
└── diagrams/                       # 7 SVG diagrams + PNG renders (1800px wide)
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

### Wired-in adapters (current state)

Adapters present in `pipeline/adapters/` and live in the policy table. Group by category matches the `/about` page in the live UI.

#### Policy gates (built-in and runtime)

| Adapter | Source |
| --- | --- |
| `manifest_validator` | (built-in) — `pipeline/adapters/manifest_validator.py` |
| `threat_model_check` | (built-in) — `pipeline/adapters/threat_model_check.py` |
| `mcp_scope` | (built-in) — `pipeline/adapters/mcp_scope.py` |
| `guardrails` (NeMo) | https://github.com/NVIDIA/NeMo-Guardrails |

#### Static analysis · secrets · dependencies

| Adapter | Source |
| --- | --- |
| `trufflehog` | https://github.com/trufflesecurity/trufflehog |
| `gitleaks` | https://github.com/gitleaks/gitleaks |
| `detect_secrets` | https://github.com/Yelp/detect-secrets |
| `semgrep` | https://github.com/semgrep/semgrep |
| `bandit` | https://github.com/PyCQA/bandit |
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
| `recon` chain | https://github.com/projectdiscovery/subfinder · https://github.com/projectdiscovery/httpx · https://github.com/projectdiscovery/naabu · https://github.com/projectdiscovery/katana |
| `sqlmap` | https://github.com/sqlmapproject/sqlmap |
| `dockle` | https://github.com/goodwithtech/dockle |

#### AI red team · eval

| Adapter | Source |
| --- | --- |
| `garak` | https://github.com/NVIDIA/garak |
| `pyrit` | https://github.com/Azure/PyRIT |
| `promptfoo` | https://github.com/promptfoo/promptfoo |
| `deepeval` (fallback for promptfoo adapter) | https://github.com/confident-ai/deepeval |
| `eval_suite` | (built-in) — `pipeline/adapters/eval_suite.py` |

#### Production · telemetry

| Adapter | Source |
| --- | --- |
| `telemetry_drift` | (built-in) — `pipeline/adapters/telemetry_drift.py` |
| `anomaly_detector` (alias) | (built-in) — `pipeline/adapters/telemetry_drift.py` |

### Reviewed but not yet wired

Tools that have been evaluated and are documented for future wiring. Each line is a pre-baked candidate — when scope changes (cloud presence, AD-integrated workloads, K8s deployment, mobile surface), add them as adapters under `pipeline/adapters/` and register in `pipeline/adapters/registry.py` + `pipeline/core/policy.py`.

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

#### Mobile / wireless / specialty (out of scope today)

| Tool | Source |
| --- | --- |
| MobSF | https://github.com/MobSF/Mobile-Security-Framework-MobSF |
| aircrack-ng | https://github.com/aircrack-ng/aircrack-ng |
| Kismet | https://github.com/kismetwireless/kismet |
| Hashcat | https://github.com/hashcat/hashcat |
| John the Ripper | https://github.com/openwall/john |

### How to add a new tool

1. Pick the source from the catalogues above (or add a new one to the relevant table here first).
2. Install the binary or pip package; add to `~/bin/` or `~/.local/bin/`.
3. Create `pipeline/adapters/<name>.py` subclassing `Adapter`.
4. Register in `pipeline/adapters/registry.py` and add a `pipeline/ui/catalog.py` entry.
5. Add the call to the relevant `pipeline/core/policy.py` tier × stage.
6. Add a test in `pipeline/tests/`.
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
