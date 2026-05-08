# `pipeline/` — the ai-protect AI assurance pipeline

This is the runnable counterpart to the v2.1 operating model and the technical companion. Same architecture; same risk-tiering; same five-stage SDLC; same compliance posture — now as code you can execute.

The pipeline is the paved road. An AI app or agent registers a manifest, the pipeline classifies it, then routes it to the right tools at the right tier × stage. Every adapter normalizes its output to the same finding schema, every finding auto-tags HIPAA / HITRUST / NIST AI RMF / MITRE ATLAS controls, and the output streams to dashboards (technical for the operators, executive for the board).

```
manifest.yml
   │
   ▼
[ tiering ]  ─►  Tier 1-4 decision (forced rules: PHI / clinical / external)
   │
   ▼
[ orchestrator ]  reads policy table  →  runs adapters per (tier, stage)
   │
   ├─►  manifest_validator   (every tier, intake)
   ├─►  threat_model_check   (Tier 1-2, design)
   ├─►  trufflehog           (build)
   ├─►  nuclei               (build, Tier 1-2)
   ├─►  garak                (build + preprod)
   ├─►  pyrit                (build + preprod)
   ├─►  mcp_scope            (preprod, Tier 1-2 blocking)   ← highest-leverage
   ├─►  burp                 (preprod, Tier 1-2)
   ├─►  metasploit           (preprod, Tier 1 only, authorized exploit list)
   ├─►  atomic               (preprod, Tier 1, allow_mutation=true)
   ├─►  eval_suite           (preprod, hallucination/bias/jailbreak)
   └─►  telemetry_drift      (production)
   │
   ▼
[ FindingStore ]  append-only JSONL
   │
   ├─►  reporting/technical   (per-app, per-adapter detail)
   └─►  reporting/executive   (board / risk-committee rollup)
```

## Quickstart

```bash
# 1. Install Python deps (most adapters degrade gracefully if their tool isn't installed)
pip install -r pipeline/requirements.txt

# 2. Tier-classify the example clinical assistant manifest
python -m pipeline.cli tier pipeline/manifests/example_clinical_assistant.yml

# 3. Run a specific stage (preprod has the deepest coverage for Tier 1)
python -m pipeline.cli --findings /tmp/findings.jsonl run \
    pipeline/manifests/example_clinical_assistant.yml --stage preprod

# 4. Run every stage end-to-end (stops at first gate failure)
python -m pipeline.cli --findings /tmp/findings.jsonl run \
    pipeline/manifests/example_clinical_assistant.yml --all

# 5. Generate dashboards
python -m pipeline.cli --findings /tmp/findings.jsonl report --kind technical
python -m pipeline.cli --findings /tmp/findings.jsonl report --kind executive

# 6. Inspect what runs where
python -m pipeline.cli adapters
python -m pipeline.cli policy --tier 1 --stage preprod

# 7. Tests
python -m pytest pipeline/tests/ -q
```

## Manifest schema

Every AI app or agent declares itself with a YAML manifest (`pipeline/manifests/example_*.yml`). The manifest is the single source of truth for tiering, adapter selection, and compliance evidence.

Key fields:

| Field | Purpose |
| --- | --- |
| `data_sensitivity` | `phi` / `pii` / `financial` / `confidential` / `public`. PHI forces Tier 1. |
| `decision_impact` | `irreversible` / `clinical_influence` / `automated_action` / `advisory`. Clinical forces Tier 1. |
| `integration_footprint` | `external_action` / `agent_tool_use` / `write_back` / `read_only`. |
| `user_population` | `external` / `enterprise` / `team` / `single_user`. External + non-advisory forces Tier 1. |
| `models` | List of model endpoints. PHI handling requires `via_gateway: true` AND `baa_covered: true`. |
| `mcp_servers` | Each declares tier, data_scope, actions, side_effects. Tier inheritance flows MCP → agent. |
| `expected_actions` | Ground-truth allow-list. Anything an MCP exposes outside this set is a scope violation. |
| `target.allow_mutation` | Required `true` for adapters that modify state (atomic-red-team, burp active, exploit modules). |
| `target.test_user_token_env` | Env var holding a test token; if set, mcp_scope probes a forbidden action live. |
| `threat_model_path` | Required for Tier 1/2 at design stage. |

## Tools wired in

Every adapter implements the same interface (`pipeline/adapters/base.py`): preflight → run → return list of normalized `Finding` objects. The orchestrator handles the rest.

| Adapter | Tool | Stage | Notes |
| --- | --- | --- | --- |
| `manifest_validator` | (built-in) | intake | Schema + sanctioned-infra policy. PHI without BAA fails immediately. |
| `threat_model_check` | (built-in) | design | Tier 1-2 require a signed-off threat model artifact. |
| `trufflehog` | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | build | Source-tree secret scanning. CRITICAL on verified hits. |
| `nuclei` | [Nuclei](https://github.com/projectdiscovery/nuclei) | build | Template-driven web vuln scan. |
| `garak` | [NVIDIA garak](https://github.com/NVIDIA/garak) | build + preprod | LLM probes (prompt injection, leakage, jailbreak, encoding). |
| `pyrit` | [Microsoft PyRIT](https://github.com/Azure/PyRIT) | build + preprod | Multi-turn orchestrators (injection, encoding, multiturn, crescendo, leakage). |
| `mcp_scope` | (built-in) | preprod blocking | **Highest-leverage control.** Tier inheritance, action allow-list, side-effect, live token-scope probe. |
| `burp` | [PortSwigger Burp Suite](https://portswigger.net/burp) | preprod | REST API client for passive/active scans of the surrounding app. |
| `metasploit` | [Rapid7 Metasploit](https://github.com/rapid7/metasploit-framework) | preprod | Auxiliary scanners by default; exploits require Tier 1 + explicit `authorized_exploits` list. |
| `atomic` | [Red Canary Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | preprod | MITRE ATT&CK technique emulation against the agent runtime host. Validates EDR detection coverage. |
| `eval_suite` | (built-in hooks) | preprod blocking | Hallucination / bias / jailbreak thresholds. Plug TruthfulQA / MedQA / custom QA harness. |
| `telemetry_drift` | SCV correlation API | production | Drift across prompts, tool calls, policy events, token velocity. |
| `anomaly_detector` | (alias) | production | Lighter-weight production-stage check. |

Tools from the [RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools) catalog included today: `trufflehog`, `nuclei`, `metasploit`. The adapter base class makes adding more (`prowler`, `kubehunter`, `subfinder`, etc.) a 50-line file.

## Risk tiering

Implements the v2.1 four-tier framework verbatim. See `pipeline/core/tiering.py` for the dimension scoring and forced-Tier-1 rules.

```
Tier 1   PHI / clinical / external-facing            embedded review + manual red team
Tier 2   sensitive internal action / write-back      embedded review + automated red team
Tier 3   internal advisory with broad reach          async checklist + automated scanning
Tier 4   low-impact assistive                        paved-road template + secret scan only
```

**Forced Tier 1:** PHI handling; clinical decision influence; external-facing with non-advisory impact. **Tier inheritance:** the agent's tier ≤ the most restrictive MCP it uses (`min` of MCP tier numbers wins).

## Policy table — what runs at what tier × stage

`pipeline/core/policy.py` is the operating model in code. Every (tier, stage) pair maps to an ordered list of `AdapterCall` entries with `blocking: bool` and `config: dict`. Change the table to change what the team runs.

```
python -m pipeline.cli policy --tier 1 --stage preprod
Tier 1 × stage preprod:
  - garak [BLOCKING]  config={'probes': 'all'}
  - pyrit [BLOCKING]  config={'strategies': ['multiturn', 'encoding', 'injection', 'crescendo']}
  - mcp_scope [BLOCKING]
  - burp                config={'scan': 'active'}
  - atomic              config={'techniques': ['T1059', 'T1567', 'T1071']}
  - eval_suite [BLOCKING]  config={'hallucination': True, 'bias': True, 'jailbreak': True}
```

## Findings & compliance auto-tagging

Every adapter produces `Finding` objects (`pipeline/core/findings.py`). The store is append-only JSONL — adapters write, dashboards read.

```python
@dataclass
class Finding:
    finding_id: str
    app_name: str
    tier: int
    stage: str
    adapter: str
    category: Category          # prompt_injection, jailbreak, data_leakage, ...
    severity: Severity          # info / low / medium / high / critical
    title: str
    description: str
    evidence: dict              # prompt, output, payload, hash
    affected: dict              # which model, MCP, host, target
    compliance: list[str]       # ["HIPAA-164.312(a)(1)", "MITRE-ATLAS-AML.T0051", ...]
    remediation: str | None
    references: list[str]
    fingerprint: str            # stable hash for dedup
```

`pipeline/core/compliance.py` maps every finding category to HIPAA, HITRUST, NIST AI RMF, MITRE ATLAS, and FDA SaMD identifiers. The mapping is deliberately conservative — auditors prefer over-coverage.

## Dashboards

```
EXECUTIVE DASHBOARD — ai-protect pipeline
============================================================

VELOCITY
  Apps in pipeline            5
  Tier 1 (PHI/clinical/ext)   2
  Tier 2 (internal action)    1
  Tier 3 (internal advisory)  1
  Tier 4 (low-impact)         1

RISK MADE VISIBLE
  Open HIGH+ findings         12
    Tier 1                    8
    Tier 2                    3
    Tier 3                    1
    Tier 4                    0

  Top finding categories (HIGH+):
    prompt_injection          5
    data_leakage              3
    scope_violation           2
    jailbreak                 2

FOOTING ESTABLISHED — control evidence touched
  HIPAA                       28 evidence records
  HITRUST                     21 evidence records
  NIST                        17 evidence records
  MITRE-ATLAS                  9 evidence records
```

## Safety posture

This pipeline orchestrates dual-use security tools against AI workloads. Defaults are conservative.

- **`Adapter.requires_mutation`** — adapters that modify target state (atomic-red-team, burp active, metasploit exploits) refuse to run unless `target.allow_mutation: true` in the manifest.
- **Exploit modules** require Tier 1 AND an explicit `authorized_exploits` list in the adapter config. Auxiliary scanners are the default Metasploit posture.
- **Atomic Red Team** requires the techniques to be enumerated explicitly; there is no "run everything" mode.
- **Token probes** in `mcp_scope` only execute if the manifest declares `target.test_user_token_env`. Without it the adapter performs static checks only.
- **`--dry-run`** lists what would run without invoking adapters.

## Layout

```
pipeline/
├── README.md                       # this file
├── cli.py                          # python -m pipeline.cli ...
├── requirements.txt
├── core/
│   ├── manifest.py                 # YAML schema → Manifest dataclass
│   ├── tiering.py                  # 4-dim scoring, forced rules, MCP inheritance
│   ├── findings.py                 # Finding, Severity, Category, FindingStore
│   ├── compliance.py               # category → control identifiers
│   ├── policy.py                   # tier × stage → adapter list (the operating model)
│   └── orchestrator.py             # ties it all together
├── adapters/
│   ├── base.py                     # Adapter base class + exceptions
│   ├── registry.py                 # name → class
│   ├── manifest_validator.py
│   ├── threat_model_check.py
│   ├── garak.py
│   ├── pyrit.py
│   ├── atomic.py
│   ├── burp.py
│   ├── metasploit.py
│   ├── mcp_scope.py
│   ├── nuclei.py
│   ├── trufflehog.py
│   ├── eval_suite.py
│   └── telemetry_drift.py
├── reporting/
│   ├── technical.py                # per-app, per-adapter detail
│   └── executive.py                # board-style rollup
├── manifests/                      # example app/agent declarations
│   ├── example_clinical_assistant.yml      # Tier 1
│   ├── example_internal_advisor.yml        # Tier 3
│   └── example_low_risk_assistive.yml      # Tier 4
├── fixtures/
│   └── clinical_assistant_threat_model.yml # sample TM artifact
└── tests/
    ├── test_tiering.py
    ├── test_findings.py
    ├── test_policy.py
    └── test_orchestrator.py
```

## Extending

Adding a new tool is one new file under `pipeline/adapters/` plus a registry line and a policy-table entry.

1. Create `pipeline/adapters/yourtool.py` with a class that inherits from `Adapter`. Implement `preflight()` (raise `AdapterUnavailable` if the tool isn't installed) and `run()` (return a list of Finding objects via `self.make_finding(...)` so compliance auto-tagging fires).
2. Register it in `pipeline/adapters/registry.py`.
3. Add it to `pipeline/core/policy.py` for the tier × stage combinations where it should fire.
4. Add a test in `pipeline/tests/`.

Done. The orchestrator picks it up, the dashboards aggregate it, the compliance tags accrete in audit evidence.
