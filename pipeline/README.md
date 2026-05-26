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
#    NB: --findings goes to a DURABLE path. /tmp is wiped on reboot, so any
#    findings written there are lost. The UI and all adapters share this file.
python -m pipeline.cli --findings ~/.ai-protect/findings.jsonl run \
    pipeline/manifests/example_clinical_assistant.yml --stage preprod

# 4. Run every stage end-to-end (stops at first gate failure)
python -m pipeline.cli --findings ~/.ai-protect/findings.jsonl run \
    pipeline/manifests/example_clinical_assistant.yml --all

# 5. Generate dashboards
python -m pipeline.cli --findings ~/.ai-protect/findings.jsonl report --kind technical
python -m pipeline.cli --findings ~/.ai-protect/findings.jsonl report --kind executive

# 6. Inspect what runs where
python -m pipeline.cli adapters
python -m pipeline.cli policy --tier 1 --stage preprod

# 7. Tests
python -m pytest pipeline/tests/ -q

# 8. Live findings web UI (Flask) — background poller + UI on one port
python -m pipeline.ui.server --findings ~/.ai-protect/findings.jsonl --port 3005
# open http://localhost:3005/
```

## Web UI

`pipeline/ui/` is a Flask app that reads the FindingStore on every request, so you can run a scan in one terminal and watch findings stream into the browser in another. The UI also runs the **intel feed poller** (a daemon thread that fetches CVE / threat feeds at each feed's configured interval) and surfaces an **overall system status lamp** on the home page (worst-of-three across feeds, scans, and findings-store health).

**Launch:**

```bash
# Durable findings path — survives reboots, shared by the CLI and the UI.
python -m pipeline.ui.server --findings ~/.ai-protect/findings.jsonl --port 3005
# open http://localhost:3005/
```

> **Findings path warning:** never use `/tmp/findings.jsonl` — Linux wipes `/tmp` on reboot and any findings there are lost. Use `~/.ai-protect/findings.jsonl` (or any path outside `/tmp`); the file is append-only and is created on first write.

**Findings**

- `/` — findings table with severity / app / adapter / category / fixable filters and the system-status lamp. Findings auto-resolved by a re-scan show a green "auto-resolved" provenance callout on `/finding/<id>` linking to the synthetic Change record.
- `/finding/<id>` — per-finding drill-down with description, remediation, evidence, affected, compliance tags (HIPAA · HITRUST · NIST AI RMF · MITRE ATLAS), references, and a **Related intel** section that lists any CVE matches the intel feeds have for the same vuln (post-scan cross-reference).
- `/findings.pdf`, `/findings.csv` — filter-aware exports.
- `/manifests`, `/manifests/new`, `/manifests/<name>/edit` — manifest CRUD with live tier preview. The edit form exposes the source-provider fields (see **Scanning from GitHub** below) and an `app_aliases` field that re-keys resolved Changes from a renamed predecessor onto the renaming inheritor's fingerprint namespace.
- `/history` — append-only timeline of every scan / change / finding event. Scan events include the app name (`app_name`) and the lifecycle phase (`scan.started` → `scan.done` / `scan.failed` / `scan.crashed` / `scan.stopped`); orphan transitions from power loss surface as `scan.crashed`; auto-resolutions surface as `scan.auto_resolved`.
- `/scan`, `/scan/<id>`, `/scan/<id>/stop` — launch a scan, follow its log, cancel it (SIGTERM → grace → SIGKILL on the process group). The launcher splits into SAST and DAST modes — see **Scan modes** below.
- `/remediations`, `/change/<id>` — approve / apply / revert proposed code changes.

**Intel feeds**

- `/feeds` — feed catalogue. Inline **Add feed** form (URL + polling period; format is auto-detected), per-row **Fetch / Edit / Pause / Resume / Delete / View intel** actions, **Fetch all** button at the section header, and an expandable **Recent fetches** detail per feed. Large clusters of feeds sharing a URL prefix (e.g. the 800+ `cvedaily.com/feed-tags/` per-tag feeds) auto-collapse into one `<details>` block with aggregate counts so the main table stays scannable.
- `/feeds/discover` — point at an aggregator page (e.g. `https://cvedaily.com/pages/tags/`) and the server scrapes `<a href>` links matching `.xml`/`.atom`/`.rss`/`.json` or `/feed`/`/rss`/`/atom`, then auto-detects the format of each candidate **in parallel** (ThreadPoolExecutor, ~3s for 800+ links). Operator picks via checkboxes; selected feeds are imported with `last_fetch_ts` staggered uniformly across the polling window to prevent a thundering herd on the next poller tick.
- `/feeds/validate` — JSON validator endpoint. Fetches the URL once, returns `{ok, detected_format, item_count, sample, error}`. Used by the **Validate first** button on the Add form so you know whether the as-is translator handles the feed or you need a custom one.
- `/feeds/<id>/fetch`, `/feeds/<id>/edit`, `/feeds/<id>/toggle`, `/feeds/<id>/delete` — per-feed actions. POST `/feeds/fetch-all` force-fetches every enabled feed.
- `/intel` — fetched CVE / threat items, filterable by severity and source feed. Each row links to the original advisory.

**Settings**

- `/settings` — schema-driven configuration persisted to `~/.ai-protect/config.json` (chmod 600 — holds PATs / GitHub App keys). Sections (each generated from `pipeline/core/settings.py`'s `SCHEMA` — adding a knob is one Field append, no template edits):
  - **Locale & time** — IANA timezone (free-text or curated dropdown), strftime date format. A Jinja `localtime` filter renders every epoch in the configured zone — feeds, history, intel rows, finding evidence all flip when you switch zones.
  - **Paths & storage** — findings file (default `~/.ai-protect/findings.jsonl`), manifests dir, source cache dir.
  - **Source providers** — default provider (local / github), GitHub base URL (github.com or GHES), visibility (public / private), auth method (PAT / GitHub App), clone strategy (per-scan / cached), default ref, clone depth. Progressive disclosure: pick `github` and the GitHub fields appear; pick `github_app` auth and the App ID / private-key-path / installation-id fields appear.
  - **DAST defaults** — max requests-per-second, max concurrent requests, per-adapter hard timebox (default 30 min), require-scope-prefix-for-crawlers (default on). See **Scan modes** below.
  - **Intel feeds defaults** — default polling interval, `intel_match` emission floor, disable-KEV-ratchet toggle.
  - **Remediation behavior** — auto-resolve-on-rescan toggle (default on). See **Auto-resolve on re-scan absence** below.
- `/docs` — step-by-step setup walkthroughs anchored from every settings field's `?` help bubble (PAT creation, GitHub App + installation-id retrieval, GHES URL format, DAST safety matrix, auto-resolve guards, etc.).

**System status lamp**

The home page (`/`) shows an overall **green / yellow / red** lamp computed as the worst-of-three across:

- **feeds** — red if any feed errored on its last fetch; yellow if any enabled feed is stale (no fetch within 2× its polling interval) or has never fetched; green otherwise.
- **scans** — red if any orphan scan didn't reconcile to a known terminal state; yellow if scans are running; green when idle.
- **store** — red if `--findings` points at `/tmp`; green if it's on a durable path.

The same payload is available at `/api/status` as JSON for external monitoring.

**JSON API**

- `/api/findings` — full or active-view findings list.
- `/api/stats` — counts by severity / category / adapter / app.
- `/api/status` — system status lamp payload.
- `/api/scan/<id>` — scan-status poll endpoint (used by the live scan page).

Visual style mirrors the v2.1 doc family — navy header, accent-orange rule, takeaway-blue pills, navy-banded tables; dark callouts (status lamp, additive-feeds banner, collapsible feed groups) use a navy panel class with light text.

## Scan modes (SAST vs DAST)

The `/scan` launcher splits into two distinct flows so static code analysis can't accidentally fire dynamic probes (and vice-versa), and so first-time DAST users can't accidentally aim heavy mutating tooling at a live system.

```
[ Source code (SAST) ]  [ Live target (DAST) ]
       23 adapters             14 adapters
```

**Classification** (`pipeline/core/scan_modes.py`): every adapter is bucketed using its catalog `kind` (static/dynamic/ai/policy) with a small set of explicit overrides for shape mismatches (`agentic_radar` reads agent source → SAST; `mcp_scope` probes a live MCP → DAST; `intel_match` is enrichment → pre-flight). Three always-run pre-flight adapters (`manifest_validator`, `threat_model_check`, `intel_match`) appear alongside both modes in a small "Pre-flight policy checks (when applicable)" callout so the audit story is honest about what runs.

**SAST mode** keeps the original manifest + stage + adapter form. The adapter dropdown filters to the SAST-only set.

**DAST mode** has a radio sub-tab — **Known app** (use the manifest's `target.base_url`) vs **Arbitrary URL** (one-off). The Arbitrary URL path builds a synthetic ephemeral Manifest in memory (`app_name = adhoc:<host>[:<port>]`, Tier 4, `target.allow_mutation=false`), serializes it to `~/.ai-protect/adhoc-scans/<scan_id>.yml` so the existing scan_runner subprocess can read it, and deletes the temp file via `try/finally` after the run completes (with a periodic janitor on every `/scan` GET as defense-in-depth).

The DAST adapter dropdown leads with "safe defaults" (`zap baseline + nuclei + mcp_scope`) so a first-time scan can't accidentally fire heavy mutating tools. Heavy options are tagged `· heavy / mutating` and require explicit `allow_active` / `allow_adversary` checkboxes.

**URL safety guards** (`pipeline/core/url_safety.py`):

- **Hard-deny** (never overridable, not even via `allow_internal_scan`):
  - `169.254.169.254` and named cloud-metadata hosts (`metadata.google.internal`, `metadata.azure.internal`, `metadata.oraclecloud.internal`).
  - URLs with embedded credentials (`user:pass@host`) — refused to keep tokens out of logs.
  - Non-`http(s)` schemes.
- **Default-deny** (overridable via per-manifest `target.network_allowed_zones` CIDR list, or per-scan `allow_internal_scan` typed-confirmation):
  - `127.0.0.0/8`, RFC1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT (`100.64/10`), link-local (`169.254/16`, `fe80::/10`), multicast (`224/4`, `ff00::/8`), IPv6 ULA (`fc00::/7`), reserved / docs / benchmark ranges.
- **DNS** is resolved fresh on every check (no cache), and the check rejects if **any** resolved A/AAAA matches a denied range — defeats DNS rebinding.
- **HTTPS-only by default**; an `allow_insecure_http` toggle exists for known internal targets that don't serve TLS.
- **Typed confirmation** required to enable an internal-network scan — checkbox + `Type ALLOW-INTERNAL` (case-sensitive) keystroke rather than a single click. PAL flagged checkboxes as too easy to toggle accidentally for this risk class.
- **One-time-per-host gate** in localStorage (24 h TTL) so the "I'm authorized to test this target" confirmation shows once per session per target host:port rather than every scan.

**DAST execution policies** (`pipeline/core/dast_config.py`): a typed `DastConfig` dataclass carries the intent — `max_rps`, `max_concurrency`, `timebox_s`, `scope_prefix`, `require_scope_prefix`, `allow_active`, `allow_adversary`. Built from `settings + manifest.target` overrides. Each adapter translates the dataclass to its native CLI flags via a small in-adapter mapping:

| Adapter | Flags from DastConfig |
| --- | --- |
| `nuclei` | `-rate-limit`, `-c`, subprocess timeout, **bare-origin refusal** |
| `zap` | `ascan threadsPerHost` via REST, polling deadline ← timebox, **bare-origin refusal** |
| `recon/subfinder` | result-cap (200), subprocess timeout |
| `recon/httpx` | `-threads`, `-rate-limit`, subprocess timeout |
| `recon/naabu` | `-rate` scaled (×5, capped 500/s), `-top-ports 100` |
| `recon/katana` | `-d` depth, `-c`, `-rate-limit`, `max_urls` cap, **bare-origin refusal** |
| `sqlmap` | `--threads` (≤10), subprocess timeout |
| `garak` | `--parallel_requests`, subprocess timeout |
| `burp` | scope.include rule + poll-deadline ← timebox, **bare-origin refusal** |
| `pyrit` | wall-clock between-strategies cap, `max_prompts_per_strategy` (in-process, no subprocess) |
| `metasploit` | two-level timebox (stage + per-module budget) |

**Bare-origin refusal** fires in the preflight of every crawler-class adapter (nuclei, ZAP, katana, burp) when `dast_require_scope_prefix_for_crawlers` is on (default) AND the target's path is `/` or empty. Bypass by scoping the manifest's `target.base_url` (e.g. `https://target.example.com/myapp/`) or unchecking the setting. Prevents "scan the whole domain" accidents.

## Scanning from GitHub (`pipeline/sources/`)

Each manifest can declare a **source provider** so the orchestrator materializes code from a remote repo before adapter dispatch. Two providers ship today:

| Provider | What it does |
| --- | --- |
| `local` | (default) passthrough — adapters scan `manifest.source_paths` on disk |
| `github` | shallow-clone the declared repo before each scan to a temp dir (or persistent cache); cleanup on exit, even on adapter errors |

Manifest fields added for GitHub: `source_provider`, `github_repo` (accepts `owner/name`, full HTTPS URL, or `git@github.com:owner/name.git`), `github_ref` (branch / tag / SHA — provider detects SHAs and uses explicit checkout), `github_clone_depth` (1 = shallow, default; 0 = full history).

**Auth methods** (configured on `/settings → Source providers`, persisted to `~/.ai-protect/config.json` chmod 600):

- **none** — public repos only.
- **PAT** — fine-grained personal access token, injected as `https://x-access-token:<TOKEN>@github.com/...`. Best for single-operator / homelab installs. See `/docs#source-github-pat` for the step-by-step (PAT scope: `Contents: Read` on selected repos).
- **GitHub App** — installable on an org, fine-grained per-repo permissions, **short-lived installation tokens auto-minted on demand** via JWT → `/app/installations/<id>/access_tokens`. Recommended for organizations. Requires PyJWT (`pip install PyJWT cryptography`).

**Clone strategies**:

- **per_scan** — shallow clone to a temp dir, removed on exit. No persistent state, slower on the 2nd scan.
- **cached** — clone once into `~/.ai-protect/src-cache/<owner>/<repo>`, `git fetch + checkout` on subsequent runs. Much faster on re-scans of the same repo.

**GHES** is supported: set `GitHub base URL` in settings to your enterprise hostname; the provider derives the API URL automatically (`github.com → api.github.com`; GHES → `<ghes>/api/v3`).

**Orchestrator hook**: `Orchestrator.run_stage()` wraps adapter dispatch with the provider's context manager: clone on enter, set `manifest.source_paths` to the materialized path, scan, **restore + cleanup on exit even on adapter errors**. Provider failure (clone failed, auth missing, etc.) records a single `_source` adapter result and gates the stage — no other adapters run when there's nothing to scan.

## Auto-resolve on re-scan absence

When a re-scan's `status=ok` adapters don't re-emit a fingerprint they previously emitted, the system automatically writes a Change with `state=applied` and `strategy=auto_resolve_absent`. The scanner is treated as ground truth: if it can't reproduce a vuln, the vuln is fixed/gone. Manual marking defeats the point of automation.

Implementation: `pipeline/core/auto_resolve.py:compute_and_apply()`, called by `Orchestrator.run_stage()` after the adapter loop completes. Guards (each prevents a real false-positive class):

- **Adapter scope** — only adapters with `status=ok` in this scan can auto-resolve their own fingerprints. If `garak` was `unavailable` (tool not installed), garak findings stay open — absence isn't evidence when the adapter didn't look.
- **Stage scope** — a `build`-stage scan can't auto-resolve `preprod` findings.
- **Honor revert** — if the operator manually reverted a Change for a fingerprint, that revert is a "leave it open" signal; no new auto-resolution Change is written until the operator re-engages through the normal workflow.
- **Skip already-resolved** — fingerprints whose latest Change is already `applied / validated / deployed` aren't duplicated.
- **Toggle** — `auto_resolve_on_rescan` in `~/.ai-protect/config.json` (default `on`). Off falls back to manual marking.

Provenance: every auto-resolved Change carries `actor="auto-resolve"`, a summary noting the scan id and adapter, plus an EventStore `scan.auto_resolved` row per fingerprint so the audit story is fully recoverable. The `/finding/<id>` page surfaces a green "auto-resolved by re-scan" callout when applicable, linking to the Change record and explaining how to override (revert the Change).

## Intel feeds (`pipeline/intel/`)

External CVE / threat feeds are first-class citizens: configured in the UI, polled in the background, and consulted during scans (see **Intel-scan integration** below).

| Component | What it does |
| --- | --- |
| `feeds.py` | `Feed` + `FeedStore` (latest-row-per-id wins), `FeedFetch` + `FeedFetchStore` (append-only history), `IntelItem` + `IntelStore` (deduped by hash of `source_feed_id + cve_id`). Persisted to `~/.ai-protect/feeds.jsonl`, `feed_fetches.jsonl`, `intel.jsonl`. |
| `translators.py` | One translator per format: **atom**, **rss**, **xml** (generic), **json**. `detect_format(raw)` peeks at the bytes (root tag / leading char) to pick the right one. JSON translator knows the CISA KEV shape (`cveID`, `vulnerabilityName`, `shortDescription`, `dateAdded`) and marks every KEV row severity=critical because KEV inclusion ≙ active exploitation in the wild. |
| `fetcher.py` | `fetch_feed()` (single fetch + translate + persist + log + status update), `validate_feed()` (dry-run for the UI validator), `start_poller()` (idempotent daemon thread, 30s tick, dispatches each feed whose interval has elapsed). |
| `status.py` | `overall_status()` computes the green/yellow/red lamp by combining feed / scan / store health. |

**Polling and stagger.** The poller wakes every 30s and dispatches each enabled feed whose `last_fetch_ts + poll_seconds` has elapsed. Bulk imports (via `/feeds/discover/import`) randomize `last_fetch_ts = now − uniform(0, poll_seconds)` per imported feed, so 800+ feeds spread their next-fetch times uniformly across the polling window — no thundering herd.

**Format support.** Atom 1.0, RSS 2.0, generic XML (iterates top-level children, pulls common fields by tag name), and JSON (handles JSON Feed 1.x, NVD-style `{"vulnerabilities":[...]}`, CISA KEV, and bare lists of records). When detection fails, the validator surfaces the parser's exact error so you can tell the operator whether the feed needs a custom translator.

**Operator workflow:**

```text
1. /feeds — paste a URL, click "Validate first" → "accept as-is" / "needs translator"
2. Click "Add feed" — format is auto-detected on save; rejects 400 if undetectable
3. Or /feeds/discover — point at an aggregator page and bulk-import every feed it links to
4. Watch /feeds for green status pills; /intel for the items as they arrive
5. /settings — pick your timezone; every timestamp on /feeds, /intel, /history reformats
```

## Intel-scan integration

Feeds **participate in scans**, not just sit alongside them. Two integration points:

**1. Enrichment** — `core/intel_enrichment.py:enrich_findings(findings)` is called by `Orchestrator._run_adapter` immediately before findings are persisted. For every finding from every adapter:

- regex-extract CVE ids from `title`, `description`, `references`, and `evidence` (flattened to JSON for the sweep)
- look each CVE up in `IntelStore`; stamp `evidence.intel_sources` (per-feed metadata), `evidence.cvss_max`, `evidence.kev_listed`, `evidence.kev_feeds`
- **KEV ratchet**: if any matching intel item is from a CISA-KEV-named feed (heuristic: `"kev"` or `"known exploited"` in feed name), the finding's severity is bumped to CRITICAL. Already-critical findings stay critical; never downgrades. `evidence.severity_bumped_from` records the original for audit trail.

This means a pip_audit finding for a CVE that's also on CISA's KEV list shows up as CRITICAL on the dashboard with KEV context attached, without any change to the pip_audit adapter.

**2. Detection** — the `intel_match` adapter (in `adapters/intel_match.py`, registered in the build slot for all three tiers in `policy.py`) emits *new* findings for intel items that mention assets your manifest declares:

- Tokenizes manifest `description` + `models[].name/provider/model` + `mcp_servers[].name`. Tokens are identifier-like only — start with a capital in the source text, OR contain a digit/hyphen/underscore, length ≥ 4. Hyphenated tokens are emitted whole AND split (`Drupal-based` → `{drupal-based, drupal, based}`).
- A big stoplist drops generic English / tech words ("python", "internal", "single", "operator", "studio", etc.) — the design assumes pip_audit/grype/osv_scanner cover structured dep scanning, so intel_match focuses on the rare/long-tail proper-noun matches.
- A frequency filter (corpus-adaptive) drops manifest tokens that appear in more than 5% of intel items in the store, so noise tokens like "meta" auto-disappear as the corpus grows.
- Emission gate: `config.min_severity` (default `high`) drops below-threshold matches. KEV-listed matches always emit regardless.
- Dedup by CVE id across feeds. Each finding carries `evidence.matched_tokens`, `evidence.intel_feed`, `evidence.kev_listed`.

To tune for a specific tier, override the default in `policy.py`:

```python
AdapterCall("intel_match", config={"min_severity": "critical"}),
```

**Additivity guarantee.** Zero scanner adapter imports anything from `pipeline.intel`. Intel feeds augment scanner findings; they do not replace them. The original adapter's findings remain the source of truth — enrichment only adds context, and `intel_match` only emits when its tokens match.

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
| `gitleaks` | [Gitleaks](https://github.com/gitleaks/gitleaks) | build | Second secret scanner with a different ruleset (catches what TruffleHog misses). |
| `detect_secrets` | [Yelp detect-secrets](https://github.com/Yelp/detect-secrets) | build | Entropy + pattern secret scanning. Third opinion alongside TruffleHog and Gitleaks. |
| `semgrep` | [Semgrep](https://github.com/semgrep/semgrep) | build | SAST patterns — Python + security-audit + secrets registries by default. |
| `bandit` | [Bandit](https://github.com/PyCQA/bandit) | build | Python-native SAST, complements Semgrep. |
| `gosec` | [gosec](https://github.com/securego/gosec) | build | Go-native SAST. G101/G201/G304/G4xx/G5xx rule families. Graceful degrade when no Go files in tree. |
| `bearer` | [Bearer](https://github.com/Bearer/bearer) | build | Privacy-flow SAST — tracks how PHI/PII flows through code paths. Healthcare-fit. |
| `codeql` | [GitHub CodeQL](https://github.com/github/codeql-cli-binaries) | build | Semantic SAST with full taint / data-flow analysis. Different class than Semgrep. |
| `njsscan` | [njsscan](https://github.com/ajinabraham/njsscan) | build | Node.js-specific SAST — Express, prototype pollution, JWT misconfig, eval. |
| `owasp_noir` | [OWASP Noir](https://github.com/owasp-noir/noir) | intake | Attack surface enumeration via static analysis — produces an authoritative endpoint list for downstream DAST. |
| `agentic_radar` | [SplxAI Agentic Radar](https://github.com/splx-ai/agentic-radar) | build | SAST for agentic AI workflows. LangChain / LlamaIndex / CrewAI / Claude Agent SDK / OpenAI Assistants. Surfaces tool over-grants, A2A privilege escalation, PHI flow into prompts. |
| `intel_match` | (built-in, see [Intel-scan integration](#intel-scan-integration)) | build | Cross-references manifest tokens against the configured intel feeds (CISA KEV, NVD, vendor CVE feeds). Emits a finding for every intel item whose title/summary mentions an asset the manifest declares. KEV-listed matches are CRITICAL; tunable via `config.min_severity`. Complements pip_audit/grype/osv_scanner — fires on long-tail product names those scanners don't index. |
| `ride` | [Adobe Ride](https://github.com/adobe/ride) | preprod | REST/JSON API test runner hook. Runs a configured Maven Ride suite, converts failures to Findings. Mutation-required. |
| `pip_audit` | [pip-audit](https://github.com/pypa/pip-audit) | build | Python dep CVE scanner (PyPA Advisory DB + OSV). |
| `dependency_check` | [OWASP Dependency-Check](https://github.com/dependency-check/DependencyCheck) | build | Multi-language CVE scanner (Maven / NPM / Gradle / .NET / Ruby / PHP / Python) against NIST NVD. **Requires `NVD_API_KEY` env var on v9+.** Current stable: v12.2.0. |
| `osv_scanner` | [OSV-Scanner](https://github.com/google/osv-scanner) | build | Google OSV.dev multi-language vuln scanner — broader language coverage than pip-audit. |
| `syft` | [Syft](https://github.com/anchore/syft) | build | Anchore SBOM generator (CycloneDX / SPDX). Compliance evidence for HITRUST. |
| `grype` | [Grype](https://github.com/anchore/grype) | build | Anchore SBOM-aware vulnerability scanner. Pairs with Syft. |
| `trivy` | [Trivy](https://github.com/aquasecurity/trivy) | build / preprod | Filesystem / image / IaC / secret scan in one binary; multi-mode. |
| `checkov` | [Checkov](https://github.com/bridgecrewio/checkov) | design / build | IaC specialist (Terraform / K8s / Helm / Dockerfile). |
| `hadolint` | [hadolint](https://github.com/hadolint/hadolint) | build | Dockerfile linter — build-time best practices, CIS-aligned rules. |
| `modelscan` | [Protect AI ModelScan](https://github.com/protectai/modelscan) | build | Malicious model file detection (pickle, h5, pt, safetensors, onnx). v2.1 names this at build. |
| `presidio` | [Microsoft Presidio](https://github.com/microsoft/presidio) | build | PHI/PII detection in text and source files. v2.1 default scrubber. |
| `nuclei` | [Nuclei](https://github.com/projectdiscovery/nuclei) | build / preprod | Template-driven web vuln scan. |
| `zap` | [OWASP ZAP](https://github.com/zaproxy/zaproxy) | preprod | Free Burp Pro substitute via REST API. Modes: `spider`, `baseline` (1-min + passive), `active`, `full`, `api` (OpenAPI/SOAP/GraphQL spec-driven). The `api` mode imports a spec then drives the scan, ideal for AI gateway and MCP server surfaces. |
| `sqlmap` | [sqlmap](https://github.com/sqlmapproject/sqlmap) | preprod | SQL injection confirmation + characterization. Confirms what Nuclei/ZAP detect. |
| `dockle` | [dockle](https://github.com/goodwithtech/dockle) | preprod | Container image hygiene scanner — different focus than Trivy (image best practices). |
| `recon` | [subfinder](https://github.com/projectdiscovery/subfinder) + [httpx](https://github.com/projectdiscovery/httpx) + [naabu](https://github.com/projectdiscovery/naabu) + [katana](https://github.com/projectdiscovery/katana) | intake (Tier 1) | Shadow-AI discovery chain — subdomains → HTTP services → ports → URLs. |
| `promptfoo` | [promptfoo](https://github.com/promptfoo/promptfoo) / [DeepEval](https://github.com/confident-ai/deepeval) | preprod | AI eval frameworks complementary to PyRIT (correctness, safety, refusal). |
| `guardrails` | [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) | design / preprod | Runtime input/output filter validation + smoke against the guarded endpoint. |
| `garak` | [NVIDIA garak](https://github.com/NVIDIA/garak) | build + preprod | LLM probes (prompt injection, leakage, jailbreak, encoding). |
| `pyrit` | [Microsoft PyRIT](https://github.com/Azure/PyRIT) | build + preprod | Multi-turn orchestrators (injection, encoding, multiturn, crescendo, leakage). |
| `mcp_scope` | (built-in) | preprod blocking | **Highest-leverage control.** Tier inheritance, action allow-list, side-effect, live token-scope probe. |
| `burp` | [PortSwigger Burp Suite](https://portswigger.net/burp) | preprod | REST API client for passive/active scans of the surrounding app. |
| `metasploit` | [Rapid7 Metasploit](https://github.com/rapid7/metasploit-framework) | preprod | Auxiliary scanners by default; exploits require Tier 1 + explicit `authorized_exploits` list. |
| `atomic` | [Red Canary Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | preprod | MITRE ATT&CK technique emulation against the agent runtime host. Validates EDR detection coverage. |
| `caldera` | [MITRE Caldera](https://github.com/mitre/caldera) | preprod | Autonomous adversary emulation — chained ATT&CK abilities run via Caldera REST API. Complements Atomic (per-technique) with end-to-end campaigns. Mutation-required; `adversary_id` config required. |
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
- **URL safety** for DAST scans — see **Scan modes** above. Cloud-metadata IPs are hard-denied (non-overridable); RFC1918 / loopback / link-local / etc. are default-denied with typed-confirmation override. DNS re-resolved on every check. HTTPS-only by default.
- **Universal DAST timebox** — `dast_timebox_seconds` (default 30 min) is the wall-clock cap applied to every DAST adapter subprocess. Per-adapter `timeout_s` config can request shorter; longer is clamped.
- **Bare-origin refusal** — crawler-class adapters (`nuclei`, `zap`, `katana`, `burp`) refuse to launch when the manifest's `target.base_url` path is `/` or empty. Prevents accidentally crawling the whole host. Bypass by scoping the URL or unchecking `dast_require_scope_prefix_for_crawlers` on `/settings`.

## Layout

```
pipeline/
├── README.md                       # this file
├── cli.py                          # python -m pipeline.cli ...
├── requirements.txt
├── core/
│   ├── manifest.py                 # YAML schema → Manifest dataclass (source_provider / github_*)
│   ├── tiering.py                  # 4-dim scoring, forced rules, MCP inheritance
│   ├── findings.py                 # Finding, Severity, Category, FindingStore
│   ├── compliance.py               # category → control identifiers
│   ├── policy.py                   # tier × stage → adapter list (the operating model)
│   ├── orchestrator.py             # ties it all together; materializes source, calls
│   │                               # intel_enrichment, calls auto_resolve at end of stage
│   ├── intel_enrichment.py         # stamps intel-feed context onto findings (KEV ratchet)
│   ├── auto_resolve.py             # detect + persist auto-resolutions for re-scan absence
│   ├── scan_modes.py               # SAST / DAST / pre-flight taxonomy + adapter classification
│   ├── url_safety.py               # DAST URL validator (hard/default deny lists + DNS resolve)
│   ├── adhoc.py                    # synthetic ephemeral manifest for ad-hoc DAST URLs
│   ├── dast_config.py              # DastConfig dataclass: per-adapter intent carrier
│   └── settings.py                 # schema-driven ~/.ai-protect/config.json
├── adapters/
│   ├── base.py                     # Adapter base class + exceptions
│   ├── registry.py                 # name → class
│   ├── manifest_validator.py
│   ├── threat_model_check.py
│   ├── intel_match.py              # cross-refs manifest tokens vs intel feeds (detection)
│   ├── garak.py                    # DastConfig: --parallel_requests, subprocess timeout
│   ├── pyrit.py                    # DastConfig: wall-clock + max_prompts_per_strategy
│   ├── atomic.py
│   ├── burp.py                     # DastConfig: scope.include + bare-origin refusal
│   ├── metasploit.py               # DastConfig: two-level timebox (stage + per-module)
│   ├── mcp_scope.py
│   ├── nuclei.py                   # DastConfig: -rate-limit, -c, bare-origin refusal
│   ├── zap.py                      # DastConfig: threadsPerHost + bare-origin refusal
│   ├── recon.py                    # DastConfig: subfinder cap, httpx/naabu/katana flags
│   ├── sqlmap.py                   # DastConfig: --threads, subprocess timeout
│   ├── trufflehog.py
│   ├── eval_suite.py
│   └── telemetry_drift.py
├── sources/                        # remote-source providers (the orchestrator clones before scan)
│   ├── base.py                     # SourceProvider ABC + SourceMaterialization context manager
│   ├── local.py                    # passthrough (default — read manifest.source_paths from disk)
│   └── github.py                   # github.com / GHES; PAT or App auth; per-scan or cached clone
├── intel/                          # external CVE / threat feed ingestion
│   ├── feeds.py                    # Feed / IntelItem dataclasses + JSONL stores
│   ├── translators.py              # atom / rss / xml / json + detect_format
│   ├── fetcher.py                  # fetch_feed, validate_feed, background poller
│   └── status.py                   # green/yellow/red lamp computation
├── ui/                             # Flask app — findings dashboard + feeds + settings + docs
│   ├── server.py                   # routes (findings, feeds, intel, settings, docs, history, scan, api)
│   ├── manifest_io.py              # YAML manifest CRUD + load-by-yaml-name fallback
│   ├── catalog.py                  # adapter catalog metadata for /about
│   ├── pdf_report.py               # /findings.pdf generator
│   ├── static/                     # style.css + favicon.svg
│   └── templates/                  # index, finding, feeds, feeds_discover, feed_edit, intel,
│                                   # settings, docs, history, scan (SAST/DAST), scan_status,
│                                   # manifests, manifest_form, ...
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
