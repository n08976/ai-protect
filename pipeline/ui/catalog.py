"""Adapter catalog for the about page.

Source-of-truth metadata for every adapter: human description, upstream link,
the v2.1 stages where it typically runs, and the broad category it covers.
"""
from __future__ import annotations


# Each entry: (description, source_url, stages, category, kind)
#   stages   — comma-separated v2.1 stage names where the adapter runs
#   category — broad bucket for the about-page grouping
#   kind     — "static" | "dynamic" | "ai" | "policy"
CATALOG: dict[str, dict] = {
    # ---------- intake / design / policy ----------
    "manifest_validator": {
        "description": "Validates the manifest at intake — schema + sanctioned-infrastructure policy (PHI without BAA fails immediately, direct API access blocked).",
        "source_url": "https://github.com/n08976/ai-protect/blob/main/pipeline/adapters/manifest_validator.py",
        "stages": "intake",
        "category": "Policy gates",
        "kind": "policy",
    },
    "threat_model_check": {
        "description": "At design stage, verifies a signed-off threat model artifact exists for Tier 1/2 apps (assets, actors, trust boundaries, threats, mitigations, approver).",
        "source_url": "https://github.com/n08976/ai-protect/blob/main/pipeline/adapters/threat_model_check.py",
        "stages": "design",
        "category": "Policy gates",
        "kind": "policy",
    },
    "mcp_scope": {
        "description": "MCP scope validator — tier inheritance, action allow-list, side-effect classification, and live token-scope probe. Highest-leverage single control in the v2.1 plan.",
        "source_url": "https://github.com/n08976/ai-protect/blob/main/pipeline/adapters/mcp_scope.py",
        "stages": "preprod",
        "category": "Policy gates",
        "kind": "policy",
    },
    "guardrails": {
        "description": "NeMo Guardrails — verify guardrails config + smoke a high-severity prompt-injection/PHI prompt through the guarded endpoint.",
        "source_url": "https://github.com/NVIDIA/NeMo-Guardrails",
        "stages": "design, preprod",
        "category": "Policy gates",
        "kind": "policy",
    },

    # ---------- static analysis / secrets / deps ----------
    "trufflehog": {
        "description": "Live-verifying secret scanner across 700+ detectors. CRITICAL on verified hits; HIGH on unverified pattern matches.",
        "source_url": "https://github.com/trufflesecurity/trufflehog",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "gitleaks": {
        "description": "Pattern-based secret scanner with a different ruleset than TruffleHog — running both catches more than either alone.",
        "source_url": "https://github.com/gitleaks/gitleaks",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "semgrep": {
        "description": "Multi-language SAST. Default ruleset: p/python + p/security-audit + p/secrets registries.",
        "source_url": "https://github.com/semgrep/semgrep",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "bandit": {
        "description": "Python-native SAST — exec/eval, weak crypto, hardcoded credentials, unsafe subprocess, weak SSL/TLS, deserialization risks.",
        "source_url": "https://github.com/PyCQA/bandit",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "pip_audit": {
        "description": "Python dependency CVE scanner — PyPA Advisory DB + OSV. Catches known-vulnerable transitive deps.",
        "source_url": "https://github.com/pypa/pip-audit",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "trivy": {
        "description": "Filesystem / container image / IaC / secret scanner in one binary. Multi-mode: filesystem, image, config (IaC), k8s.",
        "source_url": "https://github.com/aquasecurity/trivy",
        "stages": "build, preprod",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "checkov": {
        "description": "IaC specialist — Terraform / Kubernetes / Helm / CloudFormation / Dockerfile against a 1000+ rule catalog.",
        "source_url": "https://github.com/bridgecrewio/checkov",
        "stages": "design, build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "syft": {
        "description": "Anchore Syft — SBOM generator (CycloneDX / SPDX). Compliance evidence for HITRUST.",
        "source_url": "https://github.com/anchore/syft",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "grype": {
        "description": "Anchore Grype — SBOM-aware vulnerability scanner. Pairs with Syft; complements Trivy + pip-audit + OSV-Scanner.",
        "source_url": "https://github.com/anchore/grype",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "osv_scanner": {
        "description": "Google OSV-Scanner — multi-language vuln scanner against the OSV.dev database. Broader language coverage than pip-audit.",
        "source_url": "https://github.com/google/osv-scanner",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "modelscan": {
        "description": "Protect AI ModelScan — malicious model file detection (pickle, h5, pt, safetensors, onnx). v2.1 names this at build.",
        "source_url": "https://github.com/protectai/modelscan",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "presidio": {
        "description": "Microsoft Presidio — PHI/PII detection in text and source files. v2.1 names this as the default scrubber.",
        "source_url": "https://github.com/microsoft/presidio",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "bearer": {
        "description": "Bearer — privacy-flow SAST. Tracks how PHI/PII flows through code paths; healthcare-fit.",
        "source_url": "https://github.com/Bearer/bearer",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "codeql": {
        "description": "GitHub CodeQL — semantic SAST with full taint / data-flow analysis. Different class than Semgrep.",
        "source_url": "https://github.com/github/codeql-cli-binaries",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "detect_secrets": {
        "description": "Yelp detect-secrets — entropy + pattern secret scanning. Third opinion alongside TruffleHog and Gitleaks.",
        "source_url": "https://github.com/Yelp/detect-secrets",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "njsscan": {
        "description": "njsscan — Node.js-specific SAST (Express, prototype pollution, JWT misconfig, eval).",
        "source_url": "https://github.com/ajinabraham/njsscan",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "dependency_check": {
        "description": "OWASP Dependency-Check — multi-language CVE scanner against NIST NVD. Broader language coverage than pip_audit.",
        "source_url": "https://github.com/dependency-check/DependencyCheck",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "hadolint": {
        "description": "hadolint — Dockerfile linter (build-time best practices, CIS-aligned rules).",
        "source_url": "https://github.com/hadolint/hadolint",
        "stages": "build",
        "category": "Static analysis · secrets · deps",
        "kind": "static",
    },
    "dockle": {
        "description": "dockle — container image hygiene scanner (different focus than Trivy: image best practices).",
        "source_url": "https://github.com/goodwithtech/dockle",
        "stages": "preprod",
        "category": "Dynamic · web · network",
        "kind": "dynamic",
    },
    "sqlmap": {
        "description": "sqlmap — SQL injection confirmation + characterization. Confirms what Nuclei/ZAP detect.",
        "source_url": "https://github.com/sqlmapproject/sqlmap",
        "stages": "preprod",
        "category": "Dynamic · web · network",
        "kind": "dynamic",
    },

    # ---------- dynamic / web ----------
    "nuclei": {
        "description": "Template-driven web vulnerability scanner. Runs the exposures/misconfiguration/vulnerabilities templates by default.",
        "source_url": "https://github.com/projectdiscovery/nuclei",
        "stages": "build, preprod",
        "category": "Dynamic · web · network",
        "kind": "dynamic",
    },
    "burp": {
        "description": "PortSwigger Burp Suite via REST API (Pro / Enterprise). Passive or active scan against the surrounding web app.",
        "source_url": "https://portswigger.net/burp",
        "stages": "preprod",
        "category": "Dynamic · web · network",
        "kind": "dynamic",
    },
    "zap": {
        "description": "OWASP ZAP — free Burp Pro substitute via REST API. Spider + active scan with auth flows.",
        "source_url": "https://github.com/zaproxy/zaproxy",
        "stages": "preprod",
        "category": "Dynamic · web · network",
        "kind": "dynamic",
    },
    "metasploit": {
        "description": "Metasploit Framework via RPC. Auxiliary scanners by default; exploit modules require Tier 1 + explicit allow-list.",
        "source_url": "https://github.com/rapid7/metasploit-framework",
        "stages": "preprod",
        "category": "Dynamic · web · network",
        "kind": "dynamic",
    },
    "atomic": {
        "description": "Red Canary Atomic Red Team — MITRE ATT&CK technique emulation against the agent runtime host. Validates EDR detection coverage.",
        "source_url": "https://github.com/redcanaryco/atomic-red-team",
        "stages": "preprod",
        "category": "Dynamic · web · network",
        "kind": "dynamic",
    },
    "recon": {
        "description": "ProjectDiscovery chain (subfinder → httpx → naabu → katana). Subdomain enumeration, HTTP probing, port scan, URL crawl. Drives shadow-AI discovery.",
        "source_url": "https://github.com/projectdiscovery",
        "stages": "intake (Tier 1)",
        "category": "Dynamic · web · network",
        "kind": "dynamic",
    },

    # ---------- AI red team / eval ----------
    "garak": {
        "description": "NVIDIA garak — LLM vulnerability scanner. Probes for prompt injection, encoding bypass, leakage, jailbreaks, toxicity.",
        "source_url": "https://github.com/NVIDIA/garak",
        "stages": "build, preprod",
        "category": "AI red team · eval",
        "kind": "ai",
    },
    "pyrit": {
        "description": "Microsoft PyRIT — multi-turn AI red team orchestration. Strategies: injection, encoding, multiturn, crescendo, leakage.",
        "source_url": "https://github.com/Azure/PyRIT",
        "stages": "build, preprod",
        "category": "AI red team · eval",
        "kind": "ai",
    },
    "promptfoo": {
        "description": "promptfoo / DeepEval — curated AI eval suites (correctness, safety, refusal). Complement to PyRIT.",
        "source_url": "https://github.com/promptfoo/promptfoo",
        "stages": "preprod",
        "category": "AI red team · eval",
        "kind": "ai",
    },
    "eval_suite": {
        "description": "Pre-prod gate: hallucination / bias / jailbreak rate must pass thresholds before deploy. Plug TruthfulQA / MedQA / custom QA harness.",
        "source_url": "https://github.com/n08976/ai-protect/blob/main/pipeline/adapters/eval_suite.py",
        "stages": "preprod",
        "category": "AI red team · eval",
        "kind": "ai",
    },

    # ---------- production / telemetry ----------
    "telemetry_drift": {
        "description": "Production-stage drift over unified AI telemetry (prompts, completions, tool calls, retrievals, agent decisions, policy events).",
        "source_url": "https://github.com/n08976/ai-protect/blob/main/pipeline/adapters/telemetry_drift.py",
        "stages": "production",
        "category": "Production · telemetry",
        "kind": "policy",
    },
    "anomaly_detector": {
        "description": "Lightweight anomaly detection over telemetry (alias of telemetry_drift with different defaults).",
        "source_url": "https://github.com/n08976/ai-protect/blob/main/pipeline/adapters/telemetry_drift.py",
        "stages": "production",
        "category": "Production · telemetry",
        "kind": "policy",
    },
}


# Display ordering for the about page.
CATEGORY_ORDER = [
    "Policy gates",
    "Static analysis · secrets · deps",
    "Dynamic · web · network",
    "AI red team · eval",
    "Production · telemetry",
]
