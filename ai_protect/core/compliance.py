"""Map finding categories to HIPAA / HITRUST / NIST AI RMF / MITRE ATLAS controls.

Used by the orchestrator to auto-tag findings with control identifiers so audit
evidence is queryable. The mappings are intentionally conservative — when in
doubt, tag more controls rather than fewer; auditors prefer over-coverage.
"""
from __future__ import annotations

from .findings import Category


# Each category → list of control identifiers. Audit evidence is queryable on these.
CATEGORY_CONTROLS: dict[Category, list[str]] = {
    Category.PROMPT_INJECTION: [
        "HIPAA-164.312(a)(1)",         # Access control
        "HIPAA-164.312(c)(1)",         # Integrity
        "HITRUST-AC.01",
        "NIST-AI-RMF-MEASURE-2.6",
        "MITRE-ATLAS-AML.T0051",       # LLM Prompt Injection
    ],
    Category.JAILBREAK: [
        "HIPAA-164.312(a)(1)",
        "HITRUST-AC.01",
        "NIST-AI-RMF-MEASURE-2.6",
        "MITRE-ATLAS-AML.T0054",       # LLM Jailbreak
    ],
    Category.HALLUCINATION: [
        "HIPAA-164.312(c)(1)",         # Integrity — clinical hallucinations are integrity issues
        "HITRUST-IS.04",
        "NIST-AI-RMF-MEASURE-2.5",
        "FDA-SaMD-clinical-decision-support",
    ],
    Category.DATA_LEAKAGE: [
        "HIPAA-164.502(a)",            # Uses and disclosures of PHI
        "HIPAA-164.514(b)",            # De-identification
        "HIPAA-164.530(c)",            # Safeguards
        "HITRUST-IS.10",
        "NIST-AI-RMF-MEASURE-2.10",
        "MITRE-ATLAS-AML.T0024",       # Exfiltration via inference
    ],
    Category.BIAS: [
        "NIST-AI-RMF-MEASURE-2.11",
        "FDA-SaMD-bias",
    ],
    Category.HARMFUL_CONTENT: [
        "HITRUST-IS.04",
        "NIST-AI-RMF-MEASURE-2.7",
    ],
    Category.TOOL_MISUSE: [
        "HIPAA-164.312(a)(2)(i)",      # Unique user identification
        "HITRUST-AC.05",
        "NIST-AI-RMF-MEASURE-2.6",
        "MITRE-ATLAS-AML.T0053",       # LLM Plugin Compromise
    ],
    Category.SCOPE_VIOLATION: [
        "HIPAA-164.312(a)(1)",
        "HIPAA-164.308(a)(4)",         # Information access management
        "HITRUST-AC.05",
        "NIST-AI-RMF-MEASURE-2.6",
    ],
    Category.POLICY_BYPASS: [
        "HIPAA-164.308(a)(1)(ii)(B)",
        "HITRUST-AC.01",
        "NIST-AI-RMF-MEASURE-2.6",
    ],
    Category.SUPPLY_CHAIN: [
        "HITRUST-SC.06",
        "NIST-AI-RMF-MAP-4.1",
    ],
    Category.INFRA_VULN: [
        "HIPAA-164.308(a)(1)(ii)(A)",  # Risk analysis
        "HITRUST-VM.01",
    ],
    Category.SECRETS: [
        "HIPAA-164.312(d)",            # Person or entity authentication
        "HITRUST-AC.06",
    ],
    Category.AUTH: [
        "HIPAA-164.312(a)(2)(i)",
        "HITRUST-AC.06",
    ],
    Category.OTHER: [],
}


def controls_for(category: Category) -> list[str]:
    """Return the list of compliance controls a finding of this category maps to."""
    return list(CATEGORY_CONTROLS.get(category, []))
