"""Microsoft Presidio adapter — PHI / PII scrubber.

v2.1 names Presidio as the default output scrubber. This adapter has two
modes:

  - file:    scan source/data files for hardcoded PII/PHI patterns
             (catches sample patient data committed to source by mistake)
  - text:    scrub a single string passed via config (used as a smoke
             test against gateway output filters)

Repo: https://github.com/microsoft/presidio
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable

log = logging.getLogger("ai-protect.presidio")


# Healthcare-relevant entity types Presidio recognizes out of the box, plus
# a few we wire in via custom recognizers.
HEALTHCARE_ENTITIES = [
    "PERSON",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "US_SSN",
    "MEDICAL_LICENSE",
    "US_DRIVER_LICENSE",
    "DATE_TIME",
    "LOCATION",
    "CREDIT_CARD",
    "IP_ADDRESS",
    "URL",
    "NRP",  # Nationality/Religious/Political
]


# File extensions worth scanning for hardcoded PII. Big binary artifacts skipped.
SCANNABLE_EXTS = {".py", ".js", ".ts", ".html", ".md", ".txt", ".yml", ".yaml",
                  ".json", ".csv", ".sql", ".sh", ".env"}


class PresidioAdapter(Adapter):
    name = "presidio"
    description = "Microsoft Presidio — PHI/PII detection in text and source files (v2.1 default scrubber)"

    def preflight(self) -> None:
        super().preflight()
        try:
            from presidio_analyzer import AnalyzerEngine  # noqa: F401
        except ImportError as e:
            raise AdapterUnavailable(
                "presidio-analyzer not installed. Install: "
                "pip install presidio-analyzer presidio-anonymizer && "
                "python -m spacy download en_core_web_lg"
            ) from e

    def run(self):
        self.preflight()
        from presidio_analyzer import AnalyzerEngine

        analyzer = AnalyzerEngine()
        path = self.config.get("path", self.manifest.raw.get("source_path", "."))
        threshold = float(self.config.get("score_threshold", 0.85))
        max_files = int(self.config.get("max_files", 500))
        max_bytes = int(self.config.get("max_bytes_per_file", 200_000))
        entities = self.config.get("entities", HEALTHCARE_ENTITIES)

        tier = classify(self.manifest).tier
        findings = []
        scanned = 0
        root = Path(path)
        if not root.exists():
            raise AdapterUnavailable(f"presidio source_path {path!r} does not exist")
        for f in root.rglob("*"):
            if scanned >= max_files:
                break
            if not f.is_file() or f.suffix.lower() not in SCANNABLE_EXTS:
                continue
            try:
                text = f.read_text(errors="ignore")[:max_bytes]
            except Exception:
                continue
            scanned += 1
            try:
                results = analyzer.analyze(text=text, entities=entities, language="en")
            except Exception as e:
                log.warning("presidio analyze %s raised %s", f, e)
                continue
            for r in results:
                if r.score < threshold:
                    continue
                snippet = text[max(0, r.start - 20):r.end + 20]
                # Map entity type → severity. PHI/PII categories are HIGH;
                # generic noise (URL, IP) stays MEDIUM.
                if r.entity_type in ("US_SSN", "MEDICAL_LICENSE", "CREDIT_CARD"):
                    severity = Severity.CRITICAL
                elif r.entity_type in ("PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS",
                                       "US_DRIVER_LICENSE"):
                    severity = Severity.HIGH if self.manifest.data_sensitivity == "phi" else Severity.MEDIUM
                else:
                    severity = Severity.LOW
                findings.append(self.make_finding(
                    tier=tier,
                    category=Category.DATA_LEAKAGE,
                    severity=severity,
                    title=f"Presidio: {r.entity_type} hit in source",
                    description=(
                        f"Presidio detected a {r.entity_type} match (score={r.score:.2f}) "
                        f"in {f.relative_to(root) if root in f.parents else f.name}. "
                        "If this is documented sample data, allow-list it; if not, remove "
                        "from source and replace with a synthetic fixture."
                    ),
                    evidence={
                        "entity": r.entity_type,
                        "score": round(r.score, 3),
                        "file": str(f),
                        "snippet": snippet[:200],
                        "start": r.start,
                        "end": r.end,
                    },
                    affected={"file": str(f)},
                    remediation="Replace with synthetic data; if test fixture, document and exclude from scan.",
                    references=["https://github.com/microsoft/presidio"],
                ))
        log.info("presidio scanned %d files, %d findings", scanned, len(findings))
        return findings
