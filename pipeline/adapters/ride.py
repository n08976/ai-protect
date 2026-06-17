"""Adobe Ride adapter (REST/JSON API test runner hook).

Honest note: upstream Adobe Ride is a Java test framework for REST APIs, not
a security fuzzer per se. This adapter is therefore a *configurable hook*: it
runs a Ride test suite that the team has authored against the AI gateway or
MCP server surface, then converts test failures into Findings. Wire your fuzz
properties, schema-validation tests, auth-bypass tests, and tenant-isolation
tests into the Ride suite — the pipeline runs them at preprod and surfaces
failures in the same dashboard the rest of the adapters feed.

Repo: https://github.com/adobe/ride

Configuration:
    target.api_url             API surface the suite targets (informational only;
                               Ride's own config controls actual endpoints)

Adapter config / env:
    RIDE_TEST_PATH             (required) directory containing the Maven Ride suite
    timeout_s                  (default 1800) max test duration

Future swap candidate: if no in-house Ride suite exists, swap this adapter for
schemathesis or RESTler — both are true REST API fuzzers. The Finding shape
the adapter returns stays identical.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from xml.etree.ElementTree import ParseError as _ParseError  # exception type only
from defusedxml.ElementTree import parse as _ET_parse        # hardened parsing (XXE)
from pathlib import Path

from ..core.findings import Category, Severity
from ..core.tiering import classify
from .base import Adapter, AdapterUnavailable


class RideAdapter(Adapter):
    name = "ride"
    description = "Adobe Ride — REST/JSON API test suite runner (configurable hook)"
    requires_mutation = True  # API tests can mutate state via writes

    def preflight(self) -> None:
        super().preflight()
        if not shutil.which("mvn"):
            raise AdapterUnavailable("mvn not on PATH; Ride is a Maven-based Java test framework.")
        suite = self.config.get("test_path") or os.environ.get("RIDE_TEST_PATH")
        if not suite:
            raise AdapterUnavailable(
                "RIDE_TEST_PATH (or config.test_path) not set. Point at the directory "
                "containing the Maven Ride suite that targets this app."
            )
        if not Path(suite).is_dir():
            raise AdapterUnavailable(f"Ride suite directory does not exist: {suite}")

    def run(self):
        self.preflight()
        suite = self.config.get("test_path") or os.environ["RIDE_TEST_PATH"]
        timeout_s = self.config.get("timeout_s", 1800)
        try:
            subprocess.run(
                ["mvn", "-q", "-B", "test"],
                cwd=suite,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise AdapterUnavailable(f"ride/mvn test timed out after {timeout_s}s")

        reports_dir = Path(suite) / "target" / "surefire-reports"
        if not reports_dir.is_dir():
            return []

        tier = classify(self.manifest).tier
        findings = []
        for xml_path in sorted(reports_dir.glob("TEST-*.xml")):
            try:
                tree = _ET_parse(xml_path)
            except _ParseError:
                continue
            for testcase in tree.iter("testcase"):
                failure = testcase.find("failure") or testcase.find("error")
                if failure is None:
                    continue
                tc_name = testcase.get("name", "unknown-test")
                tc_class = testcase.get("classname", "")
                msg = failure.get("message") or (failure.text or "")[:1500]
                findings.append(self.make_finding(
                    tier=tier,
                    category=self._categorize(tc_name, msg),
                    severity=Severity.MEDIUM,
                    title=f"Ride: {tc_class}.{tc_name} failed",
                    description=(msg or "")[:1500],
                    evidence={
                        "test_class": tc_class,
                        "test_name": tc_name,
                        "stack_tail": ((failure.text or "")[-1500:]),
                    },
                    affected={"target": self.manifest.target.api_url or ""},
                    remediation=(
                        "Triage as an API contract / auth / fuzz test failure. "
                        "Ride suite is the source of truth for REST API behaviors."
                    ),
                    references=["https://github.com/adobe/ride"],
                ))
        return findings

    @staticmethod
    def _categorize(name: str, msg: str) -> Category:
        text = f"{name} {msg}".lower()
        if any(k in text for k in ("auth", "token", "jwt", "tenant", "rbac")):
            return Category.AUTH
        if any(k in text for k in ("scope", "isolation", "cross-tenant")):
            return Category.SCOPE_VIOLATION
        if any(k in text for k in ("schema", "fuzz", "payload", "injection")):
            return Category.INFRA_VULN
        return Category.INFRA_VULN
