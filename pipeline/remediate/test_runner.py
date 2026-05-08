"""Run generated tests and return per-test pass/fail.

Phase 1 keeps it simple: invoke pytest in a subprocess on the generated test
files, parse exit code per file. Stdout/stderr captured for the audit trail.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TestResult:
    name: str
    path: str
    passed: bool
    output: str = ""


def run_tests(test_paths: list[str], timeout_s: int = 60) -> list[TestResult]:
    """Run each test file individually so per-file pass/fail is clean."""
    results: list[TestResult] = []
    if not shutil.which("pytest") and not shutil.which("py.test"):
        # pytest missing — record everything as failed with a message.
        for p in test_paths:
            results.append(TestResult(name=Path(p).stem, path=p, passed=False,
                                      output="pytest not on PATH; install pytest"))
        return results
    for tp in test_paths:
        try:
            proc = subprocess.run(
                ["pytest", tp, "-q", "--tb=short", "--no-header"],
                capture_output=True, text=True, timeout=timeout_s, check=False,
            )
            results.append(TestResult(
                name=Path(tp).stem,
                path=tp,
                passed=(proc.returncode == 0),
                output=(proc.stdout + "\n" + proc.stderr)[-3000:],
            ))
        except subprocess.TimeoutExpired:
            results.append(TestResult(name=Path(tp).stem, path=tp, passed=False, output="timeout"))
    return results
