"""Tests for the DefectDojo export integration."""
from __future__ import annotations

import json

import pytest

from pipeline.core.findings import Category, Severity, new_finding
from pipeline.reporting.defectdojo import (
    DefectDojoClient,
    DefectDojoConfig,
    DefectDojoConfigError,
    DefectDojoError,
    filter_by_severity,
    finding_to_generic,
    to_generic_report,
)


def _finding(**over):
    base = dict(
        app_name="commercial", tier=1, stage="preprod", adapter="semgrep",
        category=Category.INFRA_VULN, severity=Severity.HIGH,
        title="SQL injection", description="user input flows into a raw query",
        evidence={"file": "app/db.py", "line": "42", "cwe": "CWE-89"},
        remediation="Use parameterized queries.",
        references=["https://owasp.org/sqli"],
        compliance=["HIPAA-164.312(a)(1)"],
    )
    base.update(over)
    return new_finding(**base)


# ---- serialization -------------------------------------------------------- #
def test_finding_to_generic_core_fields():
    g = finding_to_generic(_finding())
    assert g["title"] == "SQL injection"
    assert g["severity"] == "High"                 # Title-cased for DefectDojo
    assert g["mitigation"] == "Use parameterized queries."
    assert g["references"] == "https://owasp.org/sqli"
    assert g["file_path"] == "app/db.py"
    assert g["line"] == 42                          # coerced str -> int
    assert g["cwe"] == 89                           # "CWE-89" -> 89
    assert "Compliance: HIPAA-164.312(a)(1)" in g["severity_justification"]


def test_finding_to_generic_unique_id_is_fingerprint():
    f = _finding()
    g = finding_to_generic(f)
    assert g["unique_id_from_tool"] == f.fingerprint
    assert g["vuln_id_from_tool"] == f.fingerprint


def test_finding_to_generic_tags():
    g = finding_to_generic(_finding())
    assert "app:commercial" in g["tags"]
    assert "tier:1" in g["tags"]
    assert "adapter:semgrep" in g["tags"]
    assert "category:infra_vuln" in g["tags"]
    assert "compliance:HIPAA-164.312(a)(1)" in g["tags"]


def test_severity_mapping_all_levels():
    want = {Severity.INFO: "Info", Severity.LOW: "Low", Severity.MEDIUM: "Medium",
            Severity.HIGH: "High", Severity.CRITICAL: "Critical"}
    for sev, label in want.items():
        assert finding_to_generic(_finding(severity=sev))["severity"] == label


def test_response_evidence_dropped_from_description():
    f = _finding(evidence={"prompt": "hi", "response": "x" * 100000})
    g = finding_to_generic(f)
    assert "response" not in g["description"]
    assert "prompt" in g["description"]


def test_to_generic_report_wraps_findings():
    rep = to_generic_report([_finding(), _finding(title="XSS")])
    assert set(rep) == {"findings"}
    assert len(rep["findings"]) == 2


def test_filter_by_severity():
    fs = [_finding(severity=Severity.LOW), _finding(severity=Severity.HIGH),
          _finding(severity=Severity.CRITICAL)]
    assert len(filter_by_severity(fs, "high")) == 2
    assert len(filter_by_severity(fs, "info")) == 3
    assert len(filter_by_severity(fs, "critical")) == 1


# ---- client / request shape ---------------------------------------------- #
class _FakeResp:
    def __init__(self, status=201, payload=None, text=""):
        self.status_code = status
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class _FakeSession:
    def __init__(self, resp):
        self.resp = resp
        self.calls = []

    def post(self, url, **kw):
        self.calls.append((url, kw))
        return self.resp


def _client(resp):
    sess = _FakeSession(resp)
    cfg = DefectDojoConfig(url="https://dd.example", token="abc123")
    return DefectDojoClient(cfg, session=sess), sess


def test_push_reimport_request_shape():
    client, sess = _client(_FakeResp(201, {"test": 7}))
    res = client.push([_finding()], product="commercial", engagement="pipeline")
    url, kw = sess.calls[0]
    assert url == "https://dd.example/api/v2/reimport-scan/"
    assert kw["headers"]["Authorization"] == "Token abc123"
    assert kw["data"]["scan_type"] == "Generic Findings Import"
    assert kw["data"]["product_name"] == "commercial"
    assert kw["data"]["engagement_name"] == "pipeline"
    assert kw["data"]["auto_create_context"] == "true"
    # the uploaded file is the Generic Findings Import JSON
    body = kw["files"]["file"][1].read().decode()
    doc = json.loads(body)
    assert doc["findings"][0]["severity"] == "High"
    assert res == {"test": 7}


def test_push_import_mode_uses_import_endpoint():
    client, sess = _client(_FakeResp(201, {"test": 1}))
    client.push([_finding()], product="p", engagement="e", reimport=False)
    assert sess.calls[0][0].endswith("/api/v2/import-scan/")


def test_push_test_title_passthrough():
    client, sess = _client(_FakeResp(201, {"test": 1}))
    client.push([_finding()], product="p", engagement="e", test_title="nightly")
    assert sess.calls[0][1]["data"]["test_title"] == "nightly"


def test_push_raises_on_http_error():
    client, _ = _client(_FakeResp(403, text="forbidden"))
    with pytest.raises(DefectDojoError) as ei:
        client.push([_finding()], product="p", engagement="e")
    assert "403" in str(ei.value)


def test_push_handles_non_json_response():
    client, _ = _client(_FakeResp(201, payload=None))
    assert client.push([_finding()], product="p", engagement="e") == {"status_code": 201}


# ---- config -------------------------------------------------------------- #
def test_config_from_env(monkeypatch):
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd.example/")
    monkeypatch.setenv("DEFECTDOJO_API_TOKEN", "tok")
    cfg = DefectDojoConfig.from_env()
    assert cfg.url == "https://dd.example"          # trailing slash stripped
    assert cfg.token == "tok"
    assert cfg.verify_ssl is True


def test_config_verify_ssl_off(monkeypatch):
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd.example")
    monkeypatch.setenv("DEFECTDOJO_API_TOKEN", "tok")
    monkeypatch.setenv("DEFECTDOJO_VERIFY_SSL", "0")
    assert DefectDojoConfig.from_env().verify_ssl is False


def test_config_missing_raises(monkeypatch):
    monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
    monkeypatch.delenv("DEFECTDOJO_API_TOKEN", raising=False)
    with pytest.raises(DefectDojoConfigError):
        DefectDojoConfig.from_env()


def test_config_explicit_args_override_env(monkeypatch):
    monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
    monkeypatch.delenv("DEFECTDOJO_API_TOKEN", raising=False)
    cfg = DefectDojoConfig.from_env(url="https://x", token="y")
    assert cfg.url == "https://x" and cfg.token == "y"
