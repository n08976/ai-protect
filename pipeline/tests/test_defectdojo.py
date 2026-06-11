"""Tests for the modular DefectDojo findings sink."""
from __future__ import annotations

import json

import pytest

from pipeline.core.findings import Category, Severity, new_finding
from pipeline.integrations import (
    SinkContext,
    configured_sinks,
    get_sink,
    sink_names,
)
from pipeline.integrations.defectdojo import (
    DefectDojoClient,
    DefectDojoConfig,
    DefectDojoConfigError,
    DefectDojoError,
    DefectDojoSink,
    filter_by_severity,
    finding_to_generic,
    to_generic_report,
)
from pipeline.integrations.defectdojo import config as dd_config
from pipeline.integrations.defectdojo import sink as dd_sink


@pytest.fixture(autouse=True)
def _isolate_settings(monkeypatch):
    """Stop sinks from reading the dev machine's ~/.ai-protect/config.json."""
    monkeypatch.setattr(dd_config, "_settings_get", lambda key, default="": default)
    monkeypatch.setattr(dd_sink, "_settings_get", lambda key, default="": default)


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
    assert {"app:commercial", "tier:1", "stage:preprod", "adapter:semgrep",
            "category:infra_vuln", "compliance:HIPAA-164.312(a)(1)"} <= set(g["tags"])


def test_severity_mapping_all_levels():
    want = {Severity.INFO: "Info", Severity.LOW: "Low", Severity.MEDIUM: "Medium",
            Severity.HIGH: "High", Severity.CRITICAL: "Critical"}
    for sev, label in want.items():
        assert finding_to_generic(_finding(severity=sev))["severity"] == label


def test_response_evidence_dropped_from_description():
    g = finding_to_generic(_finding(evidence={"prompt": "hi", "response": "x" * 100000}))
    assert "response" not in g["description"]
    assert "prompt" in g["description"]


def test_to_generic_report_wraps_findings():
    rep = to_generic_report([_finding(), _finding(title="XSS")])
    assert set(rep) == {"findings"} and len(rep["findings"]) == 2


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
    doc = json.loads(kw["files"]["file"][1].read().decode())
    assert doc["findings"][0]["severity"] == "High"
    assert res == {"test": 7}


def test_push_import_mode_uses_import_endpoint():
    client, sess = _client(_FakeResp(201, {"test": 1}))
    client.push([_finding()], product="p", engagement="e", reimport=False)
    assert sess.calls[0][0].endswith("/api/v2/import-scan/")


def test_push_raises_on_http_error():
    client, _ = _client(_FakeResp(403, text="forbidden"))
    with pytest.raises(DefectDojoError) as ei:
        client.push([_finding()], product="p", engagement="e")
    assert "403" in str(ei.value)


def test_push_handles_non_json_response():
    client, _ = _client(_FakeResp(201, payload=None))
    assert client.push([_finding()], product="p", engagement="e") == {"status_code": 201}


# ---- sink ---------------------------------------------------------------- #
def _sink(resp, **kw):
    sess = _FakeSession(resp)
    cfg = DefectDojoConfig(url="https://dd.example", token="tok")
    return DefectDojoSink(cfg, session=sess, **kw), sess


def test_sink_is_configured():
    sink, _ = _sink(_FakeResp(201, {"test": 1}))
    assert sink.is_configured() is True
    assert DefectDojoSink(None).is_configured() is False


def test_sink_push_returns_result_and_calls_api():
    sink, sess = _sink(_FakeResp(201, {"test": 9, "engagement_id": 3}))
    res = sink.push([_finding()], SinkContext(app_name="commercial", stage="preprod"))
    assert res.ok and res.pushed == 1
    # product defaults to the app name; engagement to "ai-protect <stage>"
    assert sess.calls[0][1]["data"]["product_name"] == "commercial"
    assert sess.calls[0][1]["data"]["engagement_name"] == "ai-protect preprod"
    assert res.ref["test"] == 9 and res.ref["engagement_id"] == 3


def test_sink_context_overrides_product_engagement():
    sink, sess = _sink(_FakeResp(201, {"test": 1}))
    sink.push([_finding()], SinkContext(app_name="commercial", product="Prod X",
                                        engagement="Eng Y", test_title="nightly"))
    data = sess.calls[0][1]["data"]
    assert data["product_name"] == "Prod X"
    assert data["engagement_name"] == "Eng Y"
    assert data["test_title"] == "nightly"


def test_sink_min_severity_filters():
    sink, sess = _sink(_FakeResp(201, {"test": 1}), min_severity="critical")
    res = sink.push([_finding(severity=Severity.HIGH), _finding(severity=Severity.CRITICAL)],
                    SinkContext(app_name="a"))
    assert res.pushed == 1
    doc = json.loads(sess.calls[0][1]["files"]["file"][1].read().decode())
    assert len(doc["findings"]) == 1


def test_sink_push_http_error_returns_not_ok():
    sink, _ = _sink(_FakeResp(500, text="boom"))
    res = sink.push([_finding()], SinkContext(app_name="a"))
    assert res.ok is False and "500" in res.detail


# ---- registry ------------------------------------------------------------ #
def test_registry_lists_defectdojo():
    assert "defectdojo" in sink_names()


def test_registry_get_sink_unknown_raises():
    with pytest.raises(KeyError):
        get_sink("nope")


def test_registry_configured_sinks_empty_without_creds(monkeypatch):
    monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
    monkeypatch.delenv("DEFECTDOJO_API_TOKEN", raising=False)
    assert configured_sinks() == []


# ---- config -------------------------------------------------------------- #
def test_config_from_env(monkeypatch):
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd.example/")
    monkeypatch.setenv("DEFECTDOJO_API_TOKEN", "tok")
    cfg = DefectDojoConfig.from_env()
    assert cfg.url == "https://dd.example"          # trailing slash stripped
    assert cfg.token == "tok" and cfg.verify_ssl is True


def test_config_verify_ssl_off(monkeypatch):
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd.example")
    monkeypatch.setenv("DEFECTDOJO_API_TOKEN", "tok")
    monkeypatch.setenv("DEFECTDOJO_VERIFY_SSL", "0")
    assert DefectDojoConfig.from_env().verify_ssl is False


def test_config_missing_raises(monkeypatch):
    monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
    monkeypatch.delenv("DEFECTDOJO_API_TOKEN", raising=False)
    assert DefectDojoConfig.resolve() is None
    with pytest.raises(DefectDojoConfigError):
        DefectDojoConfig.from_env()


def test_config_explicit_args_override_env(monkeypatch):
    monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
    monkeypatch.delenv("DEFECTDOJO_API_TOKEN", raising=False)
    cfg = DefectDojoConfig.from_env(url="https://x", token="y")
    assert cfg.url == "https://x" and cfg.token == "y"


# ---- manifest integration mapping ---------------------------------------- #
def test_manifest_integration_mapping():
    from pipeline.core.manifest import Manifest
    m = Manifest.from_dict({
        "name": "app", "owner": "o@x", "description": "",
        "data_sensitivity": "public", "decision_impact": "advisory",
        "integration_footprint": "read_only", "user_population": "team",
        "integrations": {"defectdojo": {"product": "P", "engagement": "E"}},
    })
    assert m.integration("defectdojo") == {"product": "P", "engagement": "E"}
    assert m.integration("missing") == {}


# ---- CLI honors the manifest's product/engagement ------------------------ #
def test_cli_defectdojo_honors_manifest(tmp_path, monkeypatch):
    """`cli defectdojo --manifest` pushes with the manifest's product/engagement."""
    import yaml

    from pipeline import cli
    from pipeline.core.findings import FindingStore
    import pipeline.integrations.defectdojo as ddpkg

    findings_path = tmp_path / "f.jsonl"
    FindingStore(findings_path).append(_finding(app_name="metaads-commercial"))

    manifest_path = tmp_path / "m.yml"
    manifest_path.write_text(yaml.safe_dump({
        "name": "metaads-commercial", "owner": "o@x", "description": "",
        "data_sensitivity": "financial", "decision_impact": "automated_action",
        "integration_footprint": "external_action", "user_population": "external",
        "integrations": {"defectdojo": {
            "product": "Meta Ads Commercial SaaS", "engagement": "ai-protect preprod"}},
    }))

    captured = {}

    class _FakeSink:
        def __init__(self, *a, **k):
            pass

        def push(self, findings, ctx):
            captured["ctx"] = ctx
            captured["n"] = len(findings)
            from pipeline.integrations.base import SinkResult
            return SinkResult(sink="defectdojo", ok=True, pushed=len(findings), detail="ok")

    monkeypatch.setattr(ddpkg, "DefectDojoSink", _FakeSink)
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd.example")
    monkeypatch.setenv("DEFECTDOJO_API_TOKEN", "tok")

    cli.main(["--findings", str(findings_path), "defectdojo", "--manifest", str(manifest_path)])

    ctx = captured["ctx"]
    assert ctx.app_name == "metaads-commercial"
    assert ctx.product == "Meta Ads Commercial SaaS"
    assert ctx.engagement == "ai-protect preprod"
    assert captured["n"] == 1            # filtered to the manifest's app


def test_cli_defectdojo_explicit_overrides_manifest(tmp_path, monkeypatch):
    import yaml

    from pipeline import cli
    from pipeline.core.findings import FindingStore
    import pipeline.integrations.defectdojo as ddpkg

    findings_path = tmp_path / "f.jsonl"
    FindingStore(findings_path).append(_finding(app_name="metaads-commercial"))
    manifest_path = tmp_path / "m.yml"
    manifest_path.write_text(yaml.safe_dump({
        "name": "metaads-commercial", "owner": "o@x", "description": "",
        "data_sensitivity": "financial", "decision_impact": "automated_action",
        "integration_footprint": "external_action", "user_population": "external",
        "integrations": {"defectdojo": {"product": "From Manifest", "engagement": "E"}},
    }))

    captured = {}

    class _FakeSink:
        def __init__(self, *a, **k):
            pass

        def push(self, findings, ctx):
            captured["ctx"] = ctx
            from pipeline.integrations.base import SinkResult
            return SinkResult(sink="defectdojo", ok=True, pushed=1, detail="ok")

    monkeypatch.setattr(ddpkg, "DefectDojoSink", _FakeSink)
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd.example")
    monkeypatch.setenv("DEFECTDOJO_API_TOKEN", "tok")

    cli.main(["--findings", str(findings_path), "defectdojo",
              "--manifest", str(manifest_path), "--product", "Override"])
    assert captured["ctx"].product == "Override"
