"""Dashboard now SHOWS intel_match_unverified findings by default (they're
KEV-bounded and high-signal); ?include_unverified=0 hides them."""
from __future__ import annotations

from ai_protect.core.findings import Category, FindingStore, Severity, new_finding
from ai_protect.ui.server import _include_unverified, create_app


class _Req:
    def __init__(self, **args):
        self.args = args


def test_include_unverified_defaults_to_true():
    assert _include_unverified(_Req()) is True                       # absent → shown
    assert _include_unverified(_Req(include_unverified="1")) is True
    assert _include_unverified(_Req(include_unverified="0")) is False
    assert _include_unverified(_Req(include_unverified="off")) is False
    assert _include_unverified(_Req(include_unverified="false")) is False


def _seed(path):
    store = FindingStore(path)
    store.append(new_finding(
        app_name="app", tier=3, stage="build", adapter="bandit",
        category=Category.SECRETS, severity=Severity.HIGH,
        title="real scanner finding", description="d"))
    store.append(new_finding(
        app_name="app", tier=3, stage="build", adapter="intel_match",
        category=Category.SUPPLY_CHAIN, severity=Severity.HIGH,
        title="Intel match: CVE-2024-0001", description="d",
        evidence={"intel_match_unverified": True, "kev_listed": True}))


def test_api_findings_includes_intel_match_by_default(tmp_path):
    fp = tmp_path / "findings.jsonl"
    _seed(str(fp))
    client = create_app(str(fp), str(tmp_path)).test_client()

    default = {f["title"] for f in client.get("/api/findings").get_json()}
    assert "Intel match: CVE-2024-0001" in default        # shown by default now
    assert "real scanner finding" in default

    hidden = {f["title"] for f in client.get("/api/findings?include_unverified=0").get_json()}
    assert "Intel match: CVE-2024-0001" not in hidden      # explicit opt-out hides it
    assert "real scanner finding" in hidden
