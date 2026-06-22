"""Regression tests for settings get/set — especially the checkbox-off bug
that made on-by-default toggles (e.g. the DAST scope-prefix guard) impossible
to disable."""
from ai_protect.core import settings as s


def test_unchecked_checkbox_is_honored_not_reverted_to_default(tmp_path, monkeypatch):
    monkeypatch.setattr(s, "CONFIG_PATH", tmp_path / "config.json")
    key = "dast_require_scope_prefix_for_crawlers"   # checkbox, schema default "on"

    # Absent -> schema default ("on").
    assert s.get(key, "on") == "on"

    # Uncheck it (the UI persists an unchecked checkbox as "").
    assert s.set_many({key: ""}) == {}
    assert s.load().get(key) == ""                   # persisted as empty
    assert s.get(key, "on") == ""                    # honored as OFF, not reverted to "on"

    # Re-check it.
    assert s.set_many({key: "on"}) == {}
    assert s.get(key, "on") == "on"


def test_empty_non_checkbox_still_falls_back_to_default(tmp_path, monkeypatch):
    monkeypatch.setattr(s, "CONFIG_PATH", tmp_path / "config.json")
    # A text/select field cleared to "" should still fall back to its schema
    # default (only checkboxes treat "" as a real value).
    s.set_many({"github_default_ref": ""})
    assert s.get("github_default_ref") == "main"
