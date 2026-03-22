import pytest
from pathlib import Path
from sepgen.merger.policy_merger import PolicyMerger
from sepgen.models.policy import PolicyModule, TypeDeclaration, MacroCall


def test_detect_existing_policy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "myapp.te").write_text("policy_module(myapp, 1.0.0)")
    (tmp_path / "myapp.fc").write_text("/usr/bin/myapp")

    merger = PolicyMerger()
    te_path, fc_path = merger.detect_existing_policy("myapp")
    assert te_path == tmp_path / "myapp.te"
    assert fc_path == tmp_path / "myapp.fc"


def test_detect_no_existing_policy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    merger = PolicyMerger()
    te_path, fc_path = merger.detect_existing_policy("myapp")
    assert te_path is None
    assert fc_path is None


def test_compare_policies():
    existing = PolicyModule(name="myapp", version="1.0.0")
    existing.types.append(TypeDeclaration("myapp_t"))
    existing.macro_calls.append(MacroCall("read_files_pattern", ["myapp_t", "myapp_conf_t", "myapp_conf_t"]))

    new = PolicyModule(name="myapp", version="1.0.0")
    new.types.append(TypeDeclaration("myapp_t"))
    new.types.append(TypeDeclaration("myapp_data_t"))
    new.macro_calls.append(MacroCall("manage_files_pattern", ["myapp_t", "myapp_conf_t", "myapp_conf_t"]))

    merger = PolicyMerger()
    report = merger.compare(existing, new)

    assert len(report.matched_types) >= 1
    assert "myapp_data_t" in [t.name for t in report.new_types]
    assert len(report.new_macros) >= 1


def test_compare_same_name_conflict():
    existing = PolicyModule(name="myapp", version="1.0.0")
    existing.macro_calls.append(MacroCall("read_files_pattern", ["myapp_t", "old_t", "old_t"]))

    new = PolicyModule(name="myapp", version="1.0.0")
    new.macro_calls.append(MacroCall("read_files_pattern", ["myapp_t", "new_t", "new_t"]))

    merger = PolicyMerger()
    report = merger.compare(existing, new)
    assert len(report.conflicts) == 1
    assert report.conflicts[0]['name'] == "read_files_pattern"
