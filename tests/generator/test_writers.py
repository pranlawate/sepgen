import pytest
from pathlib import Path
from sepgen.generator.te_writer import TEWriter
from sepgen.generator.fc_writer import FCWriter
from sepgen.models.policy import PolicyModule, FileContexts, TypeDeclaration, MacroCall


def test_te_writer_basic(tmp_path):
    policy = PolicyModule(name="myapp", version="1.0.0")
    policy.types.append(TypeDeclaration("myapp_t"))
    policy.types.append(TypeDeclaration("myapp_exec_t"))
    policy.macro_calls.append(MacroCall("init_daemon_domain", ["myapp_t", "myapp_exec_t"]))

    output_path = tmp_path / "myapp.te"
    TEWriter().write(policy, output_path)

    assert output_path.exists()
    content = output_path.read_text()
    assert "policy_module(myapp, 1.0.0)" in content
    assert "type myapp_t;" in content
    assert "init_daemon_domain(myapp_t, myapp_exec_t)" in content


def test_fc_writer_basic(tmp_path):
    contexts = FileContexts()
    contexts.add_entry("/usr/bin/myapp", "myapp_exec_t")
    contexts.add_entry("/etc/myapp.conf", "myapp_conf_t")

    output_path = tmp_path / "myapp.fc"
    FCWriter().write(contexts, output_path)

    assert output_path.exists()
    content = output_path.read_text()
    assert "/usr/bin/myapp" in content
    assert "myapp_exec_t" in content
    assert "/etc/myapp.conf" in content
    assert "gen_context" in content
