import pytest
from sepgen.models.policy import (
    PolicyModule, FileContexts, TypeDeclaration,
    AllowRule, MacroCall, FileContextEntry
)

def test_create_policy_module():
    """Test creating a PolicyModule"""
    policy = PolicyModule(name="myapp", version="1.0.0")
    assert policy.name == "myapp"
    assert policy.version == "1.0.0"
    assert len(policy.types) == 0
    assert len(policy.allow_rules) == 0

def test_add_type_to_policy():
    """Test adding types to policy"""
    policy = PolicyModule(name="myapp", version="1.0.0")
    policy.types.append(TypeDeclaration("myapp_t"))
    policy.types.append(TypeDeclaration("myapp_conf_t"))
    assert len(policy.types) == 2
    assert policy.types[0].name == "myapp_t"

def test_create_file_contexts():
    """Test creating FileContexts"""
    contexts = FileContexts()
    contexts.entries.append(FileContextEntry(
        path="/usr/bin/myapp",
        selinux_type="myapp_exec_t"
    ))
    assert len(contexts.entries) == 1
    assert contexts.entries[0].path == "/usr/bin/myapp"
