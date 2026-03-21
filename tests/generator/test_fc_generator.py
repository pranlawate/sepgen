import pytest
from sepgen.generator.fc_generator import FCGenerator
from sepgen.models.intent import Intent, IntentType
from sepgen.models.access import Access, AccessType
from sepgen.models.policy import FileContexts


def test_generate_basic_fc():
    generator = FCGenerator(module_name="myapp", exec_path="/usr/bin/myapp")
    contexts = generator.generate([])

    assert isinstance(contexts, FileContexts)
    paths = [e.path for e in contexts.entries]
    assert "/usr/bin/myapp" in paths


def test_generate_with_config_file():
    generator = FCGenerator(module_name="myapp")
    intents = [
        Intent(intent_type=IntentType.CONFIG_FILE,
               accesses=[Access(AccessType.FILE_READ, "/etc/myapp/config.ini", "open")],
               selinux_type="myapp_conf_t"),
    ]
    contexts = generator.generate(intents)

    paths = [e.path for e in contexts.entries]
    assert "/etc/myapp/config.ini" in paths
    config_entry = [e for e in contexts.entries if e.path == "/etc/myapp/config.ini"][0]
    assert config_entry.selinux_type == "myapp_conf_t"


def test_generate_multiple_contexts():
    generator = FCGenerator(module_name="myapp", exec_path="/usr/bin/myapp")
    intents = [
        Intent(intent_type=IntentType.CONFIG_FILE,
               accesses=[Access(AccessType.FILE_READ, "/etc/myapp.conf", "open")],
               selinux_type="myapp_conf_t"),
        Intent(intent_type=IntentType.PID_FILE,
               accesses=[Access(AccessType.FILE_WRITE, "/var/run/myapp.pid", "open")],
               selinux_type="myapp_var_run_t"),
    ]
    contexts = generator.generate(intents)
    assert len(contexts.entries) >= 3
