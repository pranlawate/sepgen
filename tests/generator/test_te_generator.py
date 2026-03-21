import pytest
from sepgen.generator.te_generator import TEGenerator
from sepgen.models.intent import Intent, IntentType
from sepgen.models.access import Access, AccessType
from sepgen.models.policy import PolicyModule


def test_generate_basic_policy():
    generator = TEGenerator(module_name="myapp")
    intents = [
        Intent(intent_type=IntentType.CONFIG_FILE, accesses=[Access(AccessType.FILE_READ, "/etc/myapp.conf", "open")]),
    ]
    policy = generator.generate(intents)

    assert isinstance(policy, PolicyModule)
    assert policy.name == "myapp"
    assert policy.version == "1.0.0"
    type_names = [t.name for t in policy.types]
    assert "myapp_t" in type_names
    assert "myapp_exec_t" in type_names


def test_generate_with_custom_types():
    generator = TEGenerator(module_name="myapp")
    intents = [
        Intent(intent_type=IntentType.CONFIG_FILE, accesses=[Access(AccessType.FILE_READ, "/etc/myapp.conf", "open")]),
        Intent(intent_type=IntentType.PID_FILE, accesses=[Access(AccessType.FILE_WRITE, "/var/run/myapp.pid", "open")]),
    ]
    policy = generator.generate(intents)

    type_names = [t.name for t in policy.types]
    assert "myapp_conf_t" in type_names
    assert "myapp_var_run_t" in type_names


def test_generate_with_macros():
    generator = TEGenerator(module_name="myapp")
    intents = [
        Intent(intent_type=IntentType.SYSLOG, accesses=[Access(AccessType.SOCKET_CONNECT, "/dev/log", "connect")]),
    ]
    policy = generator.generate(intents)

    macro_names = [m.name for m in policy.macro_calls]
    assert "logging_send_syslog_msg" in macro_names
