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


def test_generate_var_run_type():
    generator = TEGenerator(module_name="myapp")
    intents = [
        Intent(intent_type=IntentType.PID_FILE,
               accesses=[Access(AccessType.FILE_WRITE, "/var/run/myapp.pid", "open")]),
    ]
    policy = generator.generate(intents)

    type_names = [t.name for t in policy.types]
    assert "myapp_var_run_t" in type_names

    macro_names = [m.name for m in policy.macro_calls]
    assert "files_pid_file" in macro_names
    assert "files_pid_filetrans" in macro_names
    assert "manage_dirs_pattern" in macro_names
    assert "manage_files_pattern" in macro_names


def test_generate_self_capability_rules():
    generator = TEGenerator(module_name="myapp")
    intents = [
        Intent(intent_type=IntentType.SELF_CAPABILITY,
               accesses=[Access(AccessType.PROCESS_CONTROL, "", "setrlimit",
                                {"capability": "sys_resource"})]),
    ]
    policy = generator.generate(intents)

    self_rules = [r for r in policy.allow_rules if r.target == "self"]
    cap_rules = [r for r in self_rules if r.object_class == "capability"]
    assert len(cap_rules) == 1
    assert "sys_resource" in cap_rules[0].permissions

    proc_rules = [r for r in self_rules if r.object_class == "process"]
    assert len(proc_rules) == 1
    assert "setrlimit" in proc_rules[0].permissions


def test_generate_self_unix_socket_rules():
    generator = TEGenerator(module_name="myapp")
    intents = [
        Intent(intent_type=IntentType.UNIX_SOCKET_SERVER,
               accesses=[Access(AccessType.SOCKET_BIND, "", "bind", {"domain": "PF_UNIX"})]),
    ]
    policy = generator.generate(intents)

    socket_rules = [r for r in policy.allow_rules
                    if r.target == "self" and r.object_class == "unix_stream_socket"]
    assert len(socket_rules) == 1
    assert "create" in socket_rules[0].permissions
    assert "bind" in socket_rules[0].permissions


def test_generate_var_run_with_unix_socket():
    generator = TEGenerator(module_name="myapp")
    intents = [
        Intent(intent_type=IntentType.PID_FILE,
               accesses=[Access(AccessType.FILE_WRITE, "/var/run/myapp/.sock", "bind")]),
        Intent(intent_type=IntentType.UNIX_SOCKET_SERVER,
               accesses=[Access(AccessType.SOCKET_BIND, "", "bind", {"domain": "PF_UNIX"})]),
    ]
    policy = generator.generate(intents)

    macro_names = [m.name for m in policy.macro_calls]
    assert "manage_sock_files_pattern" in macro_names
