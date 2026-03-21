import pytest
from sepgen.selinux.type_generator import TypeGenerator
from sepgen.models.intent import Intent, IntentType
from sepgen.models.access import Access, AccessType


def test_generate_config_file_type():
    generator = TypeGenerator()
    intent = Intent(intent_type=IntentType.CONFIG_FILE, accesses=[Access(AccessType.FILE_READ, "/etc/app.conf", "open")])
    assert generator.generate_type_name("myapp", intent) == "myapp_conf_t"


def test_generate_pid_file_type():
    generator = TypeGenerator()
    intent = Intent(intent_type=IntentType.PID_FILE, accesses=[Access(AccessType.FILE_WRITE, "/var/run/app.pid", "open")])
    assert generator.generate_type_name("myapp", intent) == "myapp_var_run_t"


def test_generate_data_dir_type():
    generator = TypeGenerator()
    intent = Intent(intent_type=IntentType.DATA_DIR, accesses=[Access(AccessType.FILE_WRITE, "/var/myapp/data.txt", "open")])
    assert generator.generate_type_name("myapp", intent) == "myapp_data_t"


def test_unknown_intent_returns_none():
    generator = TypeGenerator()
    intent = Intent(intent_type=IntentType.UNKNOWN, accesses=[Access(AccessType.FILE_READ, "/tmp/file.txt", "open")])
    assert generator.generate_type_name("myapp", intent) is None
