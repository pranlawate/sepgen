import pytest
from sepgen.selinux.macro_lookup import MacroLookup
from sepgen.models.intent import Intent, IntentType
from sepgen.models.access import Access, AccessType


def test_suggest_macro_for_syslog():
    lookup = MacroLookup()
    intent = Intent(intent_type=IntentType.SYSLOG, accesses=[Access(AccessType.SOCKET_CONNECT, "/dev/log", "connect")])
    assert lookup.suggest_macro(intent) == "logging_send_syslog_msg"


def test_suggest_macro_for_pid_file():
    """PID_FILE macros are generated directly by TEGenerator, not MacroLookup."""
    lookup = MacroLookup()
    intent = Intent(intent_type=IntentType.PID_FILE, accesses=[Access(AccessType.FILE_WRITE, "/var/run/app.pid", "open")])
    assert lookup.suggest_macro(intent) is None


def test_suggest_macro_for_config_file():
    lookup = MacroLookup()
    intent = Intent(intent_type=IntentType.CONFIG_FILE, accesses=[Access(AccessType.FILE_READ, "/etc/app.conf", "open")])
    assert lookup.suggest_macro(intent) == "read_files_pattern"


def test_suggest_macro_for_unknown_intent():
    lookup = MacroLookup()
    intent = Intent(intent_type=IntentType.UNKNOWN, accesses=[Access(AccessType.FILE_READ, "/tmp/file.txt", "open")])
    assert lookup.suggest_macro(intent) is None
