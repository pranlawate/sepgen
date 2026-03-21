from sepgen.intent.rules import PathPrefixRule
from sepgen.models.access import Access, AccessType
from sepgen.models.intent import IntentType


def test_var_log_classified_as_log_file():
    rule = PathPrefixRule()
    access = Access(AccessType.FILE_WRITE, "/var/log/myapp.log", "open")
    assert rule.matches(access)
    assert rule.get_intent_type() == IntentType.LOG_FILE


def test_tmp_classified_as_temp_file():
    rule = PathPrefixRule()
    access = Access(AccessType.FILE_CREATE, "/tmp/myapp.sock", "open")
    assert rule.matches(access)
    assert rule.get_intent_type() == IntentType.TEMP_FILE


def test_var_lib_classified_as_data_dir():
    rule = PathPrefixRule()
    access = Access(AccessType.FILE_READ, "/var/lib/myapp/data.db", "open")
    assert rule.matches(access)
    assert rule.get_intent_type() == IntentType.DATA_DIR


def test_unrelated_path_not_matched():
    rule = PathPrefixRule()
    access = Access(AccessType.FILE_READ, "/etc/myapp.conf", "open")
    assert not rule.matches(access)


def test_socket_type_not_matched():
    rule = PathPrefixRule()
    access = Access(AccessType.SOCKET_CREATE, "/var/log/something", "socket")
    assert not rule.matches(access)
