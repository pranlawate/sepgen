from sepgen.intent.rules import VarRunRule
from sepgen.models.access import Access, AccessType
from sepgen.models.intent import IntentType


def test_var_run_unlink_matches():
    rule = VarRunRule()
    access = Access(
        access_type=AccessType.FILE_UNLINK,
        path="/var/run/setrans/.setrans-unix",
        syscall="unlink"
    )
    assert rule.matches(access) is True
    assert rule.get_intent_type() == IntentType.PID_FILE


def test_var_run_chmod_matches():
    rule = VarRunRule()
    access = Access(
        access_type=AccessType.FILE_SETATTR,
        path="/var/run/setrans/.setrans-unix",
        syscall="chmod"
    )
    assert rule.matches(access) is True


def test_var_run_write_matches():
    rule = VarRunRule()
    access = Access(
        access_type=AccessType.FILE_WRITE,
        path="/var/run/setrans/data.txt",
        syscall="fopen"
    )
    assert rule.matches(access) is True


def test_run_path_matches():
    rule = VarRunRule()
    access = Access(
        access_type=AccessType.FILE_UNLINK,
        path="/run/setrans/.setrans-unix",
        syscall="unlink"
    )
    assert rule.matches(access) is True


def test_etc_path_does_not_match():
    rule = VarRunRule()
    access = Access(
        access_type=AccessType.FILE_UNLINK,
        path="/etc/app.conf",
        syscall="unlink"
    )
    assert rule.matches(access) is False


def test_socket_type_does_not_match():
    rule = VarRunRule()
    access = Access(
        access_type=AccessType.SOCKET_BIND,
        path="/var/run/setrans/.setrans-unix",
        syscall="bind"
    )
    assert rule.matches(access) is False
