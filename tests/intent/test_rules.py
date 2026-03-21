import pytest
from sepgen.intent.rules import PidFileRule, ConfigFileRule, SyslogRule, NetworkServerRule
from sepgen.models.access import Access, AccessType
from sepgen.models.intent import IntentType


def test_pid_file_rule_matches():
    rule = PidFileRule()
    access = Access(access_type=AccessType.FILE_WRITE, path="/var/run/myapp.pid", syscall="open")
    assert rule.matches(access) is True
    assert rule.get_intent_type() == IntentType.PID_FILE


def test_config_file_rule_matches():
    rule = ConfigFileRule()
    access = Access(access_type=AccessType.FILE_READ, path="/etc/myapp/config.ini", syscall="open")
    assert rule.matches(access) is True
    assert rule.get_intent_type() == IntentType.CONFIG_FILE


def test_syslog_rule_matches():
    rule = SyslogRule()
    access = Access(access_type=AccessType.SOCKET_CONNECT, path="/dev/log", syscall="connect", details={"is_syslog": True})
    assert rule.matches(access) is True
    assert rule.get_intent_type() == IntentType.SYSLOG


def test_network_server_rule_matches():
    rule = NetworkServerRule()
    access = Access(access_type=AccessType.SOCKET_BIND, path="tcp:8080", syscall="bind")
    assert rule.matches(access) is True
    assert rule.get_intent_type() == IntentType.NETWORK_SERVER
