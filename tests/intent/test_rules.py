import pytest
from sepgen.intent.rules import PidFileRule, ConfigFileRule, SyslogRule, NetworkServerRule, UdpServerRule
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
    access = Access(access_type=AccessType.SOCKET_BIND, path="tcp:8080", syscall="bind",
                    details={"domain": "AF_INET", "sock_type": "SOCK_STREAM"})
    assert rule.matches(access) is True
    assert rule.get_intent_type() == IntentType.NETWORK_SERVER


def test_network_server_rule_rejects_dgram():
    rule = NetworkServerRule()
    access = Access(access_type=AccessType.SOCKET_BIND, path="", syscall="bind",
                    details={"domain": "AF_INET", "sock_type": "SOCK_DGRAM"})
    assert rule.matches(access) is False


def test_network_server_rule_rejects_unknown_domain():
    rule = NetworkServerRule()
    access = Access(access_type=AccessType.SOCKET_BIND, path="", syscall="bind")
    assert rule.matches(access) is False


def test_udp_server_rule_matches():
    rule = UdpServerRule()
    access = Access(access_type=AccessType.SOCKET_BIND, path="", syscall="bind",
                    details={"domain": "AF_INET", "sock_type": "SOCK_DGRAM"})
    assert rule.matches(access) is True
    assert rule.get_intent_type() == IntentType.UDP_NETWORK_SERVER


def test_udp_server_rule_rejects_stream():
    rule = UdpServerRule()
    access = Access(access_type=AccessType.SOCKET_BIND, path="", syscall="bind",
                    details={"domain": "AF_INET", "sock_type": "SOCK_STREAM"})
    assert rule.matches(access) is False
