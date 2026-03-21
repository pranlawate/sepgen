import pytest
from sepgen.analyzer.syscall_mapper import SyscallMapper
from sepgen.models.access import Access, AccessType


def test_map_fopen_to_open():
    """Test mapping fopen() to open syscall"""
    mapper = SyscallMapper()
    access = mapper.map_function_call('fopen', ['"/etc/app.conf"', '"r"'])

    assert access is not None
    assert access.syscall == "open"
    assert access.path == "/etc/app.conf"
    assert access.access_type == AccessType.FILE_READ


def test_map_fopen_write_mode():
    """Test mapping fopen() with write mode"""
    mapper = SyscallMapper()
    access = mapper.map_function_call('fopen', ['"/var/log/app.log"', '"w"'])

    assert access.access_type == AccessType.FILE_WRITE
    assert access.path == "/var/log/app.log"


def test_map_socket_call():
    """Test mapping socket() call"""
    mapper = SyscallMapper()
    access = mapper.map_function_call('socket', ['AF_INET', 'SOCK_STREAM', '0'])

    assert access.syscall == "socket"
    assert access.access_type == AccessType.SOCKET_CREATE
    assert access.details["domain"] == "AF_INET"


def test_map_bind_call():
    """Test mapping bind() call"""
    mapper = SyscallMapper()
    access = mapper.map_function_call('bind', [])

    assert access.syscall == "bind"
    assert access.access_type == AccessType.SOCKET_BIND
