import pytest
from pathlib import Path
from sepgen.tracer.strace_parser import StraceParser
from sepgen.models.access import AccessType


def test_parse_open_readonly():
    """Test parsing open() with O_RDONLY"""
    parser = StraceParser()
    line = 'open("/etc/myapp.conf", O_RDONLY) = 3'
    accesses = parser.parse_line(line)

    assert len(accesses) == 1
    assert accesses[0].syscall == "open"
    assert accesses[0].path == "/etc/myapp.conf"
    assert accesses[0].access_type == AccessType.FILE_READ


def test_parse_open_write():
    """Test parsing open() with O_WRONLY|O_CREAT"""
    parser = StraceParser()
    line = 'open("/var/run/app.pid", O_WRONLY|O_CREAT, 0644) = 3'
    accesses = parser.parse_line(line)

    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.FILE_CREATE


def test_parse_failed_open():
    """Test that failed syscalls are ignored"""
    parser = StraceParser()
    line = 'open("/nonexistent", O_RDONLY) = -1 ENOENT'
    accesses = parser.parse_line(line)

    assert len(accesses) == 0


def test_parse_socket_bind():
    """Test parsing bind() with port"""
    parser = StraceParser()
    line = 'bind(3, {sa_family=AF_INET, sin_port=htons(8080)}, 16) = 0'
    accesses = parser.parse_line(line)

    assert len(accesses) == 1
    assert accesses[0].syscall == "bind"
    assert accesses[0].access_type == AccessType.SOCKET_BIND
    assert accesses[0].details["port"] == 8080


def test_parse_syslog_connection():
    """Test parsing connection to /dev/log"""
    parser = StraceParser()
    line = 'connect(4, {sa_family=AF_UNIX, sun_path="/dev/log"}, 110) = 0'
    accesses = parser.parse_line(line)

    assert len(accesses) == 1
    assert accesses[0].path == "/dev/log"
    assert accesses[0].details.get("is_syslog") is True


def test_parse_file():
    """Test parsing complete strace output file"""
    parser = StraceParser()
    fixture = Path(__file__).parent.parent / "fixtures" / "strace_output.txt"
    accesses = parser.parse_file(fixture)

    assert len(accesses) > 0

    file_accesses = [a for a in accesses if a.access_type in [AccessType.FILE_READ, AccessType.FILE_CREATE]]
    assert len(file_accesses) >= 2
