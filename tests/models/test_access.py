import pytest
from sepgen.models.access import Access, AccessType

def test_create_file_read_access():
    """Test creating a file read access"""
    access = Access(
        access_type=AccessType.FILE_READ,
        path="/etc/myapp.conf",
        syscall="open"
    )
    assert access.path == "/etc/myapp.conf"
    assert access.access_type == AccessType.FILE_READ
    assert access.syscall == "open"

def test_create_socket_bind_access():
    """Test creating a socket bind access"""
    access = Access(
        access_type=AccessType.SOCKET_BIND,
        path="tcp:8080",
        syscall="bind",
        details={"port": 8080, "protocol": "tcp"}
    )
    assert access.details["port"] == 8080
    assert access.access_type == AccessType.SOCKET_BIND

def test_access_with_source_location():
    """Test access with source code location"""
    access = Access(
        access_type=AccessType.FILE_WRITE,
        path="/var/log/app.log",
        syscall="open",
        source_file="main.c",
        source_line=42
    )
    assert access.source_file == "main.c"
    assert access.source_line == 42
