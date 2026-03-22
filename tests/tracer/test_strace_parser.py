import pytest
from pathlib import Path
from sepgen.tracer.strace_parser import StraceParser
from sepgen.models.access import AccessType


@pytest.fixture
def parser():
    return StraceParser()


@pytest.fixture
def fixture_path():
    return Path(__file__).parent.parent / "fixtures" / "strace_output.txt"


def test_parse_fixture_file(parser, fixture_path):
    accesses = parser.parse_file(fixture_path)
    assert len(accesses) > 0
    types = {a.access_type for a in accesses}
    assert AccessType.FILE_READ in types
    assert AccessType.FILE_CREATE in types
    assert AccessType.SOCKET_CREATE in types
    assert AccessType.SOCKET_BIND in types


def test_openat_with_pid_prefix(parser):
    line = '1234  openat(AT_FDCWD, "/etc/myapp.conf", O_RDONLY) = 3'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.FILE_READ
    assert accesses[0].path == "/etc/myapp.conf"


def test_openat_write_create(parser):
    line = 'openat(AT_FDCWD, "/var/run/myapp.pid", O_WRONLY|O_CREAT, 0644) = 4'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.FILE_CREATE


def test_openat_failed_ignored(parser):
    line = 'openat(AT_FDCWD, "/nonexistent", O_RDONLY) = -1 ENOENT'
    accesses = parser.parse_line(line)
    assert len(accesses) == 0


def test_socket_tcp(parser):
    line = 'socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 6'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.SOCKET_CREATE
    assert accesses[0].details["domain"] == "AF_INET"
    assert accesses[0].details["sock_type"] == "SOCK_STREAM"


def test_socket_udp(parser):
    line = 'socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) = 7'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].details["sock_type"] == "SOCK_DGRAM"


def test_socket_with_cloexec_flags(parser):
    line = 'socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0) = 3'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].details["domain"] == "AF_UNIX"
    assert accesses[0].details["sock_type"] == "SOCK_DGRAM"


def test_socket_netlink(parser):
    line = 'socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) = 10'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.NETLINK_SOCKET
    assert accesses[0].details["protocol"] == "NETLINK_ROUTE"


def test_bind_inet_with_fd_tracking(parser):
    parser.parse_line('socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 6')
    accesses = parser.parse_line('bind(6, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0')
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.SOCKET_BIND
    assert accesses[0].details["domain"] == "AF_INET"
    assert accesses[0].details["sock_type"] == "SOCK_STREAM"
    assert accesses[0].details["port"] == 8080


def test_bind_udp_fd_tracking(parser):
    parser.parse_line('socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) = 7')
    accesses = parser.parse_line('bind(7, {sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("0.0.0.0")}, 16) = 0')
    assert len(accesses) == 1
    assert accesses[0].details["sock_type"] == "SOCK_DGRAM"


def test_bind_unix(parser):
    parser.parse_line('socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 8')
    accesses = parser.parse_line('bind(8, {sa_family=AF_UNIX, sun_path="/var/run/myapp.sock"}, 110) = 0')
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.SOCKET_BIND
    assert accesses[0].path == "/var/run/myapp.sock"
    assert accesses[0].details["domain"] == "AF_UNIX"
    assert accesses[0].details["sock_type"] == "SOCK_STREAM"


def test_connect_syslog(parser):
    line = 'connect(9, {sa_family=AF_UNIX, sun_path="/dev/log"}, 110) = 0'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.SYSLOG
    assert accesses[0].details["is_syslog"] is True


def test_connect_unix_non_syslog(parser):
    line = 'connect(11, {sa_family=AF_UNIX, sun_path="/var/run/dbus/system_bus_socket"}, 110) = 0'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.SOCKET_CONNECT
    assert accesses[0].path == "/var/run/dbus/system_bus_socket"


def test_listen(parser):
    line = 'listen(6, 5) = 0'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.SOCKET_LISTEN


def test_execve(parser):
    line = 'execve("/usr/bin/testapp", ["testapp"], 0x7ffd... /* 24 vars */) = 0'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.PROCESS_EXEC
    assert accesses[0].path == "/usr/bin/testapp"


def test_unlink(parser):
    line = 'unlink("/var/run/testapp/testapp.sock") = 0'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.FILE_UNLINK


def test_chmod(parser):
    line = 'chmod("/var/run/testapp", 0755) = 0'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.FILE_SETATTR


def test_setrlimit(parser):
    line = 'prlimit64(0, RLIMIT_NOFILE, {rlim_cur=65536, rlim_max=65536}, NULL) = 0'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.PROCESS_CONTROL
    assert accesses[0].details["capability"] == "sys_resource"


def test_shmget(parser):
    line = 'shmget(IPC_PRIVATE, 4096, IPC_CREAT|0600) = 12345'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.IPC_SYSV
    assert accesses[0].details["ipc_type"] == "shm"


def test_semget(parser):
    line = 'semget(IPC_PRIVATE, 1, IPC_CREAT|0600) = 67890'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].details["ipc_type"] == "sem"


def test_msgget(parser):
    line = 'msgget(IPC_PRIVATE, IPC_CREAT|0600) = 11111'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].details["ipc_type"] == "mq"


def test_prctl_capability(parser):
    line = 'prctl(PR_CAPBSET_READ, CAP_NET_BIND_SERVICE) = 1'
    accesses = parser.parse_line(line)
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.CAPABILITY
    assert accesses[0].details["capability"] == "net_bind_service"


def test_signal_and_exit_lines_ignored(parser):
    assert parser.parse_line('--- SIGCHLD {si_signo=SIGCHLD} ---') == []
    assert parser.parse_line('+++ exited with 0 +++') == []
    assert parser.parse_line('') == []


def test_deduplication(parser, fixture_path):
    accesses = parser.parse_file(fixture_path)
    keys = [(a.access_type, a.path, a.syscall) for a in accesses]
    assert len(keys) == len(set(keys))


def test_real_ls_fixture(parser):
    path = Path(__file__).parent.parent / "fixtures" / "strace_ls_real.txt"
    if not path.exists():
        pytest.skip("Real strace fixture not available")
    accesses = parser.parse_file(path)
    assert len(accesses) > 0
    types = {a.access_type for a in accesses}
    assert AccessType.FILE_READ in types


def test_real_chronyd_fixture(parser):
    path = Path(__file__).parent.parent / "fixtures" / "strace_chronyd_real.txt"
    if not path.exists():
        pytest.skip("Real chronyd strace fixture not available")
    accesses = parser.parse_file(path)
    assert len(accesses) > 0
    syslog = [a for a in accesses if a.access_type == AccessType.SYSLOG]
    assert len(syslog) > 0
