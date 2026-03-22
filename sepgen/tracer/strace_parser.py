"""Parse strace output into Access objects for policy generation."""
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from sepgen.models.access import Access, AccessType


class StraceParser:
    """Parse strace output with FD tracking and comprehensive syscall coverage."""

    PID_PREFIX = re.compile(r'^\d+\s+')

    OPENAT_PATTERN = re.compile(
        r'open(?:at)?\((?:AT_FDCWD,\s*)?"([^"]+)",\s*([^)]+)\)\s*=\s*(-?\d+)'
    )
    SOCKET_PATTERN = re.compile(
        r'socket\(([^,]+),\s*([^,|)]+)(?:\|[^,]*)?,\s*([^)]*)\)\s*=\s*(-?\d+)'
    )
    BIND_INET_PATTERN = re.compile(
        r'bind\((\d+),\s*\{sa_family=(AF_INET6?),\s*sin6?_port=htons\((\d+)\)'
    )
    BIND_UNIX_PATTERN = re.compile(
        r'bind\((\d+),\s*\{sa_family=AF_UNIX,\s*sun_path="([^"]+)"'
    )
    BIND_NETLINK_PATTERN = re.compile(
        r'bind\((\d+),\s*\{sa_family=AF_NETLINK'
    )
    CONNECT_PATTERN = re.compile(
        r'connect\((\d+),\s*\{sa_family=([^,]+)(?:.*?sun_path="([^"]+)")?'
    )
    LISTEN_PATTERN = re.compile(r'listen\((\d+),\s*(\d+)\)\s*=\s*0')
    EXECVE_PATTERN = re.compile(r'execve\("([^"]+)"')
    UNLINK_PATTERN = re.compile(r'unlink(?:at)?\((?:AT_FDCWD,\s*)?"([^"]+)"\)\s*=\s*0')
    CHMOD_PATTERN = re.compile(r'(?:f?chmod)(?:at)?\((?:\d+,\s*)?"?([^",]+)"?,\s*(\d+)\)\s*=\s*0')
    SETRLIMIT_PATTERN = re.compile(r'(?:p?setrlimit|prlimit64)\(')
    SHMGET_PATTERN = re.compile(r'shmget\(')
    SHMAT_PATTERN = re.compile(r'shmat\(')
    SEMGET_PATTERN = re.compile(r'semget\(')
    MSGGET_PATTERN = re.compile(r'msgget\(')
    SHM_OPEN_PATTERN = re.compile(r'shm_open\("([^"]+)"')
    PRCTL_PATTERN = re.compile(r'prctl\(PR_CAPBSET_READ,\s*CAP_(\w+)\)')
    CAPGET_PATTERN = re.compile(r'capget\(')

    def __init__(self):
        self._fd_map: Dict[int, Tuple[str, str]] = {}

    def parse_line(self, line: str) -> List[Access]:
        """Parse a single strace output line into Access objects."""
        line = self.PID_PREFIX.sub('', line).strip()
        if not line or line.startswith('---') or line.startswith('+++'):
            return []

        accesses = []

        self._parse_openat(line, accesses)
        self._parse_socket(line, accesses)
        self._parse_bind(line, accesses)
        self._parse_connect(line, accesses)
        self._parse_listen(line, accesses)
        self._parse_execve(line, accesses)
        self._parse_unlink(line, accesses)
        self._parse_chmod(line, accesses)
        self._parse_setrlimit(line, accesses)
        self._parse_ipc(line, accesses)
        self._parse_capability(line, accesses)

        return accesses

    def parse_file(self, path: Path) -> List[Access]:
        """Parse an entire strace output file with deduplication."""
        self._fd_map = {}
        accesses = []

        with open(path, 'r') as f:
            for line in f:
                accesses.extend(self.parse_line(line))

        return self._deduplicate(accesses)

    def _parse_openat(self, line: str, accesses: List[Access]) -> None:
        match = self.OPENAT_PATTERN.search(line)
        if not match:
            return
        path = match.group(1)
        flags = match.group(2)
        fd = int(match.group(3))
        if fd < 0:
            return

        if 'O_WRONLY' in flags or 'O_RDWR' in flags:
            access_type = AccessType.FILE_CREATE if 'O_CREAT' in flags else AccessType.FILE_WRITE
        else:
            access_type = AccessType.FILE_READ

        accesses.append(Access(
            access_type=access_type, path=path, syscall="open",
            details={"flags": flags},
        ))

    def _parse_socket(self, line: str, accesses: List[Access]) -> None:
        match = self.SOCKET_PATTERN.search(line)
        if not match:
            return
        domain = match.group(1).strip()
        sock_type = match.group(2).strip()
        protocol = match.group(3).strip()
        fd = int(match.group(4))
        if fd < 0:
            return

        self._fd_map[fd] = (domain, sock_type)

        if domain in ("AF_NETLINK", "PF_NETLINK"):
            accesses.append(Access(
                access_type=AccessType.NETLINK_SOCKET, path="", syscall="socket",
                details={"domain": domain, "sock_type": sock_type, "protocol": protocol},
            ))
        else:
            accesses.append(Access(
                access_type=AccessType.SOCKET_CREATE,
                path=f"{domain}:{sock_type}", syscall="socket",
                details={"domain": domain, "sock_type": sock_type},
            ))

    def _parse_bind(self, line: str, accesses: List[Access]) -> None:
        match = self.BIND_INET_PATTERN.search(line)
        if match:
            fd = int(match.group(1))
            family = match.group(2)
            port = int(match.group(3))
            domain, sock_type = self._fd_map.get(fd, (family, None))
            details = {"port": port, "domain": domain}
            if sock_type:
                details["sock_type"] = sock_type
            accesses.append(Access(
                access_type=AccessType.SOCKET_BIND, path=f"{domain}:{port}",
                syscall="bind", details=details,
            ))
            return

        match = self.BIND_UNIX_PATTERN.search(line)
        if match:
            fd = int(match.group(1))
            sun_path = match.group(2)
            _, sock_type = self._fd_map.get(fd, ("AF_UNIX", None))
            details = {"domain": "AF_UNIX"}
            if sock_type:
                details["sock_type"] = sock_type
            accesses.append(Access(
                access_type=AccessType.SOCKET_BIND, path=sun_path,
                syscall="bind", details=details,
            ))
            return

        match = self.BIND_NETLINK_PATTERN.search(line)
        if match:
            return

    def _parse_connect(self, line: str, accesses: List[Access]) -> None:
        match = self.CONNECT_PATTERN.search(line)
        if not match:
            return
        fd = int(match.group(1))
        family = match.group(2).strip()
        path = match.group(3)

        if path == "/dev/log":
            accesses.append(Access(
                access_type=AccessType.SYSLOG, path="/dev/log", syscall="connect",
                details={"family": family, "is_syslog": True},
            ))
        elif family == "AF_UNIX" and path:
            accesses.append(Access(
                access_type=AccessType.SOCKET_CONNECT, path=path,
                syscall="connect", details={"domain": "AF_UNIX"},
            ))

    def _parse_listen(self, line: str, accesses: List[Access]) -> None:
        match = self.LISTEN_PATTERN.search(line)
        if match:
            accesses.append(Access(
                access_type=AccessType.SOCKET_LISTEN, path="", syscall="listen",
                details={},
            ))

    def _parse_execve(self, line: str, accesses: List[Access]) -> None:
        match = self.EXECVE_PATTERN.search(line)
        if match:
            path = match.group(1)
            accesses.append(Access(
                access_type=AccessType.PROCESS_EXEC, path=path, syscall="execve",
                details={},
            ))

    def _parse_unlink(self, line: str, accesses: List[Access]) -> None:
        match = self.UNLINK_PATTERN.search(line)
        if match:
            accesses.append(Access(
                access_type=AccessType.FILE_UNLINK, path=match.group(1),
                syscall="unlink", details={},
            ))

    def _parse_chmod(self, line: str, accesses: List[Access]) -> None:
        match = self.CHMOD_PATTERN.search(line)
        if match:
            accesses.append(Access(
                access_type=AccessType.FILE_SETATTR, path=match.group(1),
                syscall="chmod", details={"mode": match.group(2)},
            ))

    def _parse_setrlimit(self, line: str, accesses: List[Access]) -> None:
        if self.SETRLIMIT_PATTERN.search(line):
            accesses.append(Access(
                access_type=AccessType.PROCESS_CONTROL, path="", syscall="setrlimit",
                details={"capability": "sys_resource"},
            ))

    def _parse_ipc(self, line: str, accesses: List[Access]) -> None:
        if self.SHMGET_PATTERN.search(line) or self.SHMAT_PATTERN.search(line):
            accesses.append(Access(
                access_type=AccessType.IPC_SYSV, path="", syscall="shmget",
                details={"ipc_type": "shm"},
            ))
        elif self.SHM_OPEN_PATTERN.search(line):
            accesses.append(Access(
                access_type=AccessType.IPC_POSIX, path="", syscall="shm_open",
                details={"ipc_type": "shm"},
            ))
        elif self.SEMGET_PATTERN.search(line):
            accesses.append(Access(
                access_type=AccessType.IPC_SYSV, path="", syscall="semget",
                details={"ipc_type": "sem"},
            ))
        elif self.MSGGET_PATTERN.search(line):
            accesses.append(Access(
                access_type=AccessType.IPC_SYSV, path="", syscall="msgget",
                details={"ipc_type": "mq"},
            ))

    def _parse_capability(self, line: str, accesses: List[Access]) -> None:
        match = self.PRCTL_PATTERN.search(line)
        if match:
            cap = match.group(1).lower()
            accesses.append(Access(
                access_type=AccessType.CAPABILITY, path="", syscall="prctl",
                details={"capability": cap},
            ))
        elif self.CAPGET_PATTERN.search(line):
            accesses.append(Access(
                access_type=AccessType.CAPABILITY, path="", syscall="capget",
                details={},
            ))

    def _deduplicate(self, accesses: List[Access]) -> List[Access]:
        """Remove duplicate accesses (same type + path + key details)."""
        seen = set()
        result = []
        for a in accesses:
            key = (a.access_type, a.path, a.syscall)
            if key in seen:
                continue
            seen.add(key)
            result.append(a)
        return result
