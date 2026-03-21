import re
from pathlib import Path
from typing import List
from sepgen.models.access import Access, AccessType


class StraceParser:
    """Parse strace output and extract system accesses"""

    OPEN_PATTERN = re.compile(
        r'open(?:at)?\("([^"]+)",\s*([^)]+)\)\s*=\s*(\d+|-1)'
    )
    SOCKET_PATTERN = re.compile(
        r'socket\(([^,]+),\s*([^,]+),\s*([^)]+)\)\s*=\s*(\d+)'
    )
    BIND_PATTERN = re.compile(
        r'bind\(\d+,\s*\{sa_family=([^,]+).*?sin_port=htons\((\d+)\)'
    )
    CONNECT_PATTERN = re.compile(
        r'connect\(\d+,\s*\{sa_family=([^,]+)(?:.*?sun_path="([^"]+)")?'
    )

    def parse_line(self, line: str) -> List[Access]:
        """Parse a single strace output line"""
        accesses = []

        match = self.OPEN_PATTERN.search(line)
        if match:
            path = match.group(1)
            flags = match.group(2)
            fd = match.group(3)

            if fd == '-1':
                return accesses

            if 'O_WRONLY' in flags or 'O_RDWR' in flags:
                if 'O_CREAT' in flags:
                    access_type = AccessType.FILE_CREATE
                else:
                    access_type = AccessType.FILE_WRITE
            else:
                access_type = AccessType.FILE_READ

            accesses.append(Access(
                access_type=access_type,
                path=path,
                syscall="open",
                details={"flags": flags}
            ))

        match = self.BIND_PATTERN.search(line)
        if match:
            family = match.group(1)
            port = int(match.group(2))

            accesses.append(Access(
                access_type=AccessType.SOCKET_BIND,
                path=f"tcp:{port}",
                syscall="bind",
                details={"port": port, "family": family, "protocol": "tcp"}
            ))

        match = self.SOCKET_PATTERN.search(line)
        if match:
            domain = match.group(1)
            sock_type = match.group(2)

            accesses.append(Access(
                access_type=AccessType.SOCKET_CREATE,
                path=f"{domain}:{sock_type}",
                syscall="socket",
                details={"domain": domain, "type": sock_type}
            ))

        match = self.CONNECT_PATTERN.search(line)
        if match:
            family = match.group(1)
            path = match.group(2)

            if path == "/dev/log":
                accesses.append(Access(
                    access_type=AccessType.SOCKET_CONNECT,
                    path="/dev/log",
                    syscall="connect",
                    details={"family": family, "is_syslog": True}
                ))

        return accesses

    def parse_file(self, path: Path) -> List[Access]:
        """Parse an entire strace output file"""
        accesses = []

        with open(path, 'r') as f:
            for line in f:
                accesses.extend(self.parse_line(line))

        return accesses
