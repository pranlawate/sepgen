from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional

class AccessType(Enum):
    """Types of system accesses"""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_CREATE = "file_create"
    FILE_UNLINK = "file_unlink"
    DIR_READ = "dir_read"
    DIR_WRITE = "dir_write"
    SOCKET_CREATE = "socket_create"
    SOCKET_BIND = "socket_bind"
    SOCKET_LISTEN = "socket_listen"
    SOCKET_CONNECT = "socket_connect"
    SOCKET_ACCEPT = "socket_accept"
    IPC_SYSV = "ipc_sysv"
    IPC_POSIX = "ipc_posix"

@dataclass
class Access:
    """Represents a single system access"""
    access_type: AccessType
    path: str
    syscall: str
    details: Dict[str, Any] = field(default_factory=dict)
    source_file: Optional[str] = None
    source_line: Optional[int] = None
