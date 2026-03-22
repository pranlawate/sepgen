from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from sepgen.models.access import Access

class IntentType(Enum):
    """Classified intent categories"""
    CONFIG_FILE = "config_file"
    PID_FILE = "pid_file"
    DATA_DIR = "data_dir"
    LOG_FILE = "log_file"
    TEMP_FILE = "temp_file"
    NETWORK_SERVER = "network_server"
    UDP_NETWORK_SERVER = "udp_network_server"
    NETWORK_CLIENT = "network_client"
    SYSLOG = "syslog"
    UNIX_SOCKET_SERVER = "unix_socket_server"
    SELF_CAPABILITY = "self_capability"
    DAEMON_PROCESS = "daemon_process"
    EXEC_BINARY = "exec_binary"
    KERNEL_STATE = "kernel_state"
    SYSFS_READ = "sysfs_read"
    SELINUX_API = "selinux_api"
    NETLINK_SOCKET = "netlink_socket"
    DEV_RANDOM = "dev_random"
    SHM_ACCESS = "shm_access"
    SEM_ACCESS = "sem_access"
    MSGQ_ACCESS = "msgq_access"
    NSSWITCH = "nsswitch"
    TERMINAL_IO = "terminal_io"
    SHARED_LIBRARY = "shared_library"
    UNKNOWN = "unknown"

@dataclass
class Intent:
    """Classified security intent with associated accesses"""
    intent_type: IntentType
    accesses: List['Access']
    confidence: float = 1.0
    selinux_type: Optional[str] = None
    macros: List[str] = field(default_factory=list)
