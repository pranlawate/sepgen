"""Maps C library function calls to SELinux access requirements.

Inspired by sepolicy generate's nm-based symbol analysis, but works
statically on source code rather than compiled binaries.
"""
import re
from pathlib import Path
from typing import Dict, List, Tuple

from sepgen.models.access import Access, AccessType

SYMBOL_MAP: Dict[str, Tuple[AccessType, Dict]] = {
    # Shared memory
    "shm_open": (AccessType.IPC_POSIX, {"ipc_type": "shm"}),
    "shmget": (AccessType.IPC_SYSV, {"ipc_type": "shm"}),
    "shmat": (AccessType.IPC_SYSV, {"ipc_type": "shm"}),
    # Message queues
    "mq_open": (AccessType.IPC_POSIX, {"ipc_type": "mq"}),
    "msgget": (AccessType.IPC_SYSV, {"ipc_type": "mq"}),
    # Semaphores
    "sem_open": (AccessType.IPC_POSIX, {"ipc_type": "sem"}),
    "semget": (AccessType.IPC_SYSV, {"ipc_type": "sem"}),
    # Capabilities
    "chroot": (AccessType.CAPABILITY, {"capability": "sys_chroot"}),
    "chown": (AccessType.CAPABILITY, {"capability": "chown"}),
    "setuid": (AccessType.CAPABILITY, {"capability": "setuid"}),
    "setgid": (AccessType.CAPABILITY, {"capability": "setgid"}),
    "setgroups": (AccessType.CAPABILITY, {"capability": "setgid"}),
    "setreuid": (AccessType.CAPABILITY, {"capability": "setuid"}),
    "setregid": (AccessType.CAPABILITY, {"capability": "setgid"}),
    "setpcap": (AccessType.CAPABILITY, {"capability": "setpcap"}),
    "seteuid": (AccessType.CAPABILITY, {"capability": "setuid"}),
    "setegid": (AccessType.CAPABILITY, {"capability": "setgid"}),
    "nice": (AccessType.CAPABILITY, {"capability": "sys_nice"}),
    "sched_setscheduler": (AccessType.CAPABILITY, {"capability": "sys_nice"}),
    "mount": (AccessType.CAPABILITY, {"capability": "sys_admin"}),
    "umount": (AccessType.CAPABILITY, {"capability": "sys_admin"}),
    "umount2": (AccessType.CAPABILITY, {"capability": "sys_admin"}),
    "reboot": (AccessType.CAPABILITY, {"capability": "sys_boot"}),
    "klogctl": (AccessType.CAPABILITY, {"capability": "sys_admin"}),
    "mlock": (AccessType.CAPABILITY, {"capability": "ipc_lock"}),
    "mlockall": (AccessType.CAPABILITY, {"capability": "ipc_lock"}),
    # Terminal / TTY
    "grantpt": (AccessType.CAPABILITY, {"capability": "sys_tty_config"}),
    "ptsname": (AccessType.CAPABILITY, {"capability": "sys_tty_config"}),
    "unlockpt": (AccessType.CAPABILITY, {"capability": "sys_tty_config"}),
    # Network raw
    "raw": (AccessType.CAPABILITY, {"capability": "net_raw"}),
    "rawsocket": (AccessType.CAPABILITY, {"capability": "net_raw"}),
    # Signal
    "kill": (AccessType.CAPABILITY, {"capability": "kill"}),
    # NSS resolution
    "getpwnam": (AccessType.CAPABILITY, {"capability": "nsswitch"}),
    "getpwuid": (AccessType.CAPABILITY, {"capability": "nsswitch"}),
    "getpwnam_r": (AccessType.CAPABILITY, {"capability": "nsswitch"}),
    "getgrnam": (AccessType.CAPABILITY, {"capability": "nsswitch"}),
    "getgrgid": (AccessType.CAPABILITY, {"capability": "nsswitch"}),
    "getgrnam_r": (AccessType.CAPABILITY, {"capability": "nsswitch"}),
    "gethostbyname": (AccessType.CAPABILITY, {"capability": "nsswitch"}),
    "gethostbyname2": (AccessType.CAPABILITY, {"capability": "nsswitch"}),
    "getaddrinfo": (AccessType.CAPABILITY, {"capability": "nsswitch"}),
    # Process execution
    "execl": (AccessType.PROCESS_EXEC, {}),
    "execlp": (AccessType.PROCESS_EXEC, {}),
    "execle": (AccessType.PROCESS_EXEC, {}),
    "execv": (AccessType.PROCESS_EXEC, {}),
    "execvp": (AccessType.PROCESS_EXEC, {}),
    "execve": (AccessType.PROCESS_EXEC, {}),
    "execvpe": (AccessType.PROCESS_EXEC, {}),
    "system": (AccessType.PROCESS_EXEC, {}),
    "popen": (AccessType.PROCESS_EXEC, {}),
    # SELinux API
    "getcon": (AccessType.SELINUX_API, {"api": "getcon"}),
    "getcon_raw": (AccessType.SELINUX_API, {"api": "getcon"}),
    "setcon": (AccessType.SELINUX_API, {"api": "setcon"}),
    "getpidcon": (AccessType.SELINUX_API, {"api": "getpidcon"}),
    "security_compute_av": (AccessType.SELINUX_API, {"api": "compute_av"}),
    "security_compute_av_flags": (AccessType.SELINUX_API, {"api": "compute_av"}),
    "avc_has_perm": (AccessType.SELINUX_API, {"api": "avc"}),
    "selabel_open": (AccessType.SELINUX_API, {"api": "selabel"}),
    "selinux_check_access": (AccessType.SELINUX_API, {"api": "check_access"}),
    # D-Bus API
    "dbus_bus_get": (AccessType.CAPABILITY, {"capability": "dbus_client"}),
    "dbus_bus_get_private": (AccessType.CAPABILITY, {"capability": "dbus_client"}),
    "dbus_connection_open": (AccessType.CAPABILITY, {"capability": "dbus_client"}),
    "sd_bus_open_system": (AccessType.CAPABILITY, {"capability": "dbus_client"}),
    "sd_bus_open_user": (AccessType.CAPABILITY, {"capability": "dbus_client"}),
    "sd_bus_open": (AccessType.CAPABILITY, {"capability": "dbus_client"}),
    "sd_bus_default_system": (AccessType.CAPABILITY, {"capability": "dbus_client"}),
    # Audit API
    "audit_open": (AccessType.CAPABILITY, {"capability": "audit_write"}),
    "audit_log_user_message": (AccessType.CAPABILITY, {"capability": "audit_write"}),
    "audit_log_user_avc_message": (AccessType.CAPABILITY, {"capability": "audit_write"}),
}

_FUNC_PATTERN = re.compile(
    r'\b(' + '|'.join(re.escape(s) for s in SYMBOL_MAP) + r')\s*\('
)


_SELINUX_INCLUDE = re.compile(r'#include\s+<selinux/selinux\.h>')
_NETLINK_INCLUDE = re.compile(r'#include\s+<linux/netlink\.h>')
_DBUS_INCLUDE = re.compile(r'#include\s+<dbus/dbus\.h>|#include\s+<systemd/sd-bus\.h>')
_AUDIT_INCLUDE = re.compile(r'#include\s+<libaudit\.h>')


class SymbolScanner:
    """Scans source for C library calls and maps to Access objects."""

    def scan_string(self, code: str) -> List[Access]:
        accesses = []
        seen = set()
        for match in _FUNC_PATTERN.finditer(code):
            func = match.group(1)
            if func in seen:
                continue
            seen.add(func)
            access_type, details = SYMBOL_MAP[func]
            accesses.append(Access(
                access_type=access_type,
                path="",
                syscall=func,
                details=dict(details),
                source_line=code[:match.start()].count('\n') + 1,
            ))

        has_dbus = any(a.details.get("capability") == "dbus_client" for a in accesses)
        if not has_dbus and _DBUS_INCLUDE.search(code):
            accesses.append(Access(
                access_type=AccessType.CAPABILITY, path="", syscall="dbus_header",
                details={"capability": "dbus_client"},
            ))

        has_audit = any(a.details.get("capability") == "audit_write" for a in accesses)
        if not has_audit and _AUDIT_INCLUDE.search(code):
            accesses.append(Access(
                access_type=AccessType.CAPABILITY, path="", syscall="audit_header",
                details={"capability": "audit_write"},
            ))

        return accesses

    def scan_file(self, file_path: Path) -> List[Access]:
        code = file_path.read_text()
        accesses = self.scan_string(code)
        for a in accesses:
            a.source_file = str(file_path)
        return accesses

    C_EXTENSIONS = ("*.c", "*.cc", "*.cpp", "*.cxx")

    def scan_directory(self, dir_path: Path) -> List[Access]:
        accesses = []
        for ext in self.C_EXTENSIONS:
            for c_file in sorted(dir_path.rglob(ext)):
                accesses.extend(self.scan_file(c_file))
        return self._deduplicate(accesses)

    def _deduplicate(self, accesses: List[Access]) -> List[Access]:
        seen = set()
        result = []
        for a in accesses:
            key = (a.access_type, a.syscall, tuple(sorted(a.details.items())))
            if key in seen:
                continue
            seen.add(key)
            result.append(a)
        return result
