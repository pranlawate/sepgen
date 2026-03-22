import re
from pathlib import Path
from typing import List
from sepgen.analyzer.base import BaseAnalyzer
from sepgen.analyzer.syscall_mapper import SyscallMapper
from sepgen.analyzer.preprocessor import Preprocessor
from sepgen.analyzer.dataflow import DataFlowAnalyzer
from sepgen.models.access import Access, AccessType

class CAnalyzer(BaseAnalyzer):
    """Static analyzer for C/C++ code using regex patterns"""

    SYSLOG_PATTERN = re.compile(r'\b(syslog|openlog|vsyslog)\s*\(')
    LISTEN_PATTERN = re.compile(r'\blisten\s*\(')
    ACCEPT_PATTERN = re.compile(r'\baccept\s*\(')
    SOCKET_PATTERN = re.compile(
        r'\bsocket\s*\(\s*(PF_UNIX|PF_INET|AF_UNIX|AF_INET|PF_INET6|AF_INET6|AF_NETLINK|PF_NETLINK)'
        r'\s*,\s*(SOCK_STREAM|SOCK_DGRAM|SOCK_RAW|SOCK_SEQPACKET)'
    )
    SOCKET_PATTERN_SIMPLE = re.compile(
        r'\bsocket\s*\(\s*(PF_UNIX|PF_INET|AF_UNIX|AF_INET|PF_INET6|AF_INET6|AF_NETLINK|PF_NETLINK)'
    )
    WRAPPER_SOCKET_PATTERN = re.compile(
        r'\w+\s*\([^)]*\b(AF_UNIX|PF_UNIX|AF_INET|PF_INET|AF_INET6|PF_INET6|AF_NETLINK|PF_NETLINK)\b'
        r'[^)]*\b(SOCK_STREAM|SOCK_DGRAM|SOCK_RAW|SOCK_SEQPACKET)\b'
    )
    BIND_PATTERN = re.compile(r'\bbind\s*\(')
    SETRLIMIT_PATTERN = re.compile(r'\bsetrlimit\s*\(')
    CAP_PATTERN = re.compile(r'\b(cap_init|cap_set_proc|cap_get_proc|cap_set_flag)\s*\(')
    CAP_MACRO_PATTERN = re.compile(
        r'\bCAP_(SYS_TIME|SYS_NICE|SYS_ADMIN|SYS_RESOURCE|SYS_CHROOT|SYS_BOOT|'
        r'SYS_PTRACE|SYS_RAWIO|SYS_MODULE|SYS_PACCT|SYS_TTY_CONFIG|'
        r'NET_ADMIN|NET_BIND_SERVICE|NET_RAW|NET_BROADCAST|'
        r'KILL|DAC_READ_SEARCH|DAC_OVERRIDE|FSETID|FOWNER|CHOWN|'
        r'IPC_LOCK|IPC_OWNER|SETUID|SETGID|SETPCAP|SETFCAP|MKNOD|'
        r'AUDIT_WRITE|AUDIT_CONTROL|SYSLOG|'
        r'LINUX_IMMUTABLE|LEASE|MAC_ADMIN|MAC_OVERRIDE|'
        r'BLOCK_SUSPEND|WAKE_ALARM)\b'
    )
    CAP_TEXT_PATTERN = re.compile(r'"cap_([a-z_]+)=e?p?"')
    DAEMON_PATTERN = re.compile(r'\bdaemon\s*\(')
    DEV_PATH_PATTERN = re.compile(r'"(/dev/(?:u?random|urandom))"')
    UNLINK_PATTERN = re.compile(r'\bunlink\s*\(\s*"([^"]+)"\s*\)')
    CHMOD_PATTERN = re.compile(r'\bchmod\s*\(\s*"([^"]+)"')
    OPEN_PATTERN = re.compile(r'\bopen\s*\(\s*"([^"]+)"\s*,\s*([^)]+)\)')

    def __init__(self):
        self.mapper = SyscallMapper()
        self.preprocessor = Preprocessor()
        self.dataflow = DataFlowAnalyzer()

    def analyze_file(self, file_path: Path) -> List[Access]:
        """Analyze a C source file"""
        code = file_path.read_text()
        accesses = self.analyze_string(code)
        for access in accesses:
            access.source_file = str(file_path)
        return accesses

    C_EXTENSIONS = ("*.c", "*.cc", "*.cpp", "*.cxx")

    def analyze_directory(self, dir_path: Path) -> List[Access]:
        """Analyze all C/C++ files in a directory recursively."""
        accesses = []
        for ext in self.C_EXTENSIONS:
            for c_file in sorted(dir_path.rglob(ext)):
                accesses.extend(self.analyze_file(c_file))
        accesses = self._deduplicate_cross_file(accesses)
        return accesses

    def _deduplicate_cross_file(self, accesses: List[Access]) -> List[Access]:
        """Remove duplicate SYSLOG accesses across files (same function → one access)."""
        seen_syslog_funcs = set()
        result = []
        for access in accesses:
            if access.access_type == AccessType.SYSLOG:
                func = access.details.get("function")
                if func in seen_syslog_funcs:
                    continue
                seen_syslog_funcs.add(func)
            result.append(access)
        return result

    def analyze_string(self, code: str) -> List[Access]:
        """Analyze C code string using regex patterns"""
        defines = self.preprocessor.extract_defines(code)
        code = self.preprocessor.expand_macros(code, defines)

        self.dataflow.extract_string_assignments(code)
        code = self.dataflow.resolve_variables(code)

        accesses = []

        # Pattern: fopen("path", "mode")
        fopen_pattern = re.compile(r'fopen\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)')
        for match in fopen_pattern.finditer(code):
            path = match.group(1)
            mode = match.group(2)
            access = self.mapper.map_function_call('fopen', [f'"{path}"', f'"{mode}"'])
            if access:
                accesses.append(access)

        accesses.extend(self._detect_socket(code))
        accesses.extend(self._detect_bind(code))

        accesses.extend(self._detect_syslog(code))
        accesses.extend(self._detect_listen(code))
        accesses.extend(self._detect_accept(code))
        accesses.extend(self._detect_unlink(code))
        accesses.extend(self._detect_chmod(code))
        accesses.extend(self._detect_open(code))
        accesses.extend(self._detect_setrlimit(code))
        accesses.extend(self._detect_capabilities(code))
        accesses.extend(self._detect_daemon(code))
        accesses.extend(self._detect_signal_include(code))
        accesses.extend(self._detect_dev_paths(code))

        self._infer_bind_paths(accesses)

        return accesses

    def _detect_socket(self, code: str) -> List[Access]:
        accesses = []
        self._last_socket_domain = None
        self._last_socket_type = None

        for match in self.SOCKET_PATTERN.finditer(code):
            domain = match.group(1)
            sock_type = match.group(2)
            self._last_socket_domain = domain
            self._last_socket_type = sock_type

            if domain in ("AF_NETLINK", "PF_NETLINK"):
                accesses.append(Access(
                    access_type=AccessType.NETLINK_SOCKET,
                    path="",
                    syscall="socket",
                    details={"domain": domain, "sock_type": sock_type},
                    source_line=code[:match.start()].count('\n') + 1,
                ))
            else:
                accesses.append(Access(
                    access_type=AccessType.SOCKET_CREATE,
                    path=f"{domain}:{sock_type}",
                    syscall="socket",
                    details={"domain": domain, "sock_type": sock_type},
                    source_line=code[:match.start()].count('\n') + 1,
                ))

        if not accesses:
            for match in self.SOCKET_PATTERN_SIMPLE.finditer(code):
                domain = match.group(1)
                self._last_socket_domain = domain
                if domain in ("AF_NETLINK", "PF_NETLINK"):
                    accesses.append(Access(
                        access_type=AccessType.NETLINK_SOCKET,
                        path="",
                        syscall="socket",
                        details={"domain": domain},
                        source_line=code[:match.start()].count('\n') + 1,
                    ))
                else:
                    accesses.append(Access(
                        access_type=AccessType.SOCKET_CREATE,
                        path=f"{domain}",
                        syscall="socket",
                        details={"domain": domain},
                        source_line=code[:match.start()].count('\n') + 1,
                    ))

        if not accesses:
            for match in self.WRAPPER_SOCKET_PATTERN.finditer(code):
                domain = match.group(1)
                sock_type = match.group(2)
                self._last_socket_domain = domain
                self._last_socket_type = sock_type
                if domain in ("AF_NETLINK", "PF_NETLINK"):
                    accesses.append(Access(
                        access_type=AccessType.NETLINK_SOCKET,
                        path="",
                        syscall="socket_wrapper",
                        details={"domain": domain, "sock_type": sock_type},
                        source_line=code[:match.start()].count('\n') + 1,
                    ))
                else:
                    accesses.append(Access(
                        access_type=AccessType.SOCKET_CREATE,
                        path=f"{domain}:{sock_type}",
                        syscall="socket_wrapper",
                        details={"domain": domain, "sock_type": sock_type},
                        source_line=code[:match.start()].count('\n') + 1,
                    ))

        return accesses

    def _detect_bind(self, code: str) -> List[Access]:
        accesses = []
        for match in self.BIND_PATTERN.finditer(code):
            domain = getattr(self, '_last_socket_domain', None)
            sock_type = getattr(self, '_last_socket_type', None)
            details = {"domain": domain}
            if sock_type:
                details["sock_type"] = sock_type
            accesses.append(Access(
                access_type=AccessType.SOCKET_BIND,
                path="",
                syscall="bind",
                details=details,
                source_line=code[:match.start()].count('\n') + 1
            ))
        return accesses

    def _detect_listen(self, code: str) -> List[Access]:
        accesses = []
        for match in self.LISTEN_PATTERN.finditer(code):
            accesses.append(Access(
                access_type=AccessType.SOCKET_LISTEN,
                path="",
                syscall="listen",
                details={},
                source_line=code[:match.start()].count('\n') + 1
            ))
        return accesses

    def _detect_accept(self, code: str) -> List[Access]:
        accesses = []
        for match in self.ACCEPT_PATTERN.finditer(code):
            accesses.append(Access(
                access_type=AccessType.SOCKET_ACCEPT,
                path="",
                syscall="accept",
                details={},
                source_line=code[:match.start()].count('\n') + 1
            ))
        return accesses

    def _detect_unlink(self, code: str) -> List[Access]:
        accesses = []
        for match in self.UNLINK_PATTERN.finditer(code):
            accesses.append(Access(
                access_type=AccessType.FILE_UNLINK,
                path=match.group(1),
                syscall="unlink",
                details={},
                source_line=code[:match.start()].count('\n') + 1
            ))
        return accesses

    def _detect_chmod(self, code: str) -> List[Access]:
        accesses = []
        for match in self.CHMOD_PATTERN.finditer(code):
            accesses.append(Access(
                access_type=AccessType.FILE_SETATTR,
                path=match.group(1),
                syscall="chmod",
                details={},
                source_line=code[:match.start()].count('\n') + 1
            ))
        return accesses

    def _detect_open(self, code: str) -> List[Access]:
        """Detect C-level open() calls, mapping flags to access types."""
        accesses = []
        for match in self.OPEN_PATTERN.finditer(code):
            path = match.group(1)
            flags = match.group(2)
            if "O_WRONLY" in flags or "O_RDWR" in flags:
                access_type = AccessType.FILE_WRITE
            elif "O_CREAT" in flags:
                access_type = AccessType.FILE_CREATE
            else:
                access_type = AccessType.FILE_READ
            accesses.append(Access(
                access_type=access_type,
                path=path,
                syscall="open",
                details={"flags": flags.strip()},
                source_line=code[:match.start()].count('\n') + 1
            ))
        return accesses

    def _detect_daemon(self, code: str) -> List[Access]:
        accesses = []
        for match in self.DAEMON_PATTERN.finditer(code):
            accesses.append(Access(
                access_type=AccessType.DAEMON,
                path="",
                syscall="daemon",
                details={},
                source_line=code[:match.start()].count('\n') + 1
            ))
        return accesses

    def _detect_setrlimit(self, code: str) -> List[Access]:
        accesses = []
        for match in self.SETRLIMIT_PATTERN.finditer(code):
            accesses.append(Access(
                access_type=AccessType.PROCESS_CONTROL,
                path="",
                syscall="setrlimit",
                details={"capability": "sys_resource"},
                source_line=code[:match.start()].count('\n') + 1
            ))
        return accesses

    def _detect_capabilities(self, code: str) -> List[Access]:
        accesses = []
        seen_caps = set()
        for match in self.CAP_PATTERN.finditer(code):
            accesses.append(Access(
                access_type=AccessType.CAPABILITY,
                path="",
                syscall=match.group(1),
                details={},
                source_line=code[:match.start()].count('\n') + 1
            ))

        for match in self.CAP_MACRO_PATTERN.finditer(code):
            cap_name = match.group(1).lower()
            if cap_name not in seen_caps:
                seen_caps.add(cap_name)
                accesses.append(Access(
                    access_type=AccessType.CAPABILITY,
                    path="",
                    syscall="CAP_" + match.group(1),
                    details={"capability": cap_name},
                    source_line=code[:match.start()].count('\n') + 1
                ))

        for match in self.CAP_TEXT_PATTERN.finditer(code):
            cap_name = match.group(1)
            if cap_name not in seen_caps:
                seen_caps.add(cap_name)
                accesses.append(Access(
                    access_type=AccessType.CAPABILITY,
                    path="",
                    syscall="cap_from_text",
                    details={"capability": cap_name},
                    source_line=code[:match.start()].count('\n') + 1
                ))

        return accesses

    def _detect_dev_paths(self, code: str) -> List[Access]:
        accesses = []
        seen = set()
        for match in self.DEV_PATH_PATTERN.finditer(code):
            path = match.group(1)
            if path not in seen:
                seen.add(path)
                accesses.append(Access(
                    access_type=AccessType.FILE_READ,
                    path=path,
                    syscall="dev_access",
                    details={},
                    source_line=code[:match.start()].count('\n') + 1
                ))
        return accesses

    SIGNAL_INCLUDE_PATTERN = re.compile(r'#include\s+<signal\.h>')

    def _infer_bind_paths(self, accesses: List[Access]) -> None:
        """Copy /var/run/ unlink paths to empty-path PF_UNIX bind accesses."""
        unlink_paths = [
            a.path for a in accesses
            if a.access_type == AccessType.FILE_UNLINK
            and (a.path.startswith("/var/run/") or a.path.startswith("/run/"))
        ]
        if not unlink_paths:
            return
        for access in accesses:
            if (access.access_type == AccessType.SOCKET_BIND
                    and access.details.get("domain") in ("PF_UNIX", "AF_UNIX")
                    and not access.path):
                access.path = unlink_paths[0]

    def _detect_signal_include(self, code: str) -> List[Access]:
        """Emit synthetic PROCESS_CONTROL access when signal.h is included."""
        accesses = []
        if self.SIGNAL_INCLUDE_PATTERN.search(code):
            accesses.append(Access(
                access_type=AccessType.PROCESS_CONTROL,
                path="",
                syscall="signal",
                details={"process_perm": "signal_perms"},
                source_line=0
            ))
        return accesses

    def _detect_syslog(self, code: str) -> List[Access]:
        """Detect syslog/openlog calls — deduplicated.

        Emits one Access per distinct function name since only one
        logging_send_syslog_msg() macro is needed regardless of call count.
        """
        seen_functions = set()
        accesses = []
        for match in self.SYSLOG_PATTERN.finditer(code):
            func = match.group(1)
            if func in seen_functions:
                continue
            seen_functions.add(func)
            accesses.append(Access(
                access_type=AccessType.SYSLOG,
                path="/dev/log",
                syscall="connect",
                details={"function": func},
                source_line=code[:match.start()].count('\n') + 1
            ))
        return accesses
