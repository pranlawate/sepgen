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
    SOCKET_PATTERN = re.compile(r'\bsocket\s*\(\s*(PF_UNIX|PF_INET|AF_UNIX|AF_INET|PF_INET6|AF_INET6)')
    BIND_PATTERN = re.compile(r'\bbind\s*\(')
    SETRLIMIT_PATTERN = re.compile(r'\bsetrlimit\s*\(')
    CAP_PATTERN = re.compile(r'\b(cap_init|cap_set_proc|cap_get_proc|cap_set_flag)\s*\(')
    DAEMON_PATTERN = re.compile(r'\bdaemon\s*\(')
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

    def analyze_directory(self, dir_path: Path) -> List[Access]:
        """Analyze all .c files in a directory recursively."""
        accesses = []
        for c_file in sorted(dir_path.rglob("*.c")):
            accesses.extend(self.analyze_file(c_file))
        return accesses

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

        return accesses

    def _detect_socket(self, code: str) -> List[Access]:
        accesses = []
        self._last_socket_domain = None
        for match in self.SOCKET_PATTERN.finditer(code):
            domain = match.group(1)
            self._last_socket_domain = domain
            accesses.append(Access(
                access_type=AccessType.SOCKET_CREATE,
                path=f"{domain}:SOCK_STREAM",
                syscall="socket",
                details={"domain": domain},
                source_line=code[:match.start()].count('\n') + 1
            ))
        return accesses

    def _detect_bind(self, code: str) -> List[Access]:
        accesses = []
        for match in self.BIND_PATTERN.finditer(code):
            domain = getattr(self, '_last_socket_domain', None)
            accesses.append(Access(
                access_type=AccessType.SOCKET_BIND,
                path="",
                syscall="bind",
                details={"domain": domain},
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
        for match in self.CAP_PATTERN.finditer(code):
            accesses.append(Access(
                access_type=AccessType.CAPABILITY,
                path="",
                syscall=match.group(1),
                details={},
                source_line=code[:match.start()].count('\n') + 1
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
