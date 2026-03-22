"""Analyze Python source code for SELinux policy generation using AST parsing."""
import ast
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from sepgen.models.access import Access, AccessType


class PythonAnalyzer:
    """Static analyzer for Python source code using AST + regex."""

    SKIP_DIRS = {"test", "tests", "virt_tests", "container_tests", "__pycache__", ".git"}

    SUBPROCESS_FUNCS = {
        "run", "call", "check_call", "check_output", "Popen",
    }

    CAPABILITY_MAP = {
        "setuid": "setuid",
        "setgid": "setgid",
        "seteuid": "setuid",
        "setegid": "setgid",
        "setreuid": "setuid",
        "setregid": "setgid",
        "chroot": "sys_chroot",
        "kill": "kill",
        "nice": "sys_nice",
        "chown": "chown",
        "fchown": "chown",
        "lchown": "chown",
        "mlock": "ipc_lock",
    }

    SYSLOG_RE = re.compile(r'(?:import\s+syslog|SysLogHandler|from\s+syslog\s+import)')
    DBUS_RE = re.compile(r'(?:import\s+dbus|from\s+dbus\s+import|dbus\.SystemBus|dbus\.SessionBus|SystemMessageBus|from\s+dasbus)')
    PATH_LITERAL_RE = re.compile(r'"(/(?:etc|var|proc|sys|run|dev|boot)/[^"]+)"')

    def analyze_file(self, file_path: Path) -> List[Access]:
        try:
            code = file_path.read_text(errors='ignore')
        except (OSError, UnicodeDecodeError):
            return []

        accesses = []
        accesses.extend(self._analyze_ast(code, str(file_path)))
        accesses.extend(self._analyze_regex(code, str(file_path)))
        return accesses

    def analyze_directory(self, dir_path: Path) -> List[Access]:
        accesses = []
        for py_file in sorted(dir_path.rglob("*.py")):
            if any(skip in py_file.parts for skip in self.SKIP_DIRS):
                continue
            accesses.extend(self.analyze_file(py_file))
        return self._deduplicate(accesses)

    def _analyze_ast(self, code: str, source: str) -> List[Access]:
        try:
            tree = ast.parse(code, filename=source)
        except SyntaxError:
            return []

        accesses = []
        constants = self._extract_constants(tree)
        visitor = _PolicyVisitor(accesses, constants, source, self)
        visitor.visit(tree)
        return accesses

    def _analyze_regex(self, code: str, source: str) -> List[Access]:
        accesses = []

        if self.SYSLOG_RE.search(code):
            accesses.append(Access(
                access_type=AccessType.SYSLOG, path="/dev/log",
                syscall="syslog", details={}, source_file=source,
            ))

        if self.DBUS_RE.search(code):
            accesses.append(Access(
                access_type=AccessType.CAPABILITY, path="",
                syscall="dbus_header", details={"capability": "dbus_client"},
                source_file=source,
            ))

        seen_paths = set()
        for match in self.PATH_LITERAL_RE.finditer(code):
            path = match.group(1)
            if path not in seen_paths:
                seen_paths.add(path)
                access_type = AccessType.FILE_READ
                if path.startswith(("/var/run/", "/run/", "/var/log/")):
                    access_type = AccessType.FILE_WRITE
                accesses.append(Access(
                    access_type=access_type, path=path,
                    syscall="path_literal", details={},
                    source_file=source,
                ))

        return accesses

    def _extract_constants(self, tree: ast.AST) -> Dict[str, str]:
        constants = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                    if isinstance(node.value.value, str):
                        constants[target.id] = node.value.value
        return constants

    def _deduplicate(self, accesses: List[Access]) -> List[Access]:
        seen = set()
        result = []
        for a in accesses:
            key = (a.access_type, a.path, a.syscall)
            if key in seen:
                continue
            seen.add(key)
            result.append(a)
        return result


class _PolicyVisitor(ast.NodeVisitor):
    """AST visitor that extracts policy-relevant patterns."""

    def __init__(self, accesses: List[Access], constants: Dict[str, str],
                 source: str, analyzer: PythonAnalyzer):
        self.accesses = accesses
        self.constants = constants
        self.source = source
        self.analyzer = analyzer

    def visit_Call(self, node: ast.Call) -> None:
        self._check_subprocess(node)
        self._check_open(node)
        self._check_os_open(node)
        self._check_os_capability(node)
        self._check_path_methods(node)
        self.generic_visit(node)

    def _check_subprocess(self, node: ast.Call) -> None:
        func_name = self._get_call_name(node)
        if not func_name:
            return

        parts = func_name.split(".")
        if len(parts) == 2 and parts[0] == "subprocess" and parts[1] in PythonAnalyzer.SUBPROCESS_FUNCS:
            cmd = self._extract_first_arg_str(node)
            if cmd:
                self.accesses.append(Access(
                    access_type=AccessType.PROCESS_EXEC, path=cmd,
                    syscall="subprocess", details={"command": cmd},
                    source_file=self.source, source_line=node.lineno,
                ))

    def _check_open(self, node: ast.Call) -> None:
        func_name = self._get_call_name(node)
        if func_name != "open":
            return

        path = self._resolve_arg(node.args[0]) if node.args else None
        if not path or not path.startswith("/"):
            return

        mode = "r"
        if len(node.args) > 1:
            m = self._resolve_arg(node.args[1])
            if m:
                mode = m
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = str(kw.value.value)

        if "w" in mode or "a" in mode:
            access_type = AccessType.FILE_WRITE
        else:
            access_type = AccessType.FILE_READ

        self.accesses.append(Access(
            access_type=access_type, path=path, syscall="open",
            details={"mode": mode}, source_file=self.source,
            source_line=node.lineno,
        ))

    def _check_os_open(self, node: ast.Call) -> None:
        func_name = self._get_call_name(node)
        if func_name != "os.open":
            return

        path = self._resolve_arg(node.args[0]) if node.args else None
        if not path or not path.startswith("/"):
            return

        flags_str = ""
        if len(node.args) > 1:
            flags_str = ast.dump(node.args[1])

        if "O_WRONLY" in flags_str or "O_RDWR" in flags_str:
            if "O_CREAT" in flags_str:
                access_type = AccessType.FILE_CREATE
            else:
                access_type = AccessType.FILE_WRITE
        else:
            access_type = AccessType.FILE_READ

        self.accesses.append(Access(
            access_type=access_type, path=path, syscall="os.open",
            details={}, source_file=self.source, source_line=node.lineno,
        ))

    def _check_os_capability(self, node: ast.Call) -> None:
        func_name = self._get_call_name(node)
        if not func_name:
            return

        parts = func_name.split(".")
        if len(parts) == 2 and parts[0] == "os":
            cap = PythonAnalyzer.CAPABILITY_MAP.get(parts[1])
            if cap:
                self.accesses.append(Access(
                    access_type=AccessType.CAPABILITY, path="",
                    syscall=parts[1], details={"capability": cap},
                    source_file=self.source, source_line=node.lineno,
                ))

    def _check_path_methods(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute):
            return
        method = node.func.attr
        if method not in ("read_text", "read_bytes", "write_text", "write_bytes"):
            return

        if isinstance(node.func.value, ast.Call):
            inner = node.func.value
            inner_name = self._get_call_name(inner)
            if inner_name == "Path" and inner.args:
                path = self._resolve_arg(inner.args[0])
                if path and path.startswith("/"):
                    if "write" in method:
                        access_type = AccessType.FILE_WRITE
                    else:
                        access_type = AccessType.FILE_READ
                    self.accesses.append(Access(
                        access_type=access_type, path=path,
                        syscall="pathlib", details={},
                        source_file=self.source, source_line=node.lineno,
                    ))

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            if isinstance(node.func.value, ast.Attribute):
                if isinstance(node.func.value.value, ast.Name):
                    return f"{node.func.value.value.id}.{node.func.value.attr}.{node.func.attr}"
        return None

    def _resolve_arg(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.constants.get(node.id)
        if isinstance(node, ast.List) and node.elts:
            return self._resolve_arg(node.elts[0])
        return None

    def _extract_first_arg_str(self, node: ast.Call) -> Optional[str]:
        if not node.args:
            return None
        first = node.args[0]
        if isinstance(first, ast.List) and first.elts:
            return self._resolve_arg(first.elts[0])
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
        if isinstance(first, ast.Name):
            return self.constants.get(first.id)
        return None
