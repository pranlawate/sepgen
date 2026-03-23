import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class BuildInfo:
    """Information extracted from Makefiles."""
    prog_name: Optional[str] = None
    sbin_dir: str = "/usr/sbin"
    bin_dir: str = "/usr/bin"
    prefix: str = "/usr"
    init_script: Optional[str] = None
    uses_sbin: bool = False

    @property
    def exec_path(self) -> Optional[str]:
        if not self.prog_name:
            return None
        if self.uses_sbin:
            return f"{self.sbin_dir}/{self.prog_name}"
        return f"{self.bin_dir}/{self.prog_name}"


class MakefileParser:
    """Parses Makefiles for install targets and binary paths."""

    VAR_PATTERN = re.compile(
        r'^(\w+)[ \t]*(?:\?=|:=|=)[ \t]*([^\n]+)$', re.MULTILINE
    )
    INSTALL_PROG_PATTERN = re.compile(
        r'install\s+.*\$\(PROG\)\s+\$\(DESTDIR\)\$\((\w+)\)'
    )
    CP_PROG_PATTERN = re.compile(
        r'cp\s+(\S+)\s+\$\(DESTDIR\)\$\(PREFIX\)/(\w+)/(\S+)'
    )
    INSTALL_CMD_PATTERN = re.compile(
        r'\$\(INSTALL\)\s+-m\s+\d+\s+(\w[\w.-]*)\s+(/\S+/s?bin/\S+)'
    )
    ALL_TARGET_PATTERN = re.compile(
        r'^all:\s*(\w[\w.-]*)', re.MULTILINE
    )

    def parse(self, project_dir: Path) -> BuildInfo:
        """Find and parse Makefile in project tree."""
        info = BuildInfo()

        makefile = project_dir / "Makefile"
        if makefile.is_file():
            self._parse_file(makefile, info)
            if info.prog_name:
                return info

        if not info.prog_name:
            for makefile in sorted(project_dir.rglob("Makefile")):
                self._parse_file(makefile, info)
                if info.prog_name:
                    return info

        if not info.prog_name:
            parent = project_dir.parent
            if parent != project_dir:
                parent_makefile = parent / "Makefile"
                if parent_makefile.is_file():
                    self._parse_file(parent_makefile, info)

        return info

    def _parse_file(self, makefile: Path, info: BuildInfo) -> None:
        content = makefile.read_text()

        variables = {}
        for match in self.VAR_PATTERN.finditer(content):
            variables[match.group(1)] = match.group(2).strip()

        if "PROG" in variables:
            info.prog_name = variables["PROG"]
        if "PREFIX" in variables:
            info.prefix = variables["PREFIX"]
        if "SBINDIR" in variables:
            info.sbin_dir = self._resolve_var(variables["SBINDIR"], variables)
            info.uses_sbin = True
        if "BINDIR" in variables:
            info.bin_dir = self._resolve_var(variables["BINDIR"], variables)
        if "INITSCRIPT" in variables:
            info.init_script = variables["INITSCRIPT"]

        for match in self.INSTALL_PROG_PATTERN.finditer(content):
            target_var = match.group(1)
            if "SBIN" in target_var:
                info.uses_sbin = True

        for match in self.CP_PROG_PATTERN.finditer(content):
            subdir = match.group(2)
            prog = match.group(3)
            if not info.prog_name:
                info.prog_name = prog
            if subdir == "sbin":
                info.uses_sbin = True
                info.sbin_dir = f"{info.prefix}/sbin"
            elif subdir == "bin":
                info.bin_dir = f"{info.prefix}/bin"

        if not info.prog_name:
            for match in self.INSTALL_CMD_PATTERN.finditer(content):
                binary = match.group(1)
                dest = match.group(2)
                info.prog_name = binary
                if "/sbin/" in dest:
                    info.uses_sbin = True
                break

        if not info.prog_name:
            match = self.ALL_TARGET_PATTERN.search(content)
            if match:
                candidate = match.group(1)
                if not candidate.startswith('.') and candidate not in ('all', 'clean', 'install', 'test'):
                    info.prog_name = candidate

    def _resolve_var(self, value: str, variables: dict) -> str:
        """Resolve simple $(VAR) references."""
        def replacer(m):
            var_name = m.group(1)
            return variables.get(var_name, m.group(0))
        return re.sub(r'\$\((\w+)\)', replacer, value)
