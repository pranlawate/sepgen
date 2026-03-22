"""Parse CMakeLists.txt for executable names and install directories."""
import re
from pathlib import Path
from typing import Optional

from sepgen.analyzer.makefile_parser import BuildInfo


class CMakeParser:
    """Extracts binary names and install paths from CMake build files."""

    ADD_EXE_PATTERN = re.compile(r'add_executable\s*\(\s*(\w[\w-]*)')
    OUTPUT_NAME_PATTERN = re.compile(
        r'set_target_properties\s*\(\s*(\w[\w-]*)\s+PROPERTIES\s+OUTPUT_NAME\s+(\S+)'
    )
    INSTALL_TARGETS_PATTERN = re.compile(
        r'install\s*\(\s*TARGETS\s+(\w[\w-]*)\s+(?:RUNTIME\s+)?DESTINATION\s+\$\{([^}]+)\}'
    )
    INSTALL_TARGETS_SIMPLE = re.compile(
        r'install\s*\(\s*TARGETS\s+(\w[\w-]*)\s*\)'
    )

    def parse(self, project_dir: Path, module_name: str = "") -> BuildInfo:
        info = BuildInfo()
        all_installed = []
        all_executables = []

        search_dirs = [project_dir]
        parent = project_dir.parent
        if parent != project_dir:
            search_dirs.append(parent)

        for search_dir in search_dirs:
            for cmake_file in sorted(search_dir.rglob("CMakeLists.txt")):
                exes, installed = self._collect_targets(cmake_file)
                all_executables.extend(exes)
                all_installed.extend(installed)

        if module_name:
            for name in all_executables:
                if name == module_name:
                    info.prog_name = name
                    return info

        for name in all_installed:
            if name == module_name:
                info.prog_name = name
                return info

        skip = {"sh", "bash", "test", "tests", "check", "bench", "example"}

        if all_installed:
            for name in all_installed:
                if name.lower() in skip:
                    continue
                if 'daemon' in name or (name.endswith('d') and len(name) > 2):
                    info.prog_name = name
                    return info
            for name in all_installed:
                if name.lower() not in skip:
                    info.prog_name = name
                    return info
        elif all_executables:
            for name in all_executables:
                if name.lower() not in skip:
                    info.prog_name = name
                    return info

        return info

    def _collect_targets(self, cmake_file: Path):
        try:
            content = cmake_file.read_text(errors='ignore')
        except (OSError, UnicodeDecodeError):
            return [], []

        executables = []
        for match in self.ADD_EXE_PATTERN.finditer(content):
            executables.append(match.group(1))

        output_names = {}
        for match in self.OUTPUT_NAME_PATTERN.finditer(content):
            output_names[match.group(1)] = match.group(2).strip('"').strip("${}")

        installed = []
        for match in self.INSTALL_TARGETS_PATTERN.finditer(content):
            installed.append(match.group(1))
        for match in self.INSTALL_TARGETS_SIMPLE.finditer(content):
            if match.group(1) not in installed:
                installed.append(match.group(1))

        exe_names = [output_names.get(e, e) for e in executables]
        inst_names = [output_names.get(i, i) for i in installed]
        return exe_names, inst_names

