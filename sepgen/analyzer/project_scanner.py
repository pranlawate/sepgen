from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.analyzer.cmake_parser import CMakeParser
from sepgen.analyzer.config_parser import ConfigParser
from sepgen.analyzer.makefile_parser import BuildInfo, MakefileParser
from sepgen.analyzer.service_detector import ServiceDetector, ServiceInfo
from sepgen.analyzer.symbol_scanner import SymbolScanner
from sepgen.models.access import Access, AccessType


@dataclass
class ProjectInfo:
    """Aggregated project metadata from all scanners."""
    accesses: List[Access] = field(default_factory=list)
    service_info: Optional[ServiceInfo] = None
    build_info: Optional[BuildInfo] = None
    exec_path: Optional[str] = None
    module_name: str = ""


class ProjectScanner:
    """Orchestrates all analyzers and resolves exec_path via fallback chain."""

    def __init__(self):
        self.c_analyzer = CAnalyzer()
        self.symbol_scanner = SymbolScanner()
        self.config_parser = ConfigParser()
        self.service_detector = ServiceDetector()
        self.makefile_parser = MakefileParser()
        self.cmake_parser = CMakeParser()

    def scan(self, source_path: Path, module_name: str) -> ProjectInfo:
        info = ProjectInfo(module_name=module_name)

        if source_path.is_dir():
            info.accesses = self.c_analyzer.analyze_directory(source_path)
            info.accesses.extend(self.symbol_scanner.scan_directory(source_path))
            info.service_info = self.service_detector.detect_service_files(source_path, search_parent=True)
            info.build_info = self.makefile_parser.parse(source_path)
            if not info.build_info.prog_name:
                info.build_info = self.cmake_parser.parse(source_path, module_name)
        else:
            info.accesses = self.c_analyzer.analyze_file(source_path)
            info.accesses.extend(self.symbol_scanner.scan_file(source_path))

        self._inject_service_paths(info)
        self._inject_config_paths(info, source_path)
        info.exec_path = self._resolve_exec_path(info, module_name)
        return info

    def _resolve_exec_path(self, info: ProjectInfo, module_name: str) -> Optional[str]:
        """Fallback chain: .service → Makefile → convention."""
        if info.service_info and info.service_info.exec_path:
            return info.service_info.exec_path

        if info.build_info and info.build_info.exec_path:
            return info.build_info.exec_path

        if info.service_info and info.service_info.has_service_file:
            return f"/usr/sbin/{module_name}"

        return None

    def _inject_config_paths(self, info: ProjectInfo, source_path: Path) -> None:
        """Parse .conf files to extract data paths."""
        config_names = []
        if info.service_info:
            for cp in info.service_info.config_paths:
                config_names.append(Path(cp).name)
        search_dir = source_path if source_path.is_dir() else source_path.parent
        accesses = self.config_parser.find_and_parse(search_dir, config_names or None)
        existing = {a.path for a in info.accesses}
        for a in accesses:
            if a.path not in existing:
                info.accesses.append(a)

    def _inject_service_paths(self, info: ProjectInfo) -> None:
        """Inject config/PID paths from .service file as Access objects."""
        if not info.service_info:
            return
        existing_paths = {a.path for a in info.accesses}
        for conf_path in info.service_info.config_paths:
            if conf_path not in existing_paths:
                info.accesses.append(Access(
                    access_type=AccessType.FILE_READ,
                    path=conf_path,
                    syscall="service_file",
                    details={"source": "service_file"},
                ))
        for pid_path in info.service_info.pid_paths:
            if pid_path not in existing_paths:
                info.accesses.append(Access(
                    access_type=AccessType.FILE_WRITE,
                    path=pid_path,
                    syscall="service_file",
                    details={"source": "service_file"},
                ))
        for data_path in info.service_info.data_paths:
            if data_path not in existing_paths:
                info.accesses.append(Access(
                    access_type=AccessType.FILE_WRITE,
                    path=data_path,
                    syscall="service_file",
                    details={"source": "service_file"},
                ))
        existing_caps = {
            a.details.get("capability")
            for a in info.accesses if a.access_type == AccessType.CAPABILITY
        }
        for cap in info.service_info.capabilities:
            if cap not in existing_caps:
                info.accesses.append(Access(
                    access_type=AccessType.CAPABILITY,
                    path="",
                    syscall="service_file",
                    details={"capability": cap},
                ))
