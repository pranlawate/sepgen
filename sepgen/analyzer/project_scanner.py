from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.analyzer.makefile_parser import BuildInfo, MakefileParser
from sepgen.analyzer.service_detector import ServiceDetector, ServiceInfo
from sepgen.analyzer.symbol_scanner import SymbolScanner
from sepgen.models.access import Access


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
        self.service_detector = ServiceDetector()
        self.makefile_parser = MakefileParser()

    def scan(self, source_path: Path, module_name: str) -> ProjectInfo:
        info = ProjectInfo(module_name=module_name)

        if source_path.is_dir():
            info.accesses = self.c_analyzer.analyze_directory(source_path)
            info.accesses.extend(self.symbol_scanner.scan_directory(source_path))
            info.service_info = self.service_detector.detect_service_files(source_path, search_parent=True)
            info.build_info = self.makefile_parser.parse(source_path)
        else:
            info.accesses = self.c_analyzer.analyze_file(source_path)
            info.accesses.extend(self.symbol_scanner.scan_file(source_path))

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
