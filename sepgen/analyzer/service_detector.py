import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ServiceInfo:
    """Information extracted from .service and .init files."""
    exec_path: Optional[str] = None
    has_init_script: bool = False
    has_service_file: bool = False

    @property
    def needs_initrc_exec_t(self) -> bool:
        return self.has_init_script


class ServiceDetector:
    """Finds .service and .init files for exec paths and initrc types."""

    EXEC_START_PATTERN = re.compile(r'ExecStart\s*=\s*(.+)')

    def detect_service_files(self, project_dir: Path, search_parent: bool = False) -> ServiceInfo:
        """Scan project directory for service and init files."""
        info = ServiceInfo()

        search_dirs = [project_dir]
        if search_parent:
            parent = project_dir.parent
            if parent != project_dir:
                search_dirs.append(parent)

        for search_dir in search_dirs:
            for service_file in search_dir.rglob("*.service"):
                info.has_service_file = True
                content = service_file.read_text()
                match = self.EXEC_START_PATTERN.search(content)
                if match:
                    exec_line = match.group(1).strip()
                    info.exec_path = exec_line.split()[0]

            for init_file in search_dir.rglob("*.init"):
                info.has_init_script = True

            if info.has_service_file or info.has_init_script:
                break

        return info
