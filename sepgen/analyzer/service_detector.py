import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class ServiceInfo:
    """Information extracted from .service and .init files."""
    exec_path: Optional[str] = None
    has_init_script: bool = False
    has_service_file: bool = False
    config_paths: List[str] = field(default_factory=list)
    pid_paths: List[str] = field(default_factory=list)
    data_paths: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    needs_nnp: bool = False

    @property
    def needs_initrc_exec_t(self) -> bool:
        return self.has_init_script


class ServiceDetector:
    """Finds .service and .init files for exec paths and initrc types."""

    EXEC_START_PATTERN = re.compile(r'ExecStart\s*=\s*(.+)')
    PID_FILE_PATTERN = re.compile(r'PIDFile\s*=\s*(.+)')

    SYSTEMD_DIR_MAP = {
        'StateDirectory': '/var/lib/',
        'RuntimeDirectory': '/run/',
        'LogsDirectory': '/var/log/',
        'CacheDirectory': '/var/cache/',
    }
    SYSTEMD_DIR_PATTERN = re.compile(
        r'(StateDirectory|RuntimeDirectory|LogsDirectory|CacheDirectory)\s*=\s*(.+)'
    )
    RW_PATHS_PATTERN = re.compile(r'ReadWritePaths\s*=\s*(.+)')
    CAP_BOUNDING_PATTERN = re.compile(
        r'(CapabilityBoundingSet|AmbientCapabilities)\s*=\s*(.+)'
    )
    NNP_PATTERN = re.compile(
        r'(NoNewPrivileges|DynamicUser|ProtectSystem|PrivateDevices)\s*=\s*(true|strict)',
        re.IGNORECASE
    )

    CONF_EXTENSIONS = ('.conf', '.cfg', '.ini', '.yaml', '.toml', '.json')

    def detect_service_files(self, project_dir: Path, search_parent: bool = False) -> ServiceInfo:
        """Scan project directory for service and init files."""
        info = ServiceInfo()

        search_dirs = [project_dir]
        if search_parent:
            parent = project_dir.parent
            if parent != project_dir:
                search_dirs.append(parent)

        for search_dir in search_dirs:
            use_rglob = (search_dir == project_dir)
            pattern_fn = search_dir.rglob if use_rglob else search_dir.glob

            for pattern in ("*.service", "*.service.in"):
                for service_file in pattern_fn(pattern):
                    if not service_file.is_file():
                        continue
                    info.has_service_file = True
                    content = service_file.read_text()
                    self._parse_service_content(content, info)

            for init_file in pattern_fn("*.init"):
                if not init_file.is_file():
                    continue
                info.has_init_script = True

            if info.has_service_file or info.has_init_script:
                break

        return info

    def _parse_service_content(self, content: str, info: ServiceInfo) -> None:
        match = self.EXEC_START_PATTERN.search(content)
        if match:
            parts = match.group(1).strip().split()
            SHELL_INTERPRETERS = {"/bin/sh", "/usr/bin/sh", "/bin/bash", "/usr/bin/bash",
                                   "/usr/bin/python3", "/usr/bin/python", "/usr/bin/env"}
            if parts:
                path = parts[0]
                if ':' not in path and '@' not in path and path not in SHELL_INTERPRETERS:
                    info.exec_path = path
            for arg in parts[1:]:
                if not arg.startswith('/'):
                    continue
                if any(arg.endswith(ext) for ext in self.CONF_EXTENSIONS):
                    info.config_paths.append(arg)
                elif '.pid' in arg or arg.startswith('/var/run/') or arg.startswith('/run/'):
                    info.pid_paths.append(arg)

        pid_match = self.PID_FILE_PATTERN.search(content)
        if pid_match:
            pid_path = pid_match.group(1).strip()
            if pid_path and pid_path not in info.pid_paths:
                info.pid_paths.append(pid_path)

        for dir_match in self.SYSTEMD_DIR_PATTERN.finditer(content):
            directive = dir_match.group(1)
            prefix = self.SYSTEMD_DIR_MAP[directive]
            for name in dir_match.group(2).strip().split():
                name = name.strip()
                if name:
                    full_path = prefix + name
                    if full_path not in info.data_paths:
                        info.data_paths.append(full_path)

        rw_match = self.RW_PATHS_PATTERN.search(content)
        if rw_match:
            for token in rw_match.group(1).strip().split():
                path = token.lstrip('-')
                if path.startswith('/') and path.count('/') >= 3 and path not in info.data_paths:
                    info.data_paths.append(path)

        for cap_match in self.CAP_BOUNDING_PATTERN.finditer(content):
            line = cap_match.group(2).strip()
            if line.startswith('~'):
                continue
            for token in line.split():
                if token.startswith('CAP_'):
                    cap_name = token[4:].lower()
                    if cap_name not in info.capabilities:
                        info.capabilities.append(cap_name)

        if self.NNP_PATTERN.search(content):
            info.needs_nnp = True
