"""Parse application config files to extract paths for policy generation."""
import re
from pathlib import Path
from typing import List

from sepgen.models.access import Access, AccessType


class ConfigParser:
    """Reads KEY=VALUE config files and extracts absolute paths."""

    KV_PATTERN = re.compile(r'^(\w+)\s*=\s*(.+)$', re.MULTILINE)
    ABS_PATH = re.compile(r'^/[\w/.\-]+$')

    def parse_config(self, config_path: Path) -> List[Access]:
        if not config_path.is_file():
            return []
        content = config_path.read_text()
        return self.parse_string(content, str(config_path))

    def parse_string(self, content: str, source: str = "") -> List[Access]:
        accesses = []
        for match in self.KV_PATTERN.finditer(content):
            value = match.group(2).strip()
            if not self.ABS_PATH.match(value):
                continue
            accesses.append(Access(
                access_type=AccessType.FILE_WRITE,
                path=value,
                syscall="config_file",
                details={"key": match.group(1), "source": "config_file", "config_path": source},
            ))
        return accesses

    def find_and_parse(self, project_dir: Path, config_names: List[str] = None) -> List[Access]:
        """Find config files in the project and parse them."""
        accesses = []

        search_dirs = [project_dir]
        parent = project_dir.parent
        if parent != project_dir:
            search_dirs.append(parent)

        for search_dir in search_dirs:
            if config_names:
                for name in config_names:
                    conf = search_dir / name
                    if conf.is_file():
                        accesses.extend(self.parse_config(conf))
            for conf in search_dir.glob("*.conf"):
                accesses.extend(self.parse_config(conf))

        return accesses
