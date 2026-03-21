import re
from pathlib import Path
from typing import List
from sepgen.analyzer.base import BaseAnalyzer
from sepgen.analyzer.syscall_mapper import SyscallMapper
from sepgen.models.access import Access

class CAnalyzer(BaseAnalyzer):
    """Static analyzer for C/C++ code using regex patterns"""

    def __init__(self):
        self.mapper = SyscallMapper()

    def analyze_file(self, file_path: Path) -> List[Access]:
        """Analyze a C source file"""
        code = file_path.read_text()
        return self.analyze_string(code)

    def analyze_string(self, code: str) -> List[Access]:
        """Analyze C code string using regex patterns"""
        accesses = []

        # Pattern: fopen("path", "mode")
        fopen_pattern = re.compile(r'fopen\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)')
        for match in fopen_pattern.finditer(code):
            path = match.group(1)
            mode = match.group(2)
            access = self.mapper.map_function_call('fopen', [f'"{path}"', f'"{mode}"'])
            if access:
                accesses.append(access)

        # Pattern: socket(domain, type, protocol)
        socket_pattern = re.compile(r'socket\s*\(\s*([A-Z_]+)\s*,\s*([A-Z_]+)\s*,')
        for match in socket_pattern.finditer(code):
            domain = match.group(1)
            sock_type = match.group(2)
            access = self.mapper.map_function_call('socket', [domain, sock_type])
            if access:
                accesses.append(access)

        # Pattern: bind() - simple detection
        if 'bind(' in code:
            access = self.mapper.map_function_call('bind', [])
            if access:
                accesses.append(access)

        return accesses
