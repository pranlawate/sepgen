import re
from typing import List


class IncludeAnalyzer:
    """Infers capabilities from #include headers."""

    INCLUDE_PATTERN = re.compile(r'#include\s+[<"]([^>"]+)[>"]')

    CAPABILITY_MAP = {
        'syslog.h': ['syslog'],
        'sys/socket.h': ['socket'],
        'sys/capability.h': ['capability', 'process_setcap'],
        'sys/resource.h': ['setrlimit'],
        'signal.h': ['signal_perms'],
    }

    def infer_capabilities(self, code: str) -> List[str]:
        """Return list of capabilities implied by included headers."""
        capabilities = []
        for match in self.INCLUDE_PATTERN.finditer(code):
            header = match.group(1)
            if header in self.CAPABILITY_MAP:
                capabilities.extend(self.CAPABILITY_MAP[header])
        return capabilities
