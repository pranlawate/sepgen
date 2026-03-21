import re
from typing import Dict


class Preprocessor:
    """Resolves #define string constants before pattern matching."""

    DEFINE_PATTERN = re.compile(r'#define\s+(\w+)\s+"([^"]+)"')

    def extract_defines(self, code: str) -> Dict[str, str]:
        """Extract all #define string constants from code."""
        defines = {}
        for match in self.DEFINE_PATTERN.finditer(code):
            defines[match.group(1)] = match.group(2)
        return defines

    def expand_macros(self, text: str, defines: Dict[str, str]) -> str:
        """Replace macro names with their quoted string values."""
        for macro, value in defines.items():
            pattern = r'\b' + re.escape(macro) + r'\b'
            text = re.sub(pattern, f'"{value}"', text)
        return text
