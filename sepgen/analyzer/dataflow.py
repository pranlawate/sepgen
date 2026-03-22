import re
from typing import Dict


class DataFlowAnalyzer:
    """Track string variable assignments to resolve indirect paths."""

    ASSIGNMENT_PATTERN = re.compile(
        r'(?:const\s+)?(?:char\s*\*|char\s+)\s*(\w+)\s*=\s*"([^"]+)"'
    )

    def __init__(self):
        self.string_vars: Dict[str, str] = {}

    def extract_string_assignments(self, code: str) -> Dict[str, str]:
        """Find all char* var = "literal" assignments."""
        assignments = {}
        for match in self.ASSIGNMENT_PATTERN.finditer(code):
            assignments[match.group(1)] = match.group(2)
        self.string_vars = assignments
        return assignments

    def resolve_variables(self, code: str) -> str:
        """Replace known variable names in function call contexts with their string values."""
        result = code
        for var, value in self.string_vars.items():
            pattern = re.compile(
                r'(\b(?:fopen|open|unlink|chmod|chown)\s*\(\s*)' +
                re.escape(var) +
                r'(\s*[,)])'
            )
            safe_value = value.replace('\\', '\\\\')
            result = pattern.sub(rf'\1"{safe_value}"\2', result)
        return result
