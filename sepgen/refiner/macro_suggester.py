"""Suggest SELinux macros for AVC denials using semacro."""
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from sepgen.refiner.denial_reader import Denial


@dataclass
class Suggestion:
    """A suggested policy addition for a denial."""
    denial: Denial
    macro: Optional[str] = None
    raw_rule: Optional[str] = None
    source_file: Optional[str] = None

    def __str__(self):
        if self.macro:
            return self.macro
        return self.raw_rule or str(self.denial)


class MacroSuggester:
    """Suggest macros for denials using semacro."""

    WELL_KNOWN_MACROS = {
        ("file", "read"): "read_files_pattern",
        ("file", "write"): "manage_files_pattern",
        ("file", "create"): "manage_files_pattern",
        ("dir", "read"): "list_dirs_pattern",
        ("dir", "search"): "search_dirs_pattern",
        ("dir", "write"): "manage_dirs_pattern",
        ("sock_file", "write"): "manage_sock_files_pattern",
        ("lnk_file", "read"): "read_lnk_files_pattern",
    }

    def suggest(self, denials: List[Denial]) -> List[Suggestion]:
        suggestions = []
        for denial in denials:
            suggestion = self._suggest_one(denial)
            suggestions.append(suggestion)
        return suggestions

    def _suggest_one(self, denial: Denial) -> Suggestion:
        if self._check_semacro():
            macro = self._query_semacro(denial)
            if macro:
                return Suggestion(denial=denial, macro=macro)

        macro = self._try_well_known(denial)
        if macro:
            return Suggestion(denial=denial, macro=macro)

        return Suggestion(denial=denial, raw_rule=str(denial))

    def _check_semacro(self) -> bool:
        return shutil.which('semacro') is not None

    def _query_semacro(self, denial: Denial) -> Optional[str]:
        perms = " ".join(denial.permissions)
        cmd = ['semacro', 'which', denial.source_type, denial.target_type, perms]
        if denial.target_class:
            cmd.extend(['--class', denial.target_class])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                first_line = result.stdout.strip().split('\n')[0]
                macro = first_line.strip().split()[0] if first_line.strip() else None
                return macro
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return None

    def _try_well_known(self, denial: Denial) -> Optional[str]:
        for perm in denial.permissions:
            key = (denial.target_class, perm)
            macro_name = self.WELL_KNOWN_MACROS.get(key)
            if macro_name:
                return f"{macro_name}({denial.source_type}, {denial.target_type}, {denial.target_type})"
        return None
