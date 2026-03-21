from abc import ABC, abstractmethod
from pathlib import Path
from typing import List
from sepgen.models.access import Access


class BaseAnalyzer(ABC):
    """Base class for language-specific analyzers"""

    @abstractmethod
    def analyze_file(self, file_path: Path) -> List[Access]:
        """Analyze a source file and return predicted accesses"""
        pass

    @abstractmethod
    def analyze_string(self, code: str) -> List[Access]:
        """Analyze code string and return predicted accesses"""
        pass
