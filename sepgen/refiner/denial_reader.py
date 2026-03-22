"""Read and parse AVC denials from audit log using avc-parser."""
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class Denial:
    """A single SELinux AVC denial."""
    source_type: str
    target_type: str
    target_class: str
    permissions: List[str]
    path: str = ""
    comm: str = ""
    count: int = 1

    def __str__(self):
        perms = " ".join(sorted(self.permissions))
        return f"allow {self.source_type} {self.target_type}:{self.target_class} {{ {perms} }};"


class DenialReader:
    """Read AVC denials from audit log via avc-parser."""

    def read_audit_log(self, log_path: Path, module_type: Optional[str] = None) -> List[Denial]:
        """Parse audit log and return denials, optionally filtered by source type."""
        if not self._check_avc_parser():
            return self._fallback_parse(log_path, module_type)

        try:
            result = subprocess.run(
                ['avc-parser', '--file', str(log_path), '--json'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return self._fallback_parse(log_path, module_type)
            return self._parse_json(result.stdout, module_type)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return self._fallback_parse(log_path, module_type)

    def _check_avc_parser(self) -> bool:
        return shutil.which('avc-parser') is not None

    def _parse_json(self, json_str: str, module_type: Optional[str]) -> List[Denial]:
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return []

        denials = []
        for entry in data.get("unique_denials", []):
            log = entry.get("log", {})
            scontext = log.get("scontext", "")
            tcontext = log.get("tcontext", "")

            source_type = self._extract_type(scontext)
            target_type = self._extract_type(tcontext)

            if module_type and source_type != module_type:
                continue

            denials.append(Denial(
                source_type=source_type,
                target_type=target_type,
                target_class=log.get("tclass", ""),
                permissions=list(entry.get("permissions", [log.get("permission", "")])),
                path=log.get("path", ""),
                comm=log.get("comm", ""),
                count=entry.get("count", 1),
            ))

        return denials

    @staticmethod
    def _extract_type(context: str) -> str:
        """Extract the SELinux type from a full context string.

        Handles: user:role:type:s0, user:role:type:s0-s0:c0.c1023
        Returns the type field (3rd colon-separated element).
        """
        parts = context.split(":")
        if len(parts) >= 3:
            return parts[2]
        return context

    def _fallback_parse(self, log_path: Path, module_type: Optional[str]) -> List[Denial]:
        """Basic regex parsing when avc-parser is not available."""
        import re
        AVC_RE = re.compile(
            r'avc:\s+denied\s+\{\s*([^}]+)\}\s+for\s+.*?'
            r'scontext=(\S+)\s+tcontext=(\S+)\s+tclass=(\w+)'
        )

        denials = []
        seen = set()

        try:
            content = log_path.read_text(errors='ignore')
        except OSError:
            return []

        for match in AVC_RE.finditer(content):
            perms = match.group(1).strip().split()
            scontext = match.group(2)
            tcontext = match.group(3)
            tclass = match.group(4)

            source_type = self._extract_type(scontext)
            target_type = self._extract_type(tcontext)

            if module_type and source_type != module_type:
                continue

            key = (source_type, target_type, tclass, tuple(sorted(perms)))
            if key in seen:
                continue
            seen.add(key)

            denials.append(Denial(
                source_type=source_type,
                target_type=target_type,
                target_class=tclass,
                permissions=perms,
            ))

        return denials
