from pathlib import Path
from typing import List, Optional
from sepgen.models.intent import Intent
from sepgen.models.policy import FileContexts


class FCGenerator:
    """Generate FileContexts objects from classified intents"""

    def __init__(self, module_name: str, exec_path: Optional[str] = None):
        self.module_name = module_name
        self.exec_path = exec_path

    def generate(self, intents: List[Intent], service_info=None) -> FileContexts:
        """Generate FileContexts from intents, paths, and service info."""
        contexts = FileContexts()

        if self.exec_path:
            contexts.add_entry(self.exec_path, f"{self.module_name}_exec_t")

        if service_info and getattr(service_info, 'has_init_script', False):
            contexts.add_entry(
                f"/etc/rc.d/init.d/{self.module_name}",
                f"{self.module_name}_initrc_exec_t"
            )

        seen_paths = set()
        for intent in intents:
            if not intent.selinux_type:
                continue

            for access in intent.accesses:
                if not access.path or not access.path.startswith('/'):
                    continue

                fc_path = self._path_to_fc_regex(access.path, intent.selinux_type)
                if fc_path not in seen_paths:
                    seen_paths.add(fc_path)
                    contexts.add_entry(fc_path, intent.selinux_type)

        return contexts

    def _path_to_fc_regex(self, path: str, selinux_type: str) -> str:
        """Convert paths to .fc regex patterns for directory trees."""
        if "_var_run_t" in selinux_type:
            p = Path(path)
            parts = p.parts
            for i, part in enumerate(parts):
                if part in ("run", "var"):
                    if i + 1 < len(parts) and parts[i + 1] != "run":
                        return str(Path(*parts[:i + 2])) + "(/.*)?"
                    elif i + 2 < len(parts):
                        return str(Path(*parts[:i + 3])) + "(/.*)?"
        return path
