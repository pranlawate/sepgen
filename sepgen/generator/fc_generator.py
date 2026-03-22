from pathlib import Path
from typing import List, Optional
from sepgen.models.intent import Intent
from sepgen.models.policy import FileContexts


class FCGenerator:
    """Generate FileContexts objects from classified intents"""

    def __init__(self, module_name: str, exec_path: Optional[str] = None):
        self.module_name = module_name
        self.exec_path = exec_path

    @staticmethod
    def _is_template_path(path: str) -> bool:
        """Check if path contains unresolved template variables."""
        return ':' in path.split('/')[-1] or '@' in path

    def generate(self, intents: List[Intent], service_info=None, build_info=None) -> FileContexts:
        """Generate FileContexts from intents, paths, and service info."""
        contexts = FileContexts()

        if self.exec_path and not self._is_template_path(self.exec_path):
            contexts.add_entry(self.exec_path, f"{self.module_name}_exec_t")

        if service_info and getattr(service_info, 'has_init_script', False):
            contexts.add_entry(
                f"/etc/rc.d/init.d/{self.module_name}",
                f"{self.module_name}_initrc_exec_t"
            )
        elif build_info and getattr(build_info, 'init_script', None):
            contexts.add_entry(
                f"/etc/rc.d/init.d/{build_info.init_script}",
                f"{self.module_name}_initrc_exec_t"
            )

        seen_paths = set()
        for intent in intents:
            if not intent.selinux_type:
                continue

            for access in intent.accesses:
                if not access.path or not access.path.startswith('/'):
                    continue

                if not self._is_app_owned(access.path, intent.selinux_type):
                    continue

                fc_path = self._path_to_fc_regex(access.path, intent.selinux_type)
                if fc_path not in seen_paths:
                    seen_paths.add(fc_path)
                    contexts.add_entry(fc_path, intent.selinux_type)
                    run_alias = self._run_alias(fc_path)
                    if run_alias and run_alias not in seen_paths:
                        seen_paths.add(run_alias)
                        contexts.add_entry(run_alias, intent.selinux_type)

        return contexts

    def _is_app_owned(self, path: str, selinux_type: str) -> bool:
        """Determine if a path is owned by this app (needs .fc entry) vs
        a system file the app merely reads (handled by macros instead).

        App-owned: paths containing the module name or a recognizable
        variant, in directories that suggest app ownership.
        System: /etc/resolv.conf, /proc/*, /sys/*, other apps' dirs.
        """
        name = self.module_name.lower()
        name_base = name.rstrip("d")
        name_prefix = name.split("-")[0] if "-" in name else name
        path_lower = path.lower()
        parts = path_lower.split("/")

        candidates = {name, name_base, name_prefix}
        candidates = {c for c in candidates if len(c) > 2}

        if any(c in path_lower for c in candidates):
            return True

        if access_source := self._get_access_source(path):
            if access_source in ("service_file", "config_file"):
                return name in path_lower or name_short in path_lower

        return False

    @staticmethod
    def _get_access_source(path: str) -> Optional[str]:
        return None

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

        if "_data_t" in selinux_type or "_log_t" in selinux_type:
            p = Path(path)
            if p.suffix:
                base = str(p.parent)
            else:
                base = str(p)
            if base != "/":
                return base + "(/.*)?"

        return path

    def _run_alias(self, fc_path: str) -> str | None:
        """Emit /run/ alias for /var/run/ paths and vice versa."""
        if fc_path.startswith("/var/run/"):
            return "/run/" + fc_path[len("/var/run/"):]
        if fc_path.startswith("/run/") and not fc_path.startswith("/run/"):
            return "/var/run/" + fc_path[len("/run/"):]
        return None
