from typing import List, Optional
from sepgen.models.intent import Intent
from sepgen.models.policy import FileContexts


class FCGenerator:
    """Generate FileContexts objects from classified intents"""

    def __init__(self, module_name: str, exec_path: Optional[str] = None):
        self.module_name = module_name
        self.exec_path = exec_path

    def generate(self, intents: List[Intent]) -> FileContexts:
        """Generate FileContexts object (not string)"""
        contexts = FileContexts()

        if self.exec_path:
            contexts.add_entry(self.exec_path, f"{self.module_name}_exec_t")

        for intent in intents:
            if not intent.selinux_type:
                continue

            for access in intent.accesses:
                if access.path.startswith('/'):
                    contexts.add_entry(access.path, intent.selinux_type)

        return contexts
