from typing import Optional
from sepgen.models.intent import Intent, IntentType


class MacroLookup:
    """Hybrid macro lookup: hardcoded mappings + semacro fallback"""

    KNOWN_MAPPINGS = {
        IntentType.SYSLOG: "logging_send_syslog_msg",
        IntentType.CONFIG_FILE: "read_files_pattern",
        IntentType.NETWORK_SERVER: "corenet_tcp_bind_generic_node",
    }

    def __init__(self):
        self.semacro_available = self._check_semacro()

    def _check_semacro(self) -> bool:
        try:
            import semacro
            return True
        except ImportError:
            return False

    def suggest_macro(self, intent: Intent) -> Optional[str]:
        """Suggest macro for intent - hardcoded first, semacro fallback"""
        if intent.intent_type in self.KNOWN_MAPPINGS:
            return self.KNOWN_MAPPINGS[intent.intent_type]

        if self.semacro_available:
            return self._query_semacro(intent)

        return None

    def _query_semacro(self, intent: Intent) -> Optional[str]:
        try:
            from semacro import search_macros
            results = search_macros(intent_type=intent.intent_type.value)
            return results[0] if results else None
        except Exception:
            return None
