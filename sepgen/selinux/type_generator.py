from typing import Optional
from sepgen.models.intent import Intent, IntentType


class TypeGenerator:
    """Generate SELinux type names for intents"""

    def generate_type_name(self, module_name: str, intent: Intent) -> Optional[str]:
        """Generate type name based on intent type"""
        type_map = {
            IntentType.CONFIG_FILE: f"{module_name}_conf_t",
            IntentType.PID_FILE: f"{module_name}_var_run_t",
            IntentType.DATA_DIR: f"{module_name}_data_t",
            IntentType.LOG_FILE: f"{module_name}_log_t",
            IntentType.TEMP_FILE: f"{module_name}_tmp_t",
        }

        return type_map.get(intent.intent_type)
