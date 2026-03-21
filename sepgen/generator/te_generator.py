from typing import List
from sepgen.models.intent import Intent
from sepgen.models.policy import PolicyModule
from sepgen.selinux.type_generator import TypeGenerator
from sepgen.selinux.macro_lookup import MacroLookup


class TEGenerator:
    """Generate PolicyModule objects from classified intents"""

    def __init__(self, module_name: str, version: str = "1.0.0"):
        self.module_name = module_name
        self.version = version
        self.type_generator = TypeGenerator()
        self.macro_lookup = MacroLookup()

    def generate(self, intents: List[Intent]) -> PolicyModule:
        """Generate PolicyModule object (not string)"""
        policy = PolicyModule(name=self.module_name, version=self.version)

        policy.add_type(f"{self.module_name}_t")
        policy.add_type(f"{self.module_name}_exec_t")

        policy.add_macro("init_daemon_domain", [
            f"{self.module_name}_t",
            f"{self.module_name}_exec_t"
        ])

        for intent in intents:
            custom_type = self.type_generator.generate_type_name(
                self.module_name, intent
            )

            if custom_type:
                policy.add_type(custom_type)
                if intent.intent_type.value in ['config_file', 'pid_file', 'data_dir', 'log_file']:
                    policy.add_macro("files_type", [custom_type])
                intent.selinux_type = custom_type

            macro = self.macro_lookup.suggest_macro(intent)
            if macro:
                if custom_type and intent.intent_type.value in ['config_file', 'data_dir']:
                    policy.add_macro(macro, [
                        f"{self.module_name}_t",
                        custom_type,
                        custom_type
                    ])
                else:
                    policy.add_macro(macro, [f"{self.module_name}_t"])

        return policy
