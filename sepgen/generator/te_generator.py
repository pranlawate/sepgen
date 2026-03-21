from typing import List
from sepgen.models.access import AccessType
from sepgen.models.intent import Intent, IntentType
from sepgen.models.policy import AllowRule, PolicyModule
from sepgen.selinux.type_generator import TypeGenerator
from sepgen.selinux.macro_lookup import MacroLookup


class TEGenerator:
    """Generate PolicyModule objects from classified intents"""

    def __init__(self, module_name: str, version: str = "1.0.0"):
        self.module_name = module_name
        self.version = version
        self.type_generator = TypeGenerator()
        self.macro_lookup = MacroLookup()

    def generate(self, intents: List[Intent], service_info=None) -> PolicyModule:
        """Generate PolicyModule from classified intents and optional ServiceInfo."""
        policy = PolicyModule(name=self.module_name, version=self.version)

        policy.add_type(f"{self.module_name}_t")
        policy.add_type(f"{self.module_name}_exec_t")

        policy.add_macro("init_daemon_domain", [
            f"{self.module_name}_t",
            f"{self.module_name}_exec_t"
        ])

        has_unix_socket = False
        var_run_type = None

        for intent in intents:
            if intent.intent_type == IntentType.UNIX_SOCKET_SERVER:
                has_unix_socket = True

            custom_type = self.type_generator.generate_type_name(
                self.module_name, intent
            )

            if custom_type:
                policy.add_type(custom_type)
                intent.selinux_type = custom_type

                if "_var_run_t" in custom_type:
                    var_run_type = custom_type
                    policy.add_macro("files_pid_file", [custom_type])
                    policy.add_macro("files_pid_filetrans", [
                        f"{self.module_name}_t", custom_type, "{ file dir }"
                    ])
                    policy.add_macro("manage_dirs_pattern", [
                        f"{self.module_name}_t", custom_type, custom_type
                    ])
                    policy.add_macro("manage_files_pattern", [
                        f"{self.module_name}_t", custom_type, custom_type
                    ])
                elif intent.intent_type.value in ['config_file', 'data_dir', 'log_file']:
                    policy.add_macro("files_type", [custom_type])

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

        if has_unix_socket and var_run_type:
            policy.add_macro("manage_sock_files_pattern", [
                f"{self.module_name}_t", var_run_type, var_run_type
            ])

        # Collect self: rule permissions across all intents
        cap_perms = set()
        process_perms = set()

        for intent in intents:
            if intent.intent_type == IntentType.SELF_CAPABILITY:
                for access in intent.accesses:
                    if access.access_type == AccessType.PROCESS_CONTROL:
                        cap = access.details.get("capability")
                        if cap:
                            cap_perms.add(cap)
                        process_perms.add("setrlimit")
                    elif access.access_type == AccessType.CAPABILITY:
                        process_perms.update(["getcap", "setcap"])

        if cap_perms:
            policy.allow_rules.append(AllowRule(
                source=f"{self.module_name}_t",
                target="self",
                object_class="capability",
                permissions=sorted(cap_perms)
            ))
        if process_perms:
            policy.allow_rules.append(AllowRule(
                source=f"{self.module_name}_t",
                target="self",
                object_class="process",
                permissions=sorted(process_perms)
            ))
        if has_unix_socket:
            policy.allow_rules.append(AllowRule(
                source=f"{self.module_name}_t",
                target="self",
                object_class="unix_stream_socket",
                permissions=["create", "bind", "listen", "accept"]
            ))

        if service_info and getattr(service_info, 'needs_initrc_exec_t', False):
            initrc_type = f"{self.module_name}_initrc_exec_t"
            policy.add_type(initrc_type)
            policy.add_macro("init_script_file", [initrc_type])

        return policy
