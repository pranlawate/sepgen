from typing import List
from sepgen.models.access import AccessType
from sepgen.models.intent import Intent, IntentType
from sepgen.models.policy import AllowRule, PolicyModule, RequireBlock, TypeAttribute
from sepgen.selinux.type_generator import TypeGenerator
from sepgen.selinux.macro_lookup import MacroLookup


class TEGenerator:
    """Generate PolicyModule objects from classified intents"""

    def __init__(self, module_name: str, version: str = "1.0.0"):
        self.module_name = module_name
        self.version = version
        self.type_generator = TypeGenerator()
        self.macro_lookup = MacroLookup()

    def generate(self, intents: List[Intent], service_info=None, build_info=None) -> PolicyModule:
        """Generate PolicyModule from classified intents and optional ServiceInfo."""
        policy = PolicyModule(name=self.module_name, version=self.version)

        policy.add_type(f"{self.module_name}_t")
        policy.add_type(f"{self.module_name}_exec_t")

        policy.add_macro("init_daemon_domain", [
            f"{self.module_name}_t",
            f"{self.module_name}_exec_t"
        ])

        has_unix_socket = False
        has_unix_dgram = False
        has_network_server = False
        has_udp_server = False
        has_netlink = False
        has_shm = False
        var_run_type = None
        port_type = None

        for intent in intents:
            if intent.intent_type == IntentType.UNIX_SOCKET_SERVER:
                has_unix_socket = True
                for access in intent.accesses:
                    if access.details.get("sock_type") == "SOCK_DGRAM":
                        has_unix_dgram = True
            elif intent.intent_type == IntentType.NETWORK_SERVER:
                has_network_server = True
            elif intent.intent_type == IntentType.UDP_NETWORK_SERVER:
                has_udp_server = True
            elif intent.intent_type == IntentType.NETLINK_SOCKET:
                has_netlink = True

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
                elif intent.intent_type == IntentType.LOG_FILE:
                    policy.add_macro("logging_log_file", [custom_type])
                    policy.add_macro("manage_files_pattern", [
                        f"{self.module_name}_t", custom_type, custom_type
                    ])
                    policy.add_macro("logging_log_filetrans", [
                        f"{self.module_name}_t", custom_type, "file"
                    ])
                elif intent.intent_type == IntentType.TEMP_FILE:
                    policy.add_macro("files_tmp_file", [custom_type])
                    policy.add_macro("files_tmp_filetrans", [
                        f"{self.module_name}_t", custom_type, "{ file dir }"
                    ])
                    policy.add_macro("manage_files_pattern", [
                        f"{self.module_name}_t", custom_type, custom_type
                    ])
                elif intent.intent_type == IntentType.DATA_DIR:
                    policy.add_macro("files_type", [custom_type])
                    policy.add_macro("manage_dirs_pattern", [
                        f"{self.module_name}_t", custom_type, custom_type
                    ])
                    policy.add_macro("manage_files_pattern", [
                        f"{self.module_name}_t", custom_type, custom_type
                    ])
                elif intent.intent_type == IntentType.CONFIG_FILE:
                    policy.add_macro("files_config_file", [custom_type])
                elif intent.intent_type == IntentType.NETWORK_SERVER:
                    port_type = custom_type

            macro = self.macro_lookup.suggest_macro(intent)
            if macro:
                if custom_type and intent.intent_type == IntentType.CONFIG_FILE:
                    policy.add_macro(macro, [
                        f"{self.module_name}_t",
                        custom_type,
                        custom_type
                    ])
                else:
                    policy.add_macro(macro, [f"{self.module_name}_t"])

            if intent.intent_type == IntentType.EXEC_BINARY:
                policy.add_macro("can_exec", [
                    f"{self.module_name}_t", f"{self.module_name}_exec_t"
                ])
                policy.add_macro("corecmd_search_bin", [f"{self.module_name}_t"])
            elif intent.intent_type == IntentType.KERNEL_STATE:
                policy.add_macro("kernel_read_system_state", [f"{self.module_name}_t"])
            elif intent.intent_type == IntentType.SYSFS_READ:
                policy.add_macro("dev_read_sysfs", [f"{self.module_name}_t"])
            elif intent.intent_type == IntentType.SELINUX_API:
                policy.add_macro("selinux_compute_access_vector", [f"{self.module_name}_t"])
                policy.add_macro("seutil_read_config", [f"{self.module_name}_t"])
            elif intent.intent_type == IntentType.DEV_RANDOM:
                policy.add_macro("dev_read_urand", [f"{self.module_name}_t"])
            elif intent.intent_type == IntentType.SHM_ACCESS:
                has_shm = True

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
                        process_perm = access.details.get("process_perm")
                        if process_perm:
                            process_perms.add(process_perm)
                        else:
                            cap = access.details.get("capability")
                            if cap:
                                cap_perms.add(cap)
                            process_perms.add("setrlimit")
                    elif access.access_type == AccessType.CAPABILITY:
                        cap = access.details.get("capability")
                        if cap:
                            cap_perms.add(cap)
                        else:
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
                permissions=["create_stream_socket_perms"]
            ))
        if has_unix_dgram or has_unix_socket:
            policy.allow_rules.append(AllowRule(
                source=f"{self.module_name}_t",
                target="self",
                object_class="unix_dgram_socket",
                permissions=["create_socket_perms"]
            ))
        if has_netlink:
            policy.allow_rules.append(AllowRule(
                source=f"{self.module_name}_t",
                target="self",
                object_class="netlink_selinux_socket",
                permissions=["create_socket_perms"]
            ))

        if has_network_server:
            policy.allow_rules.append(AllowRule(
                source=f"{self.module_name}_t",
                target="self",
                object_class="tcp_socket",
                permissions=["create_stream_socket_perms"]
            ))
            policy.add_macro("corenet_tcp_sendrecv_generic_node", [f"{self.module_name}_t"])
            if port_type:
                if not policy.require:
                    policy.require = RequireBlock()
                policy.require.attributes.append("port_type")
                policy.typeattributes.append(TypeAttribute(port_type, "port_type"))
                policy.allow_rules.append(AllowRule(
                    source=f"{self.module_name}_t",
                    target=port_type,
                    object_class="tcp_socket",
                    permissions=["name_bind"]
                ))

        if has_udp_server:
            policy.allow_rules.append(AllowRule(
                source=f"{self.module_name}_t",
                target="self",
                object_class="udp_socket",
                permissions=["create_socket_perms"]
            ))
            policy.add_macro("corenet_udp_sendrecv_generic_node", [f"{self.module_name}_t"])
            policy.add_macro("corenet_udp_bind_generic_node", [f"{self.module_name}_t"])

        if has_shm:
            policy.allow_rules.append(AllowRule(
                source=f"{self.module_name}_t",
                target="self",
                object_class="shm",
                permissions=["create_shm_perms"]
            ))

        needs_initrc = (
            (service_info and getattr(service_info, 'needs_initrc_exec_t', False))
            or (build_info and getattr(build_info, 'init_script', None))
        )
        if needs_initrc:
            initrc_type = f"{self.module_name}_initrc_exec_t"
            policy.add_type(initrc_type)
            policy.add_macro("init_script_file", [initrc_type])

        return policy
