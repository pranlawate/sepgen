# Implementation Plan: Maximize Static Analysis Coverage

**Date:** 2026-03-22
**Depends on:** auto-detection plan (completed)
**Goal:** Implement all remaining statically-achievable improvements before moving to trace mode

---

## Context

Gap analysis across testprog, testprog-net, and mcstransd reference policies
identified 11 improvements achievable through static analysis alone. These
fall into two tiers based on confidence and complexity.

## Tier 1 — High Confidence

### Task 1: Service file argument parsing
- **File:** `sepgen/analyzer/service_detector.py`
- Parse ExecStart arguments beyond the executable
- `ExecStart=/usr/bin/testprog /etc/testprog.conf /var/run/testprog.pid`
  yields config_path=/etc/testprog.conf, pid_path=/var/run/testprog.pid
- Add `config_paths: List[str]` and `pid_paths: List[str]` to ServiceInfo
- Wire into ProjectScanner: inject as FILE_READ / FILE_WRITE Access objects
- **Validation:** testprog generates `/etc/testprog.conf` .fc entry

### Task 2: Config file parsing for data paths
- **New file:** `sepgen/analyzer/config_parser.py`
- Read .conf files found in source dir or referenced in service file args
- Parse KEY=VALUE format, extract absolute paths from values
- Classify extracted paths as FILE_WRITE Access (output/data files)
- `OUTPUTFILE=/var/testprog/testprg.txt` → data_dir intent for /var/testprog/
- **Validation:** testprog generates `testprog_data_t` and `/var/testprog` .fc

### Task 3: /run/ alias in .fc
- **File:** `sepgen/generator/fc_generator.py`
- Whenever /var/run/X entry generated, also emit /run/X with same type
- Modern systems symlink /var/run → /run; reference policies include both
- **Validation:** all apps get dual /var/run + /run entries

### Task 4: files_config_file macro
- **File:** `sepgen/generator/te_generator.py`
- Replace `files_type(module_conf_t)` with `files_config_file(module_conf_t)`
- This is the correct SELinux macro for config file types
- **Validation:** testprog .te uses files_config_file

### Task 5: TCP socket self-permissions
- **File:** `sepgen/generator/te_generator.py`
- When NETWORK_SERVER intent present, also emit:
  - `allow module_t self:tcp_socket create_stream_socket_perms;`
  - `corenet_tcp_sendrecv_generic_node(module_t)`
- Currently only emits corenet_tcp_bind_generic_node
- **Validation:** testprog-net gets tcp_socket self rule + sendrecv macro

### Task 6: Custom port type
- **Files:** `sepgen/generator/te_generator.py`, `sepgen/selinux/type_generator.py`
- When NETWORK_SERVER exists, generate module_port_t with port_type attribute
- Emit `typeattribute module_port_t port_type;`
- Emit `allow module_t module_port_t:tcp_socket { name_bind };`
- **Validation:** testprog-net gets testprog_port_t

## Tier 2 — Medium Confidence

### Task 7: exec/system/popen detection
- **Files:** `sepgen/analyzer/symbol_scanner.py`, `sepgen/models/access.py`,
  `sepgen/models/intent.py`, `sepgen/intent/rules.py`, `sepgen/generator/te_generator.py`
- Detect execl, execv, execve, execvp, system, popen in source
- New AccessType.PROCESS_EXEC, IntentType.EXEC_BINARY
- Generates `can_exec(module_t, module_exec_t)` + `corecmd_search_bin(module_t)`
- **Validation:** mcstransd (uses exec*) gets can_exec

### Task 8: /proc and /sys access detection
- **Files:** `sepgen/analyzer/c_analyzer.py`, `sepgen/intent/rules.py`,
  `sepgen/generator/te_generator.py`
- Detect fopen/open of /proc/* → kernel_read_system_state(module_t)
- Detect fopen/open of /sys/* → dev_read_sysfs(module_t)
- New IntentType.KERNEL_STATE, SYSFS_READ
- **Validation:** mcstransd gets kernel_read_system_state

### Task 9: Socket type expansion
- **Files:** `sepgen/analyzer/c_analyzer.py`, `sepgen/generator/te_generator.py`
- Expand SOCKET_PATTERN to capture SOCK_DGRAM and AF_NETLINK
- Parse socket(domain, type) for both arguments
- SOCK_DGRAM + PF_UNIX → unix_dgram_socket perms
- AF_NETLINK → allow self:netlink_selinux_socket create_socket_perms
- **Validation:** mcstransd gets unix_dgram_socket + netlink perms

### Task 10: SELinux API detection
- **Files:** `sepgen/analyzer/symbol_scanner.py`, `sepgen/intent/rules.py`,
  `sepgen/generator/te_generator.py`
- Detect #include <selinux/selinux.h> or calls: getcon, setcon, getpidcon,
  security_compute_av, avc_has_perm
- New IntentType.SELINUX_API
- Maps to selinux_compute_access_vector + seutil_read_config
- **Validation:** mcstransd gets selinux/seutil macros

### Task 11: Init script .fc from Makefile
- **Files:** `sepgen/generator/fc_generator.py`, `sepgen/analyzer/project_scanner.py`
- Wire BuildInfo.init_script (already parsed) into .fc generation
- Emit /etc/rc.d/init.d/<initscript> → module_initrc_exec_t
- **Validation:** mcstransd gets initrc .fc entry

## Execution Order

1. Tasks 3, 4 (quick fixes, no new components)
2. Task 1 (service file args — unblocks task 2)
3. Task 2 (config parsing — depends on knowing config path)
4. Tasks 5, 6 (network improvements)
5. Task 11 (init script .fc — wiring only)
6. Tasks 7, 9 (new detection patterns)
7. Tasks 8, 10 (new intent types + macros)

## Validation

After all tasks, run against all three test apps without --exec-path and
compare generated output to reference policies.
