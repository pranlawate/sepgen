# Implementation Plan: General-Purpose Static Analysis Improvements

**Date:** 2026-03-22
**Depends on:** max static analysis plan (completed)
**Goal:** Fix capability handling, eliminate false positives, add UDP support, and improve config/service file parsing — all general-purpose improvements benefiting any C daemon

---

## Context

Testing against chronyd (103 C files, NTP/UDP daemon) and dbus (98 C files,
system IPC broker) revealed 7 gaps that affect all C daemon analysis, not
just these specific applications. Each improvement was validated against
reference policy statistics: UDP macros appear in 99/505 modules,
self:capability in 396/505, udp_socket in 118/505, unix_dgram_socket in
148/505.

## Tier 1 — Easy, High Impact

### Task 1: Capability details in TEGenerator
- **File:** `sepgen/generator/te_generator.py`
- `AccessType.CAPABILITY` from SymbolScanner carries `details["capability"]`
  (e.g. `"setuid"`) but TEGenerator maps ALL capabilities to `getcap`/`setcap`
- Fix: when `details.get("capability")` is set, add to `cap_perms` set
  (self:capability). Fall back to getcap/setcap only when details is empty
- **Validation:** chronyd gets `self:capability { chown ipc_lock setgid setuid sys_nice }`

### Task 2: Remove SELinux API false positive
- **File:** `sepgen/analyzer/symbol_scanner.py`
- `_SELINUX_INCLUDE` fallback emits synthetic SELINUX_API from header alone
- Fix: remove header-only fallback; require actual API calls from SYMBOL_MAP
- **Validation:** chronyd has no selinux_compute_access_vector; dbus still does

### Task 3: Commit existing ServiceDetector bugfix
- **File:** `sepgen/analyzer/service_detector.py`
- Already fixed: is_file() guard + glob (not rglob) for parent search
- Prevents crashes on .service directories and cross-project contamination

## Tier 2 — Medium, High Impact

### Task 4: UDP network server support
- **Files:** `sepgen/models/intent.py`, `sepgen/intent/rules.py`,
  `sepgen/generator/te_generator.py`, `sepgen/selinux/macro_lookup.py`
- New IntentType.UDP_NETWORK_SERVER
- New UdpServerRule: SOCKET_BIND + sock_type=SOCK_DGRAM + INET domain
- Update NetworkServerRule: only match SOCK_STREAM or absent + INET;
  stop returning True when domain is unknown
- TE: self:udp_socket create_socket_perms + corenet_udp_sendrecv_generic_node
  + corenet_udp_bind_generic_node
- **Validation:** chronyd gets UDP macros, testprog-net keeps TCP

### Task 5: Propagate sock_type through socket-to-bind chain
- **File:** `sepgen/analyzer/c_analyzer.py`
- Store sock_type alongside domain in _last_socket_domain state
- Propagate to bind details
- Remove SOCK_STREAM default from SOCKET_PATTERN_SIMPLE fallback
- **Validation:** explicit SOCK_DGRAM calls produce sock_type in bind access

## Tier 3 — Medium, Medium Impact

### Task 6: Parse systemd service directory directives
- **File:** `sepgen/analyzer/service_detector.py`
- Parse StateDirectory=, RuntimeDirectory=, LogsDirectory=, CacheDirectory=
- Convention: StateDirectory=foo → /var/lib/foo, RuntimeDirectory=foo → /run/foo
- Parse ReadWritePaths= for explicit absolute paths
- **Validation:** chronyd .service ReadWritePaths yields var_lib, var_log paths

### Task 7: Extend config parser for directive-path format
- **File:** `sepgen/analyzer/config_parser.py`
- Add pattern for `word /absolute/path` lines (chrony, sshd, httpd, etc.)
- Keep existing KEY=VALUE support
- **Validation:** chrony example configs yield /var/lib/chrony, /var/log/chrony

## Execution Order

1. Tasks 1, 2 (quick fixes, no new components)
2. Task 3 (commit existing bugfix)
3. Tasks 4, 5 (UDP support — task 5 unblocks task 4 for real detection)
4. Tasks 6, 7 (config/service parsing)

## Validation

After all tasks, run against testprog, testprog-net, mcstransd, chronyd,
and dbus. Compare generated output to reference policies. All 140+ unit
tests must continue to pass.
