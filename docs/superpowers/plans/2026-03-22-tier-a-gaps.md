# Implementation Plan: Tier A Static Analysis Gap Closure

**Date:** 2026-03-22
**Depends on:** general improvements plan (completed)
**Goal:** Close remaining gaps detectable through regex-based static analysis

---

## Context

Testing against chronyd and dbus revealed gaps where source code contains
detectable patterns that our analyzer misses. All improvements are
general-purpose — CAP_* macros appear in 78% of reference policies, kill()
in many daemons, wrapper socket functions in most IPC-heavy apps.

## Task 1: CAP_* macro detection
- **File:** `sepgen/analyzer/c_analyzer.py`
- Detect `CAP_SYS_TIME`, `CAP_NET_ADMIN`, `CAP_KILL`, etc. in source
- Map to SELinux capability name (lowercase), emit AccessType.CAPABILITY
- **Validation:** chronyd gets sys_time, net_bind_service, net_raw

## Task 2: cap_from_text() string parsing
- **File:** `sepgen/analyzer/c_analyzer.py`
- Parse `"cap_sys_time=ep"` string literals passed to cap_from_text
- Extract capability name, emit AccessType.CAPABILITY
- **Validation:** chronyd cap_from_text strings produce capabilities

## Task 3: kill() -> kill capability
- **File:** `sepgen/analyzer/symbol_scanner.py`
- Add kill to SYMBOL_MAP with capability "kill"
- **Validation:** dbus gets kill in self:capability

## Task 4: Wrapper function socket detection
- **File:** `sepgen/analyzer/c_analyzer.py`
- Match any function call containing literal AF_UNIX/SOCK_STREAM args
- Fallback after SOCKET_PATTERN and SOCKET_PATTERN_SIMPLE
- **Validation:** dbus gets self:unix_stream_socket

## Task 5: /dev/urandom -> dev_read_urand()
- **Files:** `sepgen/intent/rules.py`, `sepgen/models/intent.py`,
  `sepgen/generator/te_generator.py`
- New DeviceAccessRule and IntentType.DEV_RANDOM
- **Validation:** dbus and chronyd get dev_read_urand()

## Task 6: CapabilityBoundingSet from .service files
- **File:** `sepgen/analyzer/service_detector.py`
- Parse CapabilityBoundingSet= and AmbientCapabilities= directives
- Convert CAP_XXX tokens to capability accesses
- **Validation:** chronyd gets sys_time from .service

## Task 7: Config path from .conf.in templates
- **File:** `sepgen/analyzer/config_parser.py`
- Scan *.conf.in files, add XML path pattern for /etc/* paths
- **Validation:** dbus gets dbus_conf_t for /etc/dbus-1

## Execution Order

1. Task 3 (kill, one-line change)
2. Tasks 1, 2 (CAP_* and cap_from_text)
3. Task 6 (CapabilityBoundingSet)
4. Task 5 (dev_read_urand)
5. Task 4 (wrapper socket)
6. Task 7 (.conf.in parsing)
