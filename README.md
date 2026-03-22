# sepgen

An SELinux policy generator that analyzes source code and traces runtime
behavior to produce macro-based policy modules with custom types — the policy
that `audit2allow` should generate but doesn't.

## The Problem

Writing SELinux policy today is a painful iterative loop:

1. Run the app confined → it crashes on the first denial
2. Check `ausearch` → find one denial
3. Add an allow rule → recompile → reinstall → rerun
4. Repeat 10–20 times until the app works

`audit2allow` automates step 3, but it generates **raw allow rules against
existing types** — overly broad, no custom types, no `.fc` file, no macros.
You still end up manually rewriting everything.

## The Solution

sepgen takes a dual-mode approach to policy generation:

1. **Static analysis** (primary) — Reads your C source code (single file or
   entire directory), resolves `#define` constants, tracks string variables,
   identifies syscall patterns (`fopen`, `open`, `socket`, `bind`, `syslog`,
   `setrlimit`, `cap_*`, `unlink`, `chmod`, `daemon`, `exec*`, `system`,
   `popen`), scans for 40+ capability/process symbols, detects `/proc` and
   `/sys` access, recognizes SELinux API calls, parses `.conf` files for data
   paths, extracts config/PID paths from `.service` file arguments, parses
   Makefiles for install targets, and generates `/run` alias entries and custom
   port types. No execution needed.

2. **Runtime tracing** (supplementary) — Traces the compiled binary with
   `strace` to observe actual syscalls. Use this when source code is unavailable
   or to validate and strengthen the policy generated from static analysis.

Both pipelines feed into the same intent classification engine, which maps
low-level accesses to high-level security intents and generates complete,
macro-based policy modules.

```bash
# Primary: generate policy from source code (single file or directory)
sepgen analyze ./src/myapp.c --name myapp
sepgen analyze ./src/ --name myapp

# Supplementary: trace binary to validate/strengthen the policy
sepgen trace /usr/bin/myapp -y
```

Output: `myapp.te`, `myapp.fc` — ready to compile and install.

### What sepgen generates vs audit2allow

| Access observed | audit2allow | sepgen |
|---|---|---|
| Write to `/var/run/app.pid` | `allow app_t var_run_t:file write;` | Creates `app_var_run_t`, uses `files_pid_filetrans()` + `manage_files_pattern()` |
| Read `/etc/app.conf` | `allow app_t etc_t:file read;` | Creates `app_conf_t`, uses `files_config_file()` + `read_files_pattern()` |
| Write to `/var/app/data.txt` | `allow app_t var_t:file { create write };` | Creates `app_data_t`, uses `manage_files_pattern()` |
| Syslog socket | `allow app_t devlog_t:sock_file write;` + 3 more rules | `logging_send_syslog_msg(app_t)` (deduplicated) |
| Bind TCP port | `allow app_t port_t:tcp_socket name_bind;` | Creates `app_port_t`, `tcp_socket create_stream_socket_perms` + `corenet_tcp_*` |
| Bind Unix socket | `allow app_t self:unix_stream_socket ...;` (many rules) | `allow app_t self:unix_stream_socket create_stream_socket_perms;` |
| `exec*()` / `system()` | *(not generated)* | `can_exec(app_t, app_exec_t)` + `corecmd_search_bin(app_t)` |
| Read `/proc/*` | *(not generated)* | `kernel_read_system_state(app_t)` |
| SELinux API calls | *(not generated)* | `selinux_compute_access_vector(app_t)` + `seutil_read_config(app_t)` |
| `setrlimit()` call | *(not generated)* | `allow app_t self:capability sys_resource;` + `self:process setrlimit;` |
| Init script detected | *(not generated)* | Creates `app_initrc_exec_t`, uses `init_script_file()` |
| `.fc` file | *(never generated)* | Full file context mapping with `/var/run` + `/run` aliases |

## Usage

### Analyze: Generate policy from source code

```bash
# Analyze a single C source file
sepgen analyze ./src/myapp.c --name myapp

# Analyze an entire directory (all .c files + service file detection)
sepgen analyze ./src/ --name myapp

# Analyze with verbose output (shows classified intents)
sepgen analyze ./src/ --name myapp -v

# Analyze with debug output
sepgen analyze ./src/myapp.c --name myapp -vv
```

When given a directory, sepgen analyzes all `.c` files recursively, parses
Makefiles for install targets, detects `.service` and `.init` files, and
auto-detects the binary's install path for `.fc` generation. No `--exec-path`
flag needed in the common case.

Example output:
```
[1/3] Analyzing source... ✓
[2/3] Classifying intents... ✓
[3/3] Generating policy... ✓
Generated: myapp.te (5 types), myapp.fc (3 entries)
```

With `-v`:
```
[1/3] Analyzing source... ✓
[2/3] Classifying intents... ✓
  • config_file: /etc/myapp.conf
  • pid_file: /var/run/myapp.pid
  • syslog: /dev/log
  • unix_socket_server: /var/run/myapp/.myapp-unix
  • self_capability: sys_resource
[3/3] Generating policy... ✓
  Generated types: myapp_t, myapp_conf_t, myapp_var_run_t, myapp_initrc_exec_t
  Applied macros: logging_send_syslog_msg, files_pid_filetrans,
    manage_dirs_pattern, manage_files_pattern, init_script_file
  Self rules: self:capability { sys_resource }, self:process { setrlimit }
Generated: myapp.te (7 types), myapp.fc (4 entries)
```

### Trace: Validate with runtime behavior

Use when source code is unavailable, or to strengthen an existing policy with
observed runtime behavior.

```bash
# Trace a binary (generates new policy if none exists)
sepgen trace /usr/bin/myapp

# Trace and auto-approve merge with existing policy
sepgen trace /usr/bin/myapp -y

# Attach to a running process
sepgen trace --pid $(cat /var/run/myapp.pid)
```

### Recommended workflow: Analyze then Trace

```bash
# Step 1: Generate initial policy from source code
sepgen analyze ./src/myapp.c --name myapp

# Step 2: Build and install the application
make && sudo make install

# Step 3: Trace the binary to catch runtime-only accesses
#         (glibc internals, dynamic loading, config-driven paths)
sepgen trace /usr/bin/myapp -y

# Step 4: Install the policy
sudo semodule -i myapp.pp
```

When `sepgen trace` detects an existing policy from a previous `analyze` run,
it compares the two and offers an intelligent merge:

```
Found existing policy: myapp.te (from static analysis)
Comparing with runtime trace...

Comparison:
  Static analysis: 4 types
  Runtime trace:   6 types
  Matched:         3 types

Conflicts found: 1
  • read_files_pattern
    Existing: read_files_pattern(myapp_t, myapp_conf_t, myapp_conf_t)
    Trace:    manage_files_pattern(myapp_t, myapp_conf_t, myapp_conf_t)

Merge with trace results? [Y/n/diff]
```

Use `-y` to auto-approve merges (trace wins on conflicts).

### Refine: Production hardening (future)

After analyze + trace, test in enforcing mode. If denials occur, use the
three-tool suite to resolve them:

```bash
# Step 5: Analyze denials from enforcing mode testing
avc-parser /var/log/audit/audit.log

# Step 6: Find the right macro for each denial
semacro which <access pattern>

# Step 7: Update policy (future: sepgen refine myapp.te)
```

Most apps are fully functional after analyze + trace. The refine step handles
cross-domain integration (e.g., logrotate accessing your app's logs) and
`dontaudit` rules for harmless denials.

## How It Works

```
  ┌─────────────────────┐                  ┌─────────────────┐
  │  Source Code         │                  │  Application    │
  │  (.c files / dir)   │                  │  Binary         │
  └──────────┬──────────┘                  └────────┬────────┘
             │                                      │
   ┌─────────▼───────────┐                          │
   │  Static Analysis    │                  strace -f
   │  Pipeline           │                          │
   │                     │                          │
   │  Preprocessor       │                          │
   │  (#define resolve)  │                          │
   │  DataFlowAnalyzer   │                          │
   │  (variable tracking)│                          │
   │  IncludeAnalyzer    │                          │
   │  (header inference) │                          │
   │  CAnalyzer          │                          │
   │  (20+ patterns)     │                          │
   │  SymbolScanner      │                          │
   │  (40+ cap/process)  │                          │
   │  ConfigParser       │                          │
   │  (data path extract)│                          │
   │  MakefileParser     │                          │
   │  (exec path, dirs)  │                          │
   │  ServiceDetector    │                          │
   │  (.service args)    │                          │
   │  ProjectScanner     │                          │
   │  (orchestrator)     │                          │
   └──────────┬──────────┘                          │
              │                                     │
              ▼                                     ▼
  ┌────────────────┐                  ┌─────────────────┐
  │  Predicted     │                  │  Observed       │
  │  Accesses      │                  │  Accesses       │
  │  List[Access]  │                  │  List[Access]   │
  └───────┬────────┘                  └────────┬────────┘
          │                                    │
          └──────────────┬─────────────────────┘
                         │
                 ┌───────▼────────┐
                 │    Intent      │
                 │ Classification │
                 │ (rule engine)  │
                 └───────┬────────┘
                         │
            ┌────────────┴───────────────┐
            │                            │
            ▼                            ▼
  ┌──────────────────┐        ┌──────────────────┐
  │ TypeGenerator    │        │ MacroLookup      │
  │ (custom types)   │        │ (hardcoded +     │
  │                  │        │  semacro)        │
  └────────┬─────────┘        └────────┬─────────┘
           │                           │
           └─────────┬─────────────────┘
                     ▼
            ┌──────────────────┐
            │ Policy Generator │
            │ PolicyModule +   │
            │ FileContexts     │
            │ + self: rules    │
            └────────┬─────────┘
                     │
        ┌────────────┴───────────────┐
        │                            │
        ▼                            ▼
  ┌──────────────┐          ┌──────────────┐
  │ [New policy] │          │ [Existing    │
  │ Write .te    │          │  policy?]    │
  │ Write .fc    │          │ → Merge      │
  └──────────────┘          └──────────────┘
```

### Intent Classification

sepgen classifies raw accesses into security intents using deterministic rules:

| Access Pattern | Intent | Custom Type | Macro / Rule |
|---|---|---|---|
| `/var/run/*.pid` + write | PID_FILE | `{mod}_var_run_t` | `files_pid_filetrans()` + `manage_files_pattern()` |
| `/etc/**` + read, `*.conf` | CONFIG_FILE | `{mod}_conf_t` | `files_config_file()` + `read_files_pattern()` |
| Data path from `.conf` file | DATA_DIR | `{mod}_data_t` | `files_type()` + `manage_files_pattern()` |
| `/var/log/**` + write | LOG_FILE | `{mod}_log_t` | `logging_log_file()` + `logging_log_filetrans()` |
| `/tmp/**` + write | TEMP_FILE | `{mod}_tmp_t` | `files_tmp_file()` + `files_tmp_filetrans()` |
| `syslog()` / `openlog()` | SYSLOG | — | `logging_send_syslog_msg()` |
| `bind()` on AF_INET | NETWORK_SERVER | `{mod}_port_t` | `corenet_tcp_bind/sendrecv` + `tcp_socket create_stream_socket_perms` |
| `bind()` on PF_UNIX | UNIX_SOCKET_SERVER | — | `allow ... self:unix_stream_socket create_stream_socket_perms;` |
| `socket(AF_NETLINK, ...)` | NETLINK_SOCKET | — | `allow ... self:netlink_selinux_socket create_socket_perms;` |
| `exec*()` / `system()` | EXEC_BINARY | — | `can_exec()` + `corecmd_search_bin()` |
| `fopen("/proc/...")` | KERNEL_STATE | — | `kernel_read_system_state()` |
| `fopen("/sys/...")` | SYSFS_READ | — | `dev_read_sysfs()` |
| `getcon()` / SELinux API | SELINUX_API | — | `selinux_compute_access_vector()` + `seutil_read_config()` |
| `setrlimit()` / `cap_*()` | SELF_CAPABILITY | — | `allow ... self:capability ...;` + `self:process ...;` |
| `daemon()` | DAEMON_PROCESS | — | confirms `init_daemon_domain()` |
| `.init` file / Makefile | — | `{mod}_initrc_exec_t` | `init_script_file()` |

## Installation

### System packages (Fedora/RHEL)

```bash
sudo dnf install strace python3-libselinux policycoreutils policycoreutils-devel \
                 setools-console libselinux-utils
```

### Python package

```bash
pip install sepgen
```

Or from source:
```bash
git clone https://github.com/pranlawate/sepgen.git
cd sepgen
pip install -e ".[dev]"
```

### Dependencies

**Required:**

| Package | Source | Used for |
|---|---|---|
| Python 3.9+ | System | Runtime |
| `semacro` | [github.com/pranlawate/semacro](https://github.com/pranlawate/semacro) | Macro lookup, .te parsing |
| `strace` | System | Runtime tracing (trace command only) |

**Required system packages (for trace mode):**

| Package | Provides | Used for |
|---|---|---|
| `strace` | `strace` | Syscall tracing |
| `policycoreutils` | `semanage`, `restorecon`, `semodule` | Query file contexts, load policy |
| `policycoreutils-devel` | `checkmodule`, `semodule_package` | Compile and validate `.te` |
| `setools-console` | `sesearch`, `seinfo` | Query existing policy |

**Optional:**

| Package | Source | Used for |
|---|---|---|
| `python3-libselinux` | System | `matchpathcon()` path-to-context resolution |
| `rich` | PyPI | Enhanced terminal output |

## Relationship to Other Tools

sepgen is part of a three-tool suite for SELinux policy development:

| Tool | Purpose | Input | Output |
|---|---|---|---|
| [semacro](https://github.com/pranlawate/semacro) | Explore policy macros | Macro name | Expanded rules, macro search |
| **sepgen** | Generate policy from code/behavior | Source code / binary | `.te` + `.fc` |
| [avc-parser](https://github.com/pranlawate/avc-parser) | Analyze runtime denials | Audit log | Denial timeline, coverage gaps |

Typical workflow:
1. `sepgen analyze` → generate initial policy from source
2. `sepgen trace` → validate and strengthen with runtime data
3. `semodule -i` → install policy
4. Test in enforcing mode → if denials occur:
5. `avc-parser` → understand what was missed
6. `semacro which` → find the right macro for missed access

## Project Status

**Phase:** Static analysis complete — all regex-achievable gaps closed, ready for trace mode

Implemented:
- Core data models (Access, Intent, PolicyModule, FileContexts)
- Static analysis pipeline (C analyzer with regex-based pattern detection)
- Syscall mapper (C library function → syscall translation)
- Runtime tracing pipeline (strace parser, process tracer)
- Intent classification engine with 18 deterministic rules
- SELinux type generator and hybrid macro lookup
- Policy generation (.te) and file context generation (.fc)
- Policy serialization (TEWriter, FCWriter)
- Merge layer with conflict detection and trace-wins strategy
- CLI with `analyze` and `trace` commands
- End-to-end integration tests
- `#define` constant resolution (Preprocessor)
- String variable tracking (DataFlowAnalyzer)
- Header-based capability inference (IncludeAnalyzer)
- Service file detection with argument parsing (config/PID paths from ExecStart)
- Systemd directory directives (StateDirectory, RuntimeDirectory, LogsDirectory, ReadWritePaths)
- Config file parsing for data paths (KEY=VALUE and directive /path formats)
- Multi-file directory analysis with cross-file dedup
- 25+ detection patterns (syslog, open, unlink, chmod, listen, accept, setrlimit, cap_*, daemon, exec*, /proc, /sys, netlink, CAP_* macros, cap_from_text, kill, wrapper sockets, /dev/urandom)
- 40+ symbol-to-permission mappings (from sepolicy generate) plus kill()
- SELinux API detection (getcon, setcon, security_compute_av — real calls only, no header false positives)
- CAP_* macro detection (CAP_SYS_TIME, CAP_NET_ADMIN, etc.) and cap_from_text() string parsing
- CapabilityBoundingSet/AmbientCapabilities from systemd .service files
- /dev/urandom and /dev/random -> dev_read_urand() macro
- Wrapper function socket detection (catches indirect socket creation via helper functions)
- Template config file scanning (.conf.in with XML path extraction)
- Device path string literal scanner (/dev/urandom, /dev/random in any context)
- SHM/IPC detection (shmget, shm_open) with self:shm allow rules
- UDP and TCP socket protocol awareness (separate corenet_udp_* and corenet_tcp_* macros)
- Socket type propagation (SOCK_DGRAM vs SOCK_STREAM through socket→bind chain)
- `self:` allow rules (capability with specific caps from setuid/setgid/chown/etc., process, unix_stream_socket, tcp_socket, udp_socket, unix_dgram_socket, netlink)
- `manage_*_pattern` macros for runtime directories
- Custom port type generation (port_t + port_type attribute)
- Init script type and `.fc` generation with regex patterns
- /var/run + /run dual alias in .fc generation
- VarRunRule, PathPrefixRule, bind path inference, signal_perms
- MakefileParser, ProjectScanner, SymbolScanner
- Validated against 7 apps: testprog, testprog-net, mcstransd, chronyd, dbus, vsftpd, and libvirt

Future enhancements:
- Interactive tracing mode with live UI
- Multi-session management
- Validation mode (compare against running policy)
- Tree-sitter AST parsing (replacing regex)
- `.if` interface file generation
- Refine command (update policy from audit log)
- Policy archetypes (daemon vs user app vs inetd vs dbus)

## Design Documentation

- [Design Spec](docs/superpowers/specs/2026-03-21-sepgen-design.md) (v1.8)
- [Trace Mode Scope](docs/superpowers/specs/trace-mode-scope.md) — gaps for trace mode
- [Implementation Plan — MVP](docs/superpowers/plans/2026-03-21-sepgen-implementation.md)
- [Implementation Plan — Analyzer Improvements](docs/superpowers/plans/2026-03-22-analyzer-improvements.md)
- [Implementation Plan — Coverage Fixes](docs/superpowers/plans/2026-03-22-coverage-fixes.md)
- [Implementation Plan — Auto-Detection](docs/superpowers/plans/2026-03-22-auto-detection.md)
- [Implementation Plan — Max Static Analysis](docs/superpowers/plans/2026-03-22-max-static-analysis.md)
- [Implementation Plan — General Improvements](docs/superpowers/plans/2026-03-22-general-improvements.md)
- [Implementation Plan — Tier A Gaps](docs/superpowers/plans/2026-03-22-tier-a-gaps.md)
- [Implementation Plan — Final Static Gaps](docs/superpowers/plans/2026-03-22-final-static-gaps.md)
- [mcstransd Analysis Report](testing/mcstrans/ANALYSIS_REPORT.md) — efficiency assessment

## License

TBD

## Author

Pranav Lawate
