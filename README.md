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

1. **Static analysis** (primary) — Reads your source code, identifies syscall
   patterns (`fopen`, `socket`, `bind`), and predicts what the application will
   access at runtime. No execution needed.

2. **Runtime tracing** (supplementary) — Traces the compiled binary with
   `strace` to observe actual syscalls. Use this when source code is unavailable
   or to validate and strengthen the policy generated from static analysis.

Both pipelines feed into the same intent classification engine, which maps
low-level accesses to high-level security intents and generates complete,
macro-based policy modules.

```bash
# Primary: generate policy from source code
sepgen analyze ./src/myapp.c --name myapp

# Supplementary: trace binary to validate/strengthen the policy
sepgen trace /usr/bin/myapp -y
```

Output: `myapp.te`, `myapp.fc` — ready to compile and install.

### What sepgen generates vs audit2allow

| Access observed | audit2allow | sepgen |
|---|---|---|
| Write to `/var/run/app.pid` | `allow app_t var_run_t:file write;` | Creates `app_var_run_t`, uses `files_pid_filetrans()` |
| Read `/etc/app.conf` | `allow app_t etc_t:file read;` | Creates `app_conf_t`, uses `read_files_pattern()` |
| Write to `/var/app/data.txt` | `allow app_t var_t:file { create write };` | Creates `app_data_t`, uses `manage_files_pattern()` |
| Syslog socket | `allow app_t devlog_t:sock_file write;` + 3 more rules | `logging_send_syslog_msg(app_t)` |
| Bind TCP port | `allow app_t port_t:tcp_socket name_bind;` | `corenet_tcp_bind_generic_port(app_t)` + port type |
| `.fc` file | *(never generated)* | Full file context mapping |

## Usage

### Analyze: Generate policy from source code

```bash
# Analyze a C source file
sepgen analyze ./src/myapp.c --name myapp

# Analyze with verbose output (shows classified intents)
sepgen analyze ./src/myapp.c --name myapp -v

# Analyze with debug output
sepgen analyze ./src/myapp.c --name myapp -vv
```

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
  • network_server: tcp:8080
[3/3] Generating policy... ✓
Generated: myapp.te (5 types), myapp.fc (3 entries)
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

## How It Works

```
  ┌────────────────┐                  ┌─────────────────┐
  │  Source Code    │                  │  Application    │
  │  (.c files)    │                  │  Binary         │
  └───────┬────────┘                  └────────┬────────┘
          │ CAnalyzer                          │ strace -f
          │ (regex patterns)                   │
          ▼                                    ▼
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

| Access Pattern | Intent | Custom Type | Macro |
|---|---|---|---|
| `/var/run/*.pid` + write | PID_FILE | `{module}_var_run_t` | `files_pid_filetrans()` |
| `/etc/**` + read | CONFIG_FILE | `{module}_conf_t` | `read_files_pattern()` |
| `/var/*/data/**` + write | DATA_DIR | `{module}_data_t` | `manage_files_pattern()` |
| `/dev/log` + connect | SYSLOG | — | `logging_send_syslog_msg()` |
| `bind()` | NETWORK_SERVER | — | `corenet_tcp_bind_generic_node()` |

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

**Phase:** MVP Complete

Implemented:
- Core data models (Access, Intent, PolicyModule, FileContexts)
- Static analysis pipeline (C analyzer with regex-based parsing)
- Syscall mapper (C library function → syscall translation)
- Runtime tracing pipeline (strace parser, process tracer)
- Intent classification engine with deterministic rules
- SELinux type generator and hybrid macro lookup
- Policy generation (.te) and file context generation (.fc)
- Policy serialization (TEWriter, FCWriter)
- Merge layer with conflict detection and trace-wins strategy
- CLI with `analyze` and `trace` commands
- End-to-end integration tests

Future enhancements:
- Interactive tracing mode with live UI
- Multi-session management
- Validation mode (compare against running policy)
- Tree-sitter AST parsing (replacing regex)
- `.if` interface file generation
- Refine command (update policy from audit log)

## Design Documentation

- [Design Spec](docs/superpowers/specs/2026-03-21-sepgen-design.md)
- [Implementation Plan](docs/superpowers/plans/2026-03-21-sepgen-implementation.md)

## License

TBD

## Author

Pranav Lawate
