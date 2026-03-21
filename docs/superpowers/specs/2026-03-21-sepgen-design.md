# sepgen: SELinux Policy Generator Design Document

**Version:** 1.3
**Date:** 2026-03-22
**Status:** Updated — coverage fixes: cross-file dedup, VarRunRule, bind path inference, --exec-path CLI, signal_perms

---

## 1. Overview

### 1.1 Purpose

sepgen generates SELinux policy modules by analyzing application behavior through two complementary approaches:

1. **Static analysis**: Predict syscalls from source code without execution
2. **Runtime tracing**: Observe actual syscalls using strace

The tool bridges the gap between `audit2allow` (generates raw allow rules) and hand-written policies (uses macros, custom types, file contexts).

### 1.2 Goals

- **Dual-mode operation**: Support both static analysis and runtime tracing
- **Intelligent merging**: Automatically combine results from multiple runs
- **Macro-based output**: Generate idiomatic policy using reference policy macros
- **Custom types**: Create domain-specific types (myapp_conf_t, myapp_data_t)
- **Complete modules**: Output .te (policy) and .fc (file contexts) files
- **Workflow integration**: Part of toolchain with semacro and avc-parser

### 1.3 Non-Goals (MVP)

- Interactive tracing mode with live UI (future enhancement)
- Multi-session management (future enhancement)
- Validation mode against running policy (future enhancement)
- Tree-sitter AST parsing (architecture supports, MVP uses regex)
- .if interface file generation (future enhancement)

---

## 2. High-Level Architecture

### 2.1 System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     User Interface                              │
│  Commands: analyze <source|dir> | trace <binary> [-y] [-v]      │
└────────────┬──────────────────────────┬─────────────────────────┘
             │                          │
    ┌────────▼──────────────┐  ┌────────▼────────┐
    │  Static Analysis      │  │ Runtime Tracing │
    │  Pipeline             │  │    Pipeline     │
    │ ┌───────────────────┐ │  └────────┬────────┘
    │ │ Preprocessor      │ │           │
    │ │ (#define resolve) │ │           │
    │ ├───────────────────┤ │           │
    │ │ IncludeAnalyzer   │ │           │
    │ │ (header inference)│ │           │
    │ ├───────────────────┤ │           │
    │ │ DataFlowAnalyzer  │ │           │
    │ │ (variable paths)  │ │           │
    │ ├───────────────────┤ │           │
    │ │ CAnalyzer         │ │           │
    │ │ (15+ patterns)    │ │           │
    │ ├───────────────────┤ │           │
    │ │ ServiceDetector   │ │           │
    │ │ (.service/.init)  │ │           │
    │ └───────────────────┘ │           │
    └────────┬──────────────┘           │
             │                          │
             └──────────┬───────────────┘
                        │
                ┌───────▼────────┐
                │ Unified Intent │
                │ Classification │
                └───────┬────────┘
                        │
                ┌───────▼────────┐
                │ Policy Object  │
                │ Generation     │
                │ (macros +      │
                │  self: rules)  │
                └───────┬────────┘
                        │
            ┌───────────▼───────────┐
            │ Merge Layer           │
            │ (if previous .te/.fc  │
            │  files exist)         │
            └───────────┬───────────┘
                        │
                ┌───────▼────────┐
                │ Policy Objects │
                │ (PolicyModule, │
                │  FileContexts) │
                └───────┬────────┘
                        │
                ┌───────▼────────┐
                │  Serializer    │
                │ (.te/.fc files)│
                └────────────────┘
```

### 2.2 Core Principles

1. **Separation of modes**: Static and runtime pipelines are independent
2. **Object-based policy model**: Policy is structured objects until final serialization
3. **Automatic merge**: Second run detects existing policy and offers intelligent merge
4. **Extensibility**: Component interfaces allow future enhancements (regex → tree-sitter)
5. **Deterministic classification**: Rule-based intent classification, validated against real policies

---

## 3. Core Components

### 3.1 Static Analysis Pipeline

**Purpose**: Extract predicted syscalls from source code without execution.

**Components**:

- `BaseAnalyzer`: Abstract interface for language-specific analyzers
- `CAnalyzer`: C/C++ source analyzer (regex-based, designed for tree-sitter upgrade)
- `SyscallMapper`: Maps language calls (fopen, socket) to syscalls (open, socket)
- `Preprocessor`: Resolves `#define` string constants before pattern matching
- `IncludeAnalyzer`: Infers capabilities from `#include` headers
- `DataFlowAnalyzer`: Tracks string variable assignments to resolve indirect paths
- `ServiceDetector`: Finds `.service` and `.init` files for exec paths and initrc types

**Design**:

```python
class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze_file(self, path: Path) -> List[Access]:
        """Analyze source file, return predicted accesses"""
        pass

class CAnalyzer(BaseAnalyzer):
    def __init__(self):
        self.mapper = SyscallMapper()
        self.preprocessor = Preprocessor()
        self.include_analyzer = IncludeAnalyzer()
        self.dataflow = DataFlowAnalyzer()

    def analyze_file(self, path: Path) -> List[Access]:
        code = path.read_text()
        return self.analyze_string(code)

    def analyze_directory(self, dir_path: Path) -> List[Access]:
        """Analyze all .c files in a directory recursively"""
        accesses = []
        for c_file in dir_path.rglob("*.c"):
            accesses.extend(self.analyze_file(c_file))
        return accesses

    def analyze_string(self, code: str) -> List[Access]:
        """Full analysis pipeline on a code string"""
        # 1. Resolve #define constants
        defines = self.preprocessor.extract_defines(code)
        expanded = self.preprocessor.expand_macros(code, defines)

        # 2. Extract variable-to-string assignments
        self.dataflow.string_vars = self.dataflow.extract_string_assignments(expanded)

        # 3. Run all detection patterns on expanded code
        accesses = []
        accesses.extend(self._detect_fopen(expanded))
        accesses.extend(self._detect_open(expanded))
        accesses.extend(self._detect_socket(expanded))
        accesses.extend(self._detect_bind(expanded))
        accesses.extend(self._detect_listen(expanded))
        accesses.extend(self._detect_accept(expanded))
        accesses.extend(self._detect_syslog(expanded))
        accesses.extend(self._detect_unlink(expanded))
        accesses.extend(self._detect_chmod(expanded))
        accesses.extend(self._detect_setrlimit(expanded))
        accesses.extend(self._detect_capabilities(expanded))
        accesses.extend(self._detect_daemon(expanded))
        return accesses
```

**Sub-component: Preprocessor**

```python
class Preprocessor:
    DEFINE_PATTERN = re.compile(r'#define\s+(\w+)\s+"([^"]+)"')

    def extract_defines(self, code: str) -> Dict[str, str]:
        """Extract all #define string constants"""

    def expand_macros(self, text: str, defines: Dict[str, str]) -> str:
        """Replace macro names with their quoted string values"""
```

Resolves constants like `#define SETRANS_UNIX_SOCKET "/var/run/setrans/.setrans-unix"` so that downstream patterns can extract the path from `unlink(SETRANS_UNIX_SOCKET)`.

**Sub-component: IncludeAnalyzer**

```python
class IncludeAnalyzer:
    INCLUDE_PATTERN = re.compile(r'#include\s+[<"]([^>"]+)[>"]')

    CAPABILITY_MAP = {
        'syslog.h': ['syslog'],
        'sys/socket.h': ['socket'],
        'sys/capability.h': ['capability', 'process_setcap'],
        'sys/resource.h': ['setrlimit'],
        'signal.h': ['signal_perms'],
    }

    def infer_capabilities(self, code: str) -> List[str]:
        """Infer likely capabilities from included headers"""
```

Provides early hints even when function calls are wrapped in helper functions or macros that the regex-based analyzer cannot follow.

**Sub-component: DataFlowAnalyzer**

```python
class DataFlowAnalyzer:
    VAR_ASSIGN_PATTERN = re.compile(r'(?:const\s+)?char\s*\*\s*(\w+)\s*=\s*"([^"]+)"')

    def extract_string_assignments(self, code: str) -> Dict[str, str]:
        """Extract variable-to-string assignments (e.g. char *path = "/etc/foo")"""

    def resolve_variable(self, var_name: str) -> Optional[str]:
        """Resolve a variable name to its string literal value"""
```

Enables detection of calls like `fopen(config_file, "r")` where `config_file` was assigned a string literal earlier.

**Sub-component: ServiceDetector**

```python
@dataclass
class ServiceInfo:
    has_systemd_service: bool = False
    has_init_script: bool = False
    exec_path: Optional[str] = None
    needs_initrc_exec_t: bool = False

class ServiceDetector:
    def detect_service_files(self, project_dir: Path) -> ServiceInfo:
        """Find .service and .init files, extract exec path"""
```

Examines the source tree alongside `.c` files to find systemd unit files and init scripts, providing the executable path for `.fc` generation and confirming that `_initrc_exec_t` types are needed.

**Detection patterns** (15+ in CAnalyzer):

| Pattern | Function calls detected | AccessType produced |
|---------|------------------------|---------------------|
| File open (fopen) | `fopen()` (literal + variable paths) | `FILE_READ`, `FILE_WRITE` |
| File open (open) | `open()` with O_RDONLY/O_WRONLY/O_CREAT flags | `FILE_READ`, `FILE_WRITE`, `FILE_CREATE` |
| Socket create | `socket(PF_UNIX\|AF_INET\|...)` | `SOCKET_CREATE` (with domain in details) |
| Socket bind | `bind()` (propagates domain from socket) | `SOCKET_BIND` (with domain in details) |
| Socket listen | `listen()` | `SOCKET_LISTEN` |
| Socket accept | `accept()` | `SOCKET_ACCEPT` |
| Syslog | `syslog()`, `openlog()`, `vsyslog()` (deduplicated) | `SYSLOG` |
| File delete | `unlink()`, `remove()` | `FILE_UNLINK` |
| File attributes | `chmod()`, `chown()` | `FILE_SETATTR` |
| Resource limits | `setrlimit()` | `PROCESS_CONTROL` (with `capability: "sys_resource"`) |
| Capabilities | `cap_init()`, `cap_set_proc()`, `cap_get_proc()` | `CAPABILITY` |
| Daemonize | `daemon()` | `DAEMON` |

**Deduplication**: Some patterns (notably syslog) may match dozens of times in a single file. The analyzer deduplicates by emitting only one Access per distinct function name. One `logging_send_syslog_msg()` macro is sufficient regardless of how many `syslog()` calls exist. Cross-file deduplication is performed in `analyze_directory` after aggregating per-file results — duplicate SYSLOG accesses for the same function name are collapsed.

**Bind path inference**: The C idiom `unlink(path); bind(sock, ...)` is standard for Unix sockets — the unlink path IS the socket path. After all detection passes, a post-processing step copies the path from `FILE_UNLINK` accesses on `/var/run/` paths to any `SOCKET_BIND` access with `domain=PF_UNIX`/`AF_UNIX` and an empty path.

**signal_perms from headers**: When `#include <signal.h>` is detected, the analyzer emits a synthetic `PROCESS_CONTROL` access with `details={"process_perm": "signal_perms"}`, which TEGenerator collects into `self:process` permissions.

**Key decisions**:
- Regex parsing for now (handles common patterns, fast to implement)
- Interface designed for tree-sitter swap later
- Preprocessor expands `#define` constants before pattern matching
- DataFlowAnalyzer resolves simple `char *var = "..."` assignments
- Multi-file directory analysis aggregates results across all `.c` files with cross-file dedup
- Post-processing pass infers bind paths from preceding unlink calls
- Returns same `Access` objects as trace pipeline

---

### 3.2 Runtime Tracing Pipeline

**Purpose**: Observe actual syscalls from running application using strace.

**Components**:

- `ProcessTracer`: Execute processes under strace
- `StraceParser`: Parse strace output into Access objects

**Design**:

```python
class ProcessTracer:
    def trace(self, binary: str, args: str = '', pid: int = None) -> Path:
        """Execute strace and return path to output log"""
        cmd = ['strace', '-f', '-e', 'trace=file,network,ipc', '-o', output_file]
        if pid:
            cmd.extend(['-p', str(pid)])
        else:
            cmd.extend([binary] + args.split())

        subprocess.run(cmd)  # Capture output to file
        return output_file

class StraceParser:
    OPEN_PATTERN = re.compile(r'open(?:at)?\("([^"]+)",\s*([^)]+)\)\s*=\s*(\d+|-1)')
    BIND_PATTERN = re.compile(r'bind\(.*sin_port=htons\((\d+)\)')

    def parse_file(self, strace_log: Path) -> List[Access]:
        """Parse strace output line by line"""
        accesses = []
        for line in strace_log.read_text().splitlines():
            accesses.extend(self.parse_line(line))
        return accesses

    def parse_line(self, line: str) -> List[Access]:
        """Extract syscall, path, flags from single line"""
        # Match patterns, create Access objects
```

**Key decisions**:
- Uses `strace -f` (follow forks) for comprehensive coverage
- Ignores failed syscalls (return value -1)
- Output format identical to static analysis (List[Access])
- Handles multi-process traces

---

### 3.3 Intent Classification Engine

**Purpose**: Transform low-level syscalls into high-level security intents.

**Data models**:

```python
class AccessType(Enum):
    # File operations
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_CREATE = "file_create"
    FILE_UNLINK = "file_unlink"
    FILE_SETATTR = "file_setattr"       # chmod, chown
    DIR_READ = "dir_read"
    DIR_WRITE = "dir_write"

    # Socket operations
    SOCKET_CREATE = "socket_create"
    SOCKET_BIND = "socket_bind"
    SOCKET_LISTEN = "socket_listen"
    SOCKET_CONNECT = "socket_connect"
    SOCKET_ACCEPT = "socket_accept"

    # IPC
    IPC_SYSV = "ipc_sysv"
    IPC_POSIX = "ipc_posix"

    # Logging
    SYSLOG = "syslog"                   # openlog/syslog/vsyslog

    # Process/capability operations
    PROCESS_CONTROL = "process_control" # setrlimit, setpriority
    CAPABILITY = "capability"           # cap_init, cap_set_proc
    DAEMON = "daemon"                   # daemon() call

class IntentType(Enum):
    CONFIG_FILE = "config_file"
    PID_FILE = "pid_file"
    DATA_DIR = "data_dir"
    LOG_FILE = "log_file"
    TEMP_FILE = "temp_file"
    NETWORK_SERVER = "network_server"       # AF_INET/PF_INET bind
    NETWORK_CLIENT = "network_client"
    UNIX_SOCKET_SERVER = "unix_socket_server"  # PF_UNIX/AF_UNIX bind
    SYSLOG = "syslog"
    SELF_CAPABILITY = "self_capability"     # capability + process rules
    DAEMON_PROCESS = "daemon_process"       # confirms init_daemon_domain
    TERMINAL_IO = "terminal_io"
    SHARED_LIBRARY = "shared_library"
    UNKNOWN = "unknown"

@dataclass
class Access:
    """Raw system access (from analyzer or tracer)"""
    access_type: AccessType     # FILE_READ, SOCKET_BIND, SYSLOG, etc.
    path: str                   # File path or "tcp:8080"
    syscall: str                # "open", "bind", "socket"
    details: Dict[str, Any]     # Flags, ports, domain, capability, etc.
    source_file: Optional[str]  # File where access was found
    source_line: Optional[int]  # Line number in source

@dataclass
class Intent:
    """Classified security intent"""
    intent_type: IntentType         # CONFIG_FILE, PID_FILE, UNIX_SOCKET_SERVER
    accesses: List[Access]          # All accesses for this intent
    confidence: float = 1.0         # Always 1.0 for deterministic rules
    selinux_type: Optional[str]     # e.g., "myapp_conf_t"
    macros: List[str]               # e.g., ["read_files_pattern"]
```

**Classification logic**:

```python
class IntentClassifier:
    def __init__(self):
        self.rules = [
            VarRunRule(),            # /var/run/** + unlink/chmod/write → PID_FILE
            PidFileRule(),           # /var/run/*.pid + write → PID_FILE
            ConfigFileRule(),        # /etc/** + read → CONFIG_FILE
            DataDirRule(),           # /var/*/data/** + write → DATA_DIR
            SyslogRule(),            # SYSLOG access type → SYSLOG
            UnixSocketRule(),        # SOCKET_BIND + PF_UNIX → UNIX_SOCKET_SERVER
            NetworkServerRule(),     # SOCKET_BIND + AF_INET → NETWORK_SERVER
            SelfCapabilityRule(),    # CAPABILITY/PROCESS_CONTROL → SELF_CAPABILITY
            DaemonProcessRule(),     # DAEMON → DAEMON_PROCESS
        ]

    def classify(self, accesses: List[Access]) -> List[Intent]:
        """Apply rules in order, first match wins"""
        intents = []
        for access in accesses:
            for rule in self.rules:
                if rule.matches(access):
                    intents.append(Intent(
                        intent_type=rule.get_intent_type(),
                        accesses=[access],
                        confidence=rule.get_confidence()
                    ))
                    break
            else:
                intents.append(Intent(
                    intent_type=IntentType.UNKNOWN,
                    accesses=[access],
                    confidence=0.5
                ))
        return intents
```

**Classification rules (deterministic)**:

| Rule | Condition | IntentType |
|------|-----------|------------|
| VarRunRule | `/var/run/**` or `/run/**` + unlink/chmod/write/create | PID_FILE |
| PidFileRule | `/var/run/*.pid` + write | PID_FILE |
| ConfigFileRule | `/etc/**` + read, `*.conf`, `*.cfg`, etc. | CONFIG_FILE |
| DataDirRule | `/var/*/data/**` + write | DATA_DIR |
| SyslogRule | `access_type == SYSLOG` | SYSLOG |
| UnixSocketRule | `SOCKET_BIND` + domain in `[PF_UNIX, AF_UNIX]` | UNIX_SOCKET_SERVER |
| NetworkServerRule | `SOCKET_BIND` + domain in `[AF_INET, PF_INET, AF_INET6]` | NETWORK_SERVER |
| SelfCapabilityRule | `access_type in [CAPABILITY, PROCESS_CONTROL]` | SELF_CAPABILITY |
| DaemonProcessRule | `access_type == DAEMON` | DAEMON_PROCESS |

---

### 3.4 Policy Generation Layer

**Purpose**: Transform classified intents into SELinux policy objects.

**Data models**:

```python
@dataclass
class PolicyModule:
    """Structured representation of .te policy file"""
    name: str
    version: str
    types: List[TypeDeclaration]
    allow_rules: List[AllowRule]
    macro_calls: List[MacroCall]

    def merge(self, other: 'PolicyModule', strategy: str = "trace-wins"):
        """Merge another policy, handling conflicts"""
        pass

@dataclass
class FileContexts:
    """Structured representation of .fc file"""
    entries: List[FileContextEntry]

    def merge(self, other: 'FileContexts'):
        """Merge file contexts (union, no conflicts expected)"""
        pass
```

**Generators**:

```python
class TEGenerator:
    def __init__(self, module_name: str):
        self.module_name = module_name
        self.type_generator = TypeGenerator()
        self.macro_lookup = MacroLookup()

    def generate(self, intents: List[Intent], service_info=None) -> PolicyModule:
        """Generate PolicyModule from classified intents and optional ServiceInfo"""
        policy = PolicyModule(name=self.module_name, version="1.0.0")

        # Add base types
        policy.add_type(f"{self.module_name}_t")
        policy.add_type(f"{self.module_name}_exec_t")
        policy.add_macro("init_daemon_domain", [
            f"{self.module_name}_t", f"{self.module_name}_exec_t"
        ])

        for intent in intents:
            # Generate custom type if needed
            custom_type = self.type_generator.generate_type_name(
                self.module_name, intent
            )
            if custom_type:
                policy.add_type(custom_type)
                intent.selinux_type = custom_type

                # Add type-specific declaration macros
                if "_var_run_t" in custom_type:
                    policy.add_macro("files_pid_file", [custom_type])
                    policy.add_macro("files_pid_filetrans", [
                        f"{self.module_name}_t", custom_type, "{{ file dir }}"
                    ])
                    # Manage macros for runtime directory access
                    policy.add_macro("manage_dirs_pattern", [
                        f"{self.module_name}_t", custom_type, custom_type
                    ])
                    policy.add_macro("manage_files_pattern", [
                        f"{self.module_name}_t", custom_type, custom_type
                    ])
                elif intent.intent_type.value in ['config_file', 'data_dir']:
                    policy.add_macro("files_type", [custom_type])

            # Lookup appropriate macro for the intent
            macro = self.macro_lookup.suggest_macro(intent)
            if macro:
                policy.add_macro(macro, [...])

        # Collect self: rule permissions across all intents
        cap_perms = set()
        process_perms = set()
        has_unix_socket = False

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

            elif intent.intent_type == IntentType.UNIX_SOCKET_SERVER:
                has_unix_socket = True

        # Emit consolidated self: rules
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
            # If var_run type exists, also add sock file management
            for intent in intents:
                if intent.selinux_type and "_var_run_t" in intent.selinux_type:
                    policy.add_macro("manage_sock_files_pattern", [
                        f"{self.module_name}_t", intent.selinux_type, intent.selinux_type
                    ])

        # If init script detected via ServiceInfo, add initrc type
        if service_info and service_info.needs_initrc_exec_t:
            initrc_type = f"{self.module_name}_initrc_exec_t"
            policy.add_type(initrc_type)
            policy.add_macro("init_script_file", [initrc_type])

        return policy

class FCGenerator:
    def __init__(self, module_name: str, exec_path: Optional[str] = None):
        self.module_name = module_name
        self.exec_path = exec_path

    def generate(self, intents: List[Intent], service_info=None) -> FileContexts:
        """Generate FileContexts from intents, known paths, and service info"""
        contexts = FileContexts()

        # Add executable context
        if self.exec_path:
            contexts.add_entry(self.exec_path, f"{self.module_name}_exec_t")

        # Add initrc context from service detection
        if service_info and service_info.has_init_script:
            contexts.add_entry(
                f"/etc/rc.d/init.d/{self.module_name}",
                f"{self.module_name}_initrc_exec_t"
            )

        # Add paths from classified intents
        for intent in intents:
            if not intent.selinux_type:
                continue
            for access in intent.accesses:
                if access.path and access.path.startswith("/"):
                    fc_path = self._path_to_fc_regex(access.path, intent.selinux_type)
                    contexts.add_entry(fc_path, intent.selinux_type)

        return contexts

    def _path_to_fc_regex(self, path: str, selinux_type: str) -> str:
        """Convert paths to .fc regex patterns.

        Runtime dirs (var_run_t) get regex for the parent directory
        (e.g., /run/setrans(/.*)?) since SELinux labels directory trees.
        """
        if "_var_run_t" in selinux_type:
            # Generate regex for directory tree
            parts = Path(path).parts
            for i, part in enumerate(parts):
                if part in ("run", "var"):
                    if i + 1 < len(parts) and parts[i + 1] != "run":
                        return "/".join(parts[:i + 2]) + "(/.*)?"
                    elif i + 2 < len(parts):
                        return "/".join(parts[:i + 3]) + "(/.*)?"
        return path
```

**Type generation rules**:

| Intent | Generated type | Declaration macro |
|--------|---------------|-------------------|
| (base) | `{module}_t` | — |
| (base) | `{module}_exec_t` | `init_daemon_domain()` |
| CONFIG_FILE | `{module}_conf_t` | `files_type()` |
| PID_FILE | `{module}_var_run_t` | `files_pid_file()` + `files_pid_filetrans()` + `manage_dirs_pattern()` + `manage_files_pattern()` |
| PID_FILE + UNIX_SOCKET_SERVER | `{module}_var_run_t` | Above + `manage_sock_files_pattern()` |
| DATA_DIR | `{module}_data_t` | `files_type()` |
| LOG_FILE | `{module}_log_t` | `logging_log_file()` |
| DAEMON_PROCESS | (confirms `init_daemon_domain` is correct) | — |
| ServiceInfo (init script) | `{module}_initrc_exec_t` | `init_script_file()` |

**self: allow rule generation**:

Rules are collected across all intents and emitted as consolidated allow statements (one `self:capability`, one `self:process`, one `self:unix_stream_socket`):

| IntentType / Source | Generated allow rule |
|------------|---------------------|
| SELF_CAPABILITY (setrlimit) | `allow {mod}_t self:capability sys_resource;` |
| SELF_CAPABILITY (setrlimit) | `allow {mod}_t self:process setrlimit;` (companion) |
| SELF_CAPABILITY (cap_*) | `allow {mod}_t self:process { getcap setcap };` |
| UNIX_SOCKET_SERVER | `allow {mod}_t self:unix_stream_socket { create bind listen accept };` |

---

### 3.5 Merge Layer

**Purpose**: Compare existing policy with newly generated policy, handle conflicts.

**Workflow**:

```python
class PolicyMerger:
    def detect_existing_policy(self, module_name: str) -> Tuple[Path, Path]:
        """Check if .te and .fc files already exist"""
        te_path = Path(f"{module_name}.te")
        fc_path = Path(f"{module_name}.fc")
        return (te_path if te_path.exists() else None,
                fc_path if fc_path.exists() else None)

    def load_existing_policy(self, te_path: Path) -> PolicyModule:
        """Parse existing .te file using semacro parser"""
        from semacro.parser import parse_te_file
        return parse_te_file(te_path)

    def compare(self, existing: PolicyModule, new: PolicyModule) -> MergeReport:
        """Identify matched, new, and conflicting rules"""
        return MergeReport(
            matched_rules=[...],     # Present in both
            existing_only=[...],     # Only in existing (static-only)
            new_only=[...],          # Only in new (trace-only)
            conflicts=[...]          # Same target, different permissions
        )

    def merge(self, existing: PolicyModule, new: PolicyModule,
              strategy: str = "trace-wins", auto_approve: bool = False) -> PolicyModule:
        """Merge policies according to strategy"""
        report = self.compare(existing, new)

        # Handle conflicts
        if not auto_approve and report.conflicts:
            for conflict in report.conflicts:
                response = self._prompt_user(conflict)
                if response == "trace":
                    existing.update_rule(conflict.new_rule)
                elif response == "skip":
                    continue
        else:
            # Auto-approve: trace wins
            for conflict in report.conflicts:
                existing.update_rule(conflict.new_rule)

        # Add new rules
        for rule in report.new_only:
            existing.add_rule(rule)

        return existing
```

**Merge strategies**:

1. **Conflict detection**: Same SELinux type/class, different permissions
2. **Trace-wins resolution**: On conflict, runtime behavior is ground truth
3. **Interactive mode** (default): Show conflicts, ask for confirmation
4. **Auto-approve mode** (`-y` flag): No prompts, trace always wins

**Interactive prompt format**:
```
Conflict: /etc/myapp.conf
  Static: read_files_pattern()
  Trace:  manage_files_pattern() [read+write+create]
  Use trace result? [Y/n/skip]
```

---

### 3.6 Serialization Layer

**Purpose**: Convert policy objects to .te and .fc file formats.

**Writers**:

```python
class TEWriter:
    def write(self, policy: PolicyModule, output_path: Path):
        """Serialize PolicyModule to .te file"""
        lines = []

        # Header
        lines.append(f"policy_module({policy.name}, {policy.version})")
        lines.append("")

        # Type declarations
        lines.append("########################################")
        lines.append("# Declarations")
        lines.append("########################################")
        for type_decl in policy.types:
            lines.append(str(type_decl))
        lines.append("")

        # Policy rules
        lines.append("########################################")
        lines.append("# Policy")
        lines.append("########################################")
        for macro in policy.macro_calls:
            lines.append(str(macro))
        for rule in policy.allow_rules:
            lines.append(str(rule))

        output_path.write_text("\n".join(lines))

class FCWriter:
    def write(self, contexts: FileContexts, output_path: Path):
        """Serialize FileContexts to .fc file"""
        lines = []
        for entry in sorted(contexts.entries, key=lambda e: e.path):
            lines.append(f"{entry.path}\t\tgen_context(system_u:object_r:{entry.type},s0)")
        output_path.write_text("\n".join(lines) + "\n")
```

**Key decisions**:
- Clean, deterministic output
- No format preservation (sepgen-generated files only)
- Standard SELinux formatting conventions
- Sorted entries for predictable diffs

---

### 3.7 SELinux Integration

**Purpose**: Interface with SELinux system and semacro for macro lookup.

**Macro lookup (hybrid approach)**:

```python
class MacroLookup:
    # Hardcoded mappings for common patterns (fast path)
    KNOWN_MAPPINGS = {
        IntentType.SYSLOG: "logging_send_syslog_msg",
        IntentType.PID_FILE: "files_pid_filetrans",
        IntentType.CONFIG_FILE: "read_files_pattern",
        IntentType.LOG_FILE: "logging_log_file",
        IntentType.NETWORK_SERVER: "corenet_tcp_bind_generic_node",
        IntentType.DATA_DIR: "manage_files_pattern",
    }

    # Intent types that produce self: allow rules instead of macros
    SELF_RULE_INTENTS = {
        IntentType.UNIX_SOCKET_SERVER,
        IntentType.SELF_CAPABILITY,
    }

    # Intent types that confirm existing macros rather than adding new ones
    CONFIRMATION_INTENTS = {
        IntentType.DAEMON_PROCESS,  # confirms init_daemon_domain is correct
    }

    def suggest_macro(self, intent: Intent) -> Optional[str]:
        """Hardcoded first, semacro fallback"""
        if intent.intent_type in self.SELF_RULE_INTENTS:
            return None  # handled by TEGenerator as allow rules

        if intent.intent_type in self.CONFIRMATION_INTENTS:
            return None  # no new macro needed

        if intent.intent_type in self.KNOWN_MAPPINGS:
            return self.KNOWN_MAPPINGS[intent.intent_type]

        # Fallback to semacro
        if self.semacro_available:
            from semacro import search_macros
            results = search_macros(intent_type=intent.intent_type.value)
            return results[0] if results else None

        return None
```

Note on `NETWORK_SERVER` vs `UNIX_SOCKET_SERVER`: The `corenet_tcp_bind_generic_node` macro only applies to TCP/UDP sockets (`AF_INET`, `PF_INET`, `AF_INET6`). Unix domain sockets (`PF_UNIX`, `AF_UNIX`) produce `self:unix_stream_socket` allow rules instead, which are generated directly by `TEGenerator`.

**Type generation**:

```python
class TypeGenerator:
    TYPE_MAPPING = {
        IntentType.CONFIG_FILE: "{module}_conf_t",
        IntentType.PID_FILE: "{module}_var_run_t",
        IntentType.DATA_DIR: "{module}_data_t",
        IntentType.LOG_FILE: "{module}_log_t",
    }

    def generate_type_name(self, module_name: str, intent: Intent) -> Optional[str]:
        """Create type name based on intent"""
        template = self.TYPE_MAPPING.get(intent.intent_type)
        if template:
            return template.format(module=module_name)

        # Path-based fallback: /var/run/** paths get _var_run_t
        path = intent.accesses[0].path if intent.accesses else ""
        if path.startswith(("/var/run/", "/run/")):
            return f"{module_name}_var_run_t"

        return None
```

**Integration points**:
- **semacro**: Required dependency for .te parsing and macro lookup
- **libselinux-python**: Optional for `matchpathcon()` (graceful degradation)

---

### 3.8 Error Handling Strategy

**Approach**: Best effort with summary + error log.

**Implementation**:

```python
class ErrorCollector:
    def __init__(self):
        self.errors: List[ProcessingError] = []
        self.successes: int = 0
        self.error_log_path = Path(f"/tmp/sepgen-errors-{timestamp}.log")

    def add_error(self, error: ProcessingError):
        """Record error, log immediately, continue processing"""
        logger.warning(f"[WARN] {error.message}")
        self.errors.append(error)

    def show_summary(self):
        """Display summary at end"""
        print(f"\nSummary:")
        print(f"  ✓ Successfully processed: {self.successes} items")
        if self.errors:
            print(f"  ✗ Failed: {len(self.errors)} items")
            print(f"  → See details: {self.error_log_path}")
```

**Error scenarios**:

| Scenario | Behavior |
|----------|----------|
| Can't parse C file | Skip file, log error, continue with other files |
| Unknown function call | Skip call, continue parsing |
| strace crashes | Parse partial output before crash |
| Application crashes during trace | Parse captured syscalls |
| Can't parse existing .te | Offer to backup and regenerate |
| SELinux not enabled | Warn, skip `matchpathcon()`, use heuristics |

**Output with errors**:
```
[1/4] Tracing process... ✓
[WARN] Failed to parse syscall on line 142: unknown format
[2/4] Parsing 46/47 syscalls... ✓
[3/4] Classifying intents... ✓
[4/4] Generating policy... ✓

Summary:
  ✓ Successfully processed: 46/47 syscalls
  ✗ Failed: 1 syscall (unknown format)
  → Generated policy from available data
  → See details: /tmp/sepgen-errors-20260321-153042.log

Generated: myapp.te (23 lines), myapp.fc (4 entries)
```

---

### 3.9 CLI Interface & User Experience

**Commands**:

```bash
sepgen analyze <source-path-or-directory> [--name MODULE_NAME] [--exec-path /usr/sbin/app] [-v] [-vv]
sepgen trace <binary> [--args "ARGS"] [--pid PID] [-v] [-vv] [-y]
```

When `<source-path-or-directory>` is a directory, all `.c` files are analyzed recursively and results are aggregated. Service files (`.service`, `.init`) are also detected in the directory tree. The `--exec-path` argument provides the installed binary path for `.fc` entry generation; if omitted, the analyzer tries to infer it from `.service` files.

**Verbosity levels**:

| Flag | Level | Output |
|------|-------|--------|
| (none) | Normal | Progress indicators only |
| `-v` | Verbose | Show intents, types, macros |
| `-vv` | Debug | Everything including internals |

**Example output (normal)**:
```
[1/4] Tracing process... ✓
[2/4] Parsing 47 syscalls... ✓
[3/4] Classifying 15 intents... ✓
[4/4] Generating policy... ✓
Generated: myapp.te (23 lines), myapp.fc (4 entries)
```

**Example output (verbose, `-v`)**:
```
[1/4] Tracing process... ✓
  Command: strace -f -e trace=file,network,ipc /usr/bin/myapp
  Captured: 47 syscalls

[2/4] Parsing 47 syscalls... ✓
  File accesses: 12
  Network calls: 3

[3/4] Classifying 15 intents... ✓
  • CONFIG_FILE: /etc/myapp.conf
  • PID_FILE: /var/run/myapp.pid
  • NETWORK_SERVER: tcp:8080
  • SYSLOG: /dev/log

[4/4] Generating policy... ✓
  Generated types: myapp_t, myapp_conf_t, myapp_var_run_t, myapp_initrc_exec_t
  Applied macros: logging_send_syslog_msg, files_pid_filetrans,
    manage_dirs_pattern, manage_files_pattern, init_script_file
  Self rules: self:capability { sys_resource }, self:process { setrlimit }

Generated: myapp.te (23 lines), myapp.fc (4 entries)
```

**Auto-merge workflow**:

First run (analyze):
```bash
$ sepgen analyze ./src/myapp.c
[1/3] Analyzing source... ✓
[2/3] Classifying intents... ✓
[3/3] Generating policy... ✓
Generated: myapp.te, myapp.fc
```

Second run (trace, detects existing policy):
```bash
$ sepgen trace /usr/bin/myapp

Found existing policy: myapp.te (from static analysis, 23 lines)
Comparing with runtime trace...

Comparison:
  Static analysis: 12 intents
  Runtime trace:   15 intents
  Matched:        10 intents
  Static-only:     2 intents (code paths not exercised?)
  Trace-only:      5 intents (glibc internals, dynamic loading)

Conflicts found: 1
  • /etc/myapp.conf
    Static: read_files_pattern()
    Trace:  manage_files_pattern() [read+write+create]

Merge with trace results? [Y/n/diff]
```

With `-y` flag (auto-approve):
```bash
$ sepgen trace /usr/bin/myapp -y

Found existing policy: myapp.te
[1/4] Tracing process... ✓
[2/4] Parsing syscalls... ✓
[3/4] Classifying intents... ✓
[4/4] Merging policies (auto-approved)... ✓
  Merged 15 intents (1 conflict, trace won)
  Backup saved: myapp.te.backup

Generated: myapp.te (27 lines), myapp.fc (6 entries)
```

---

### 3.10 Testing Strategy

**Test levels**:

```
tests/
├── analyzer/
│   ├── test_c_analyzer.py
│   ├── test_syscall_mapper.py
│   ├── test_syslog_detection.py
│   ├── test_socket_server_detection.py
│   ├── test_define_resolution.py
│   ├── test_file_manipulation.py      # unlink, chmod, open
│   ├── test_socket_types.py
│   ├── test_include_analysis.py
│   ├── test_capability_detection.py
│   ├── test_daemon_detection.py
│   ├── test_variable_tracking.py
│   └── test_service_detection.py
├── tracer/
│   ├── test_strace_parser.py
│   └── test_process_tracer.py
├── intent/
│   ├── test_classifier.py
│   └── test_rules.py
├── selinux/
│   ├── test_macro_lookup.py
│   └── test_type_generator.py
├── generator/
│   ├── test_te_generator.py
│   ├── test_fc_generator.py
│   ├── test_fc_from_analysis.py
│   ├── test_var_run_types.py
│   ├── test_self_rules.py
│   └── test_writers.py
├── merger/
│   └── test_policy_merger.py
├── integration/
│   ├── test_e2e.py
│   ├── test_multi_file_analysis.py
│   └── test_mcstransd_coverage.py
├── fixtures/
│   ├── sample_c_program.c
│   └── strace_output.txt
└── models/
    ├── test_access.py
    ├── test_intent.py
    └── test_policy.py
```

**TDD approach**:
1. Write failing test
2. Implement minimal code to pass
3. Refactor
4. Commit after each component

**Key test scenarios**:
- Parse sample C program → verify predicted syscalls
- Parse fixture strace output → verify Access objects
- Known access patterns → verify correct intent classification
- Known intents → verify PolicyModule structure
- Two PolicyModule objects with conflicts → verify trace-wins merge
- End-to-end: C program → analyze → trace → merge → verify .te/.fc

---

## 4. Data Flow

### 4.1 Analyze Workflow

```
Source Code (file or directory)
    ↓
[If directory]
    ServiceDetector.detect_service_files()  → exec_path, initrc type hints
    CAnalyzer.analyze_directory()           → iterates all .c files
[If single file]
    CAnalyzer.analyze_file()
    ↓
Per-file pipeline:
    Preprocessor.extract_defines()          → resolve #define constants
    Preprocessor.expand_macros()            → substitute into code
    DataFlowAnalyzer.extract_string_assignments() → resolve variable paths
    IncludeAnalyzer.infer_capabilities()    → supplementary hints from headers
    CAnalyzer detection patterns (15+)      → extract function calls
    ↓
List[Access] (aggregated predicted syscalls from all files)
    ↓
IntentClassifier.classify()
    ↓
List[Intent] (classified intents)
    ↓
TEGenerator.generate(intents, service_info) → PolicyModule object
    (types + macros + manage_*_pattern + self: rules + initrc type)
FCGenerator.generate(intents, service_info) → FileContexts object
    (exec path + initrc entry + regex patterns for var_run dirs)
    ↓
Check for existing .te/.fc files
    ↓
[If none exist]
    TEWriter.write() → myapp.te
    FCWriter.write() → myapp.fc
[If exist]
    → Go to Merge Workflow
```

### 4.2 Trace Workflow

```
Binary + Args
    ↓
ProcessTracer.trace()
    ↓
strace output file
    ↓
StraceParser.parse_file()
    ↓
List[Access] (observed syscalls)
    ↓
IntentClassifier.classify()
    ↓
List[Intent] (classified intents)
    ↓
TEGenerator.generate() → PolicyModule object
FCGenerator.generate() → FileContexts object
    ↓
Check for existing .te/.fc files
    ↓
[If none exist]
    TEWriter.write() → myapp.te
    FCWriter.write() → myapp.fc
[If exist]
    → Go to Merge Workflow
```

### 4.3 Merge Workflow

```
PolicyModule (new) + PolicyModule (existing)
    ↓
PolicyMerger.compare()
    ↓
MergeReport (matched, new, conflicts)
    ↓
[If conflicts and not -y flag]
    Show conflicts
    Prompt user for each conflict
    Apply user choices
[If conflicts and -y flag]
    Auto-approve (trace wins)
    ↓
PolicyMerger.merge()
    ↓
PolicyModule (merged)
    ↓
Backup existing files (.te.backup, .fc.backup)
    ↓
TEWriter.write() → myapp.te (updated)
FCWriter.write() → myapp.fc (updated)
```

---

## 5. Dependencies

### 5.1 Required

| Package | Source | Purpose |
|---------|--------|---------|
| `semacro` | PyPI | .te parsing, macro lookup |
| `strace` | System | Syscall tracing |
| `python3` | System | Runtime (>= 3.9) |

### 5.2 Optional

| Package | Source | Purpose | Fallback |
|---------|--------|---------|----------|
| `python3-libselinux` | System | `matchpathcon()` | Heuristic type guessing |
| `policycoreutils-devel` | System | `checkmodule` validation | Skip validation |

### 5.3 Future Enhancements

| Package | Source | Purpose |
|---------|--------|---------|
| `tree-sitter` | PyPI | AST-based C/Python parsing |
| `rich` | PyPI | Interactive mode UI |

---

## 6. Future Enhancements

These features are documented for future development but not in the MVP:

### 6.1 Interactive Tracing Mode
- Live terminal UI showing captured accesses
- Coverage suggestions during tracing
- User prompts to exercise different code paths

### 6.2 Multi-Session Management
- Save multiple tracing sessions
- Merge sessions with deduplication
- Coverage gap analysis across sessions

### 6.3 Validation Mode
- Run app in permissive mode
- Collect AVC denials via `ausearch`
- Compare against generated policy
- Report coverage gaps

### 6.4 Tree-sitter Integration
- Replace regex with AST parsing
- Accurate function call resolution
- Control flow tracking
- Extract port numbers from bind() calls

### 6.5 .if Interface Generation
- Generate interface macros for other modules
- Export domain transition interfaces
- File context labeling interfaces

---

## 7. Success Criteria

The implementation is successful when:

1. ✅ `sepgen analyze` generates valid .te and .fc files from C source
2. ✅ `sepgen trace` generates valid .te and .fc files from binary execution
3. ✅ Second run detects existing policy and offers merge
4. ✅ Merge handles conflicts with trace-wins strategy
5. ✅ `-y` flag auto-approves merge
6. ✅ `-v` flag shows detailed information
7. ✅ Generated policy uses macros (not raw allow rules)
8. ✅ Generated policy includes custom types
9. ✅ Error handling shows summary with actionable messages
10. ✅ All core components have unit test coverage
11. ✅ End-to-end integration tests pass

---

## 8. Implementation Notes

### 8.1 Development Priorities

1. **Phase 1**: Core pipeline (analyze/trace → classify → generate)
2. **Phase 2**: Merge layer with conflict detection
3. **Phase 3**: CLI polish (verbosity, error handling)
4. **Phase 4**: Testing and validation with real policies

### 8.2 Validation Against Real Policies

As development progresses, validate classification rules and type generation against existing policies in `/usr/share/selinux/devel/include/`. This ensures generated policies match community conventions.

**Primary validation target**: `mcstransd` (SELinux MCS label translation daemon)
- Source: `testing/mcstrans/src/` (copied from `selinux/mcstrans/src/`)
- Reference policy: `testing/mcstrans/reference-policy/setrans.{te,fc,if}` (from `selinux-policy`)
- Baseline report: `testing/mcstrans/ANALYSIS_REPORT.md`
- Coverage target: 60-70% of reference policy (up from ~8% baseline)

### 8.3 Component Interfaces

All component interfaces (BaseAnalyzer, IntentRule, MacroLookup) are designed for extensibility:
- Swap RegexParser → TreeSitterParser
- Add PythonAnalyzer alongside CAnalyzer
- Add custom classification rules
- Extend macro lookup logic

---

**Document Status**: Ready for implementation planning
