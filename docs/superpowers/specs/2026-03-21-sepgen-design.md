# sepgen: SELinux Policy Generator Design Document

**Version:** 1.0
**Date:** 2026-03-21
**Status:** Approved for Implementation

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
┌──────────────────────────────────────────────────────────────┐
│                     User Interface                           │
│  Commands: analyze <source> | trace <binary> [-y] [-v]       │
└────────────┬─────────────────────────┬────────────────────────┘
             │                         │
    ┌────────▼────────┐       ┌────────▼────────┐
    │ Static Analysis │       │ Runtime Tracing │
    │    Pipeline     │       │    Pipeline     │
    └────────┬────────┘       └────────┬────────┘
             │                         │
             └──────────┬──────────────┘
                        │
                ┌───────▼────────┐
                │ Unified Intent │
                │  Classification│
                └───────┬────────┘
                        │
                ┌───────▼────────┐
                │ Policy Object  │
                │  Generation    │
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
- `CAnalyzer`: C/C++ source analyzer (MVP: regex-based, designed for tree-sitter upgrade)
- `SyscallMapper`: Maps language calls (fopen, socket) to syscalls (open, socket)

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
        self.parser = RegexParser()  # Swappable with TreeSitterParser later

    def analyze_file(self, path: Path) -> List[Access]:
        code = path.read_text()
        function_calls = self.parser.extract_calls(code)
        return [self.mapper.map_to_syscall(call) for call in function_calls]

class SyscallMapper:
    """Direct mapping only for MVP"""
    DIRECT_MAPPINGS = {
        'fopen': 'open',
        'socket': 'socket',
        'bind': 'bind',
        'connect': 'connect',
    }

    def map_to_syscall(self, function_call: FunctionCall) -> Access:
        syscall_name = self.DIRECT_MAPPINGS.get(function_call.name)
        # Extract args, determine access type, return Access object
```

**Key decisions**:
- Regex parsing for MVP (handles common patterns, fast to implement)
- Interface designed for tree-sitter swap later
- Direct syscall mappings only (no complex library call expansion)
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
@dataclass
class Access:
    """Raw system access (from analyzer or tracer)"""
    access_type: AccessType     # FILE_READ, SOCKET_BIND, etc.
    path: str                   # File path or "tcp:8080"
    syscall: str                # "open", "bind", "socket"
    details: Dict[str, Any]     # Flags, ports, etc.
    source_line: Optional[int]  # For static analysis

@dataclass
class Intent:
    """Classified security intent"""
    intent_type: IntentType         # CONFIG_FILE, PID_FILE, NETWORK_SERVER
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
            PidFileRule(),      # /var/run/*.pid + write → PID_FILE
            ConfigFileRule(),   # /etc/** + read → CONFIG_FILE
            DataDirRule(),      # /var/*/data/** + write → DATA_DIR
            SyslogRule(),       # /dev/log + connect → SYSLOG
            NetworkServerRule(), # bind() → NETWORK_SERVER
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
                        confidence=1.0
                    ))
                    break
        return intents
```

**Classification rules (deterministic)**:
- `/var/run/*.pid` + write → PID_FILE
- `/etc/**` + read → CONFIG_FILE
- `/var/*/data/**` + write → DATA_DIR
- `/dev/log` + connect → SYSLOG
- `bind()` → NETWORK_SERVER

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

    def generate(self, intents: List[Intent]) -> PolicyModule:
        """Generate PolicyModule object (not string)"""
        policy = PolicyModule(name=self.module_name, version="1.0.0")

        # Add base types
        policy.types.append(TypeDeclaration(f"{self.module_name}_t"))
        policy.types.append(TypeDeclaration(f"{self.module_name}_exec_t"))

        # Process each intent
        for intent in intents:
            # Generate custom type if needed
            custom_type = self.type_generator.generate_type_name(
                self.module_name, intent
            )
            if custom_type:
                policy.types.append(TypeDeclaration(custom_type))
                intent.selinux_type = custom_type

            # Lookup appropriate macro
            macro = self.macro_lookup.suggest_macro(intent)
            if macro:
                policy.macro_calls.append(MacroCall(macro, [f"{self.module_name}_t"]))

        return policy

class FCGenerator:
    def generate(self, intents: List[Intent], exec_path: str) -> FileContexts:
        """Generate FileContexts object (not string)"""
        contexts = FileContexts()

        # Add executable context
        if exec_path:
            contexts.entries.append(FileContextEntry(
                path=exec_path,
                type=f"{self.module_name}_exec_t"
            ))

        # Extract file paths from intents
        for intent in intents:
            if intent.selinux_type:
                for access in intent.accesses:
                    contexts.entries.append(FileContextEntry(
                        path=access.path,
                        type=intent.selinux_type
                    ))

        return contexts
```

**Type generation rules**:
- Process domain: `{module}_t`
- Executable: `{module}_exec_t`
- Config files: `{module}_conf_t` (paths under `/etc/{module}/`)
- Data directories: `{module}_data_t` (paths under `/var/{module}/`)
- PID files: `{module}_var_run_t` (paths under `/var/run/`)

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

    def suggest_macro(self, intent: Intent) -> Optional[str]:
        """Hardcoded first, semacro fallback"""
        # Fast path
        if intent.intent_type in self.KNOWN_MAPPINGS:
            return self.KNOWN_MAPPINGS[intent.intent_type]

        # Fallback to semacro
        from semacro import search_macros
        results = search_macros(intent_type=intent.intent_type.value)
        return results[0] if results else None
```

**Type generation**:

```python
class TypeGenerator:
    def generate_type_name(self, module_name: str, intent: Intent) -> Optional[str]:
        """Create type name based on intent"""
        mapping = {
            IntentType.CONFIG_FILE: f"{module_name}_conf_t",
            IntentType.PID_FILE: f"{module_name}_var_run_t",
            IntentType.DATA_DIR: f"{module_name}_data_t",
            IntentType.LOG_FILE: f"{module_name}_log_t",
        }
        return mapping.get(intent.intent_type)
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
sepgen analyze <source-path> [--name MODULE_NAME] [-v] [-vv]
sepgen trace <binary> [--args "ARGS"] [--pid PID] [-v] [-vv] [-y]
```

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
  Generated types: myapp_t, myapp_conf_t, myapp_var_run_t
  Applied macros: logging_send_syslog_msg, files_pid_filetrans

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
├── unit/
│   ├── analyzer/
│   │   ├── test_c_analyzer.py
│   │   └── test_syscall_mapper.py
│   ├── tracer/
│   │   ├── test_strace_parser.py
│   │   └── test_process_tracer.py
│   ├── intent/
│   │   ├── test_classifier.py
│   │   └── test_rules.py
│   ├── selinux/
│   │   ├── test_macro_lookup.py
│   │   └── test_type_generator.py
│   ├── generator/
│   │   ├── test_te_generator.py
│   │   └── test_fc_generator.py
│   └── merger/
│       ├── test_policy_merger.py
│       └── test_merge_strategies.py
├── integration/
│   ├── test_analyze_pipeline.py
│   ├── test_trace_pipeline.py
│   ├── test_merge_workflow.py
│   └── test_cli_e2e.py
└── fixtures/
    ├── sample_c_program.c
    ├── strace_output.txt
    └── existing_policy/
        ├── myapp.te
        └── myapp.fc
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
Source Code (.c/.py files)
    ↓
CAnalyzer.analyze_file()
    ↓
List[Access] (predicted syscalls)
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

### 8.3 Component Interfaces

All component interfaces (BaseAnalyzer, IntentRule, MacroLookup) are designed for extensibility:
- Swap RegexParser → TreeSitterParser
- Add PythonAnalyzer alongside CAnalyzer
- Add custom classification rules
- Extend macro lookup logic

---

**Document Status**: Ready for implementation planning
