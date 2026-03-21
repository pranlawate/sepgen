# sepgen: SELinux Policy Generator - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a dual-mode SELinux policy generator that analyzes source code and traces runtime behavior to generate macro-based policy modules with custom types

**Architecture:** Two independent pipelines (static analysis + runtime tracing) converge to unified intent classification, then generate structured policy objects (PolicyModule, FileContexts). Auto-merge detects existing policies and intelligently combines results with trace-wins strategy. Object-based model maintained until final serialization.

**Tech Stack:** Python 3.9+, semacro (parsing & macro lookup), strace (tracing), regex (C parsing MVP), libselinux-python (optional context resolution)

**Design Spec:** `docs/superpowers/specs/2026-03-21-sepgen-design.md`

---

## File Structure

```
sepgen/
├── sepgen/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                      # CLI commands
│   ├── models/
│   │   ├── __init__.py
│   │   ├── access.py               # Access, AccessType
│   │   ├── intent.py               # Intent, IntentType
│   │   └── policy.py               # PolicyModule, FileContexts, etc.
│   ├── analyzer/
│   │   ├── __init__.py
│   │   ├── base.py                 # BaseAnalyzer interface
│   │   ├── c_analyzer.py           # C source analyzer (regex-based)
│   │   └── syscall_mapper.py       # Function → syscall mapping
│   ├── tracer/
│   │   ├── __init__.py
│   │   ├── strace_parser.py        # Parse strace output
│   │   └── process_tracer.py       # Execute strace
│   ├── intent/
│   │   ├── __init__.py
│   │   ├── classifier.py           # IntentClassifier
│   │   └── rules.py                # Classification rules
│   ├── generator/
│   │   ├── __init__.py
│   │   ├── te_generator.py         # Generate PolicyModule objects
│   │   ├── fc_generator.py         # Generate FileContexts objects
│   │   ├── te_writer.py            # Serialize PolicyModule → .te
│   │   └── fc_writer.py            # Serialize FileContexts → .fc
│   ├── selinux/
│   │   ├── __init__.py
│   │   ├── macro_lookup.py         # Hybrid macro lookup
│   │   └── type_generator.py       # Type name generation
│   ├── merger/
│   │   ├── __init__.py
│   │   └── policy_merger.py        # Merge PolicyModule objects
│   └── utils/
│       ├── __init__.py
│       ├── error_collector.py      # Error handling
│       └── logger.py               # Verbosity system
├── tests/
│   ├── __init__.py
│   ├── models/
│   ├── analyzer/
│   ├── tracer/
│   ├── intent/
│   ├── generator/
│   ├── selinux/
│   ├── merger/
│   ├── integration/
│   └── fixtures/
│       ├── sample_c_program.c
│       └── strace_output.txt
├── pyproject.toml
├── setup.py
└── README.md
```

---

### Task 1: Project Setup & Data Models

**Files:**
- Create: `pyproject.toml`
- Create: `setup.py`
- Create: `sepgen/__init__.py`
- Create: `sepgen/models/__init__.py`
- Create: `sepgen/models/access.py`
- Create: `sepgen/models/intent.py`
- Create: `sepgen/models/policy.py`
- Create: `tests/models/test_access.py`
- Create: `tests/models/test_intent.py`
- Create: `tests/models/test_policy.py`

- [ ] **Step 1: Write failing tests for Access model**

```python
# tests/models/test_access.py
import pytest
from sepgen.models.access import Access, AccessType

def test_create_file_read_access():
    """Test creating a file read access"""
    access = Access(
        access_type=AccessType.FILE_READ,
        path="/etc/myapp.conf",
        syscall="open"
    )
    assert access.path == "/etc/myapp.conf"
    assert access.access_type == AccessType.FILE_READ
    assert access.syscall == "open"

def test_create_socket_bind_access():
    """Test creating a socket bind access"""
    access = Access(
        access_type=AccessType.SOCKET_BIND,
        path="tcp:8080",
        syscall="bind",
        details={"port": 8080, "protocol": "tcp"}
    )
    assert access.details["port"] == 8080
    assert access.access_type == AccessType.SOCKET_BIND

def test_access_with_source_location():
    """Test access with source code location"""
    access = Access(
        access_type=AccessType.FILE_WRITE,
        path="/var/log/app.log",
        syscall="open",
        source_file="main.c",
        source_line=42
    )
    assert access.source_file == "main.c"
    assert access.source_line == 42
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/models/test_access.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'sepgen.models.access'"

- [ ] **Step 3: Create project configuration**

```toml
# pyproject.toml
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "sepgen"
version = "0.1.0"
description = "SELinux policy generator with static analysis and runtime tracing"
authors = [{name = "Pranav Lawate"}]
requires-python = ">=3.9"
dependencies = [
    "semacro",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
]

[project.scripts]
sepgen = "sepgen.__main__:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
```

```python
# setup.py
from setuptools import setup, find_packages

setup(
    name="sepgen",
    packages=find_packages(),
    install_requires=["semacro"],
)
```

- [ ] **Step 4: Implement Access and Intent models**

```python
# sepgen/__init__.py
"""SELinux policy generator"""
__version__ = "0.1.0"
```

```python
# sepgen/models/__init__.py
"""Data models for sepgen"""
from sepgen.models.access import Access, AccessType
from sepgen.models.intent import Intent, IntentType

__all__ = ['Access', 'AccessType', 'Intent', 'IntentType']
```

```python
# sepgen/models/access.py
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional

class AccessType(Enum):
    """Types of system accesses"""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_CREATE = "file_create"
    FILE_UNLINK = "file_unlink"
    DIR_READ = "dir_read"
    DIR_WRITE = "dir_write"
    SOCKET_CREATE = "socket_create"
    SOCKET_BIND = "socket_bind"
    SOCKET_LISTEN = "socket_listen"
    SOCKET_CONNECT = "socket_connect"
    SOCKET_ACCEPT = "socket_accept"
    IPC_SYSV = "ipc_sysv"
    IPC_POSIX = "ipc_posix"

@dataclass
class Access:
    """Represents a single system access"""
    access_type: AccessType
    path: str
    syscall: str
    details: Dict[str, Any] = field(default_factory=dict)
    source_file: Optional[str] = None
    source_line: Optional[int] = None
```

```python
# sepgen/models/intent.py
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

class IntentType(Enum):
    """Classified intent categories"""
    CONFIG_FILE = "config_file"
    PID_FILE = "pid_file"
    DATA_DIR = "data_dir"
    LOG_FILE = "log_file"
    TEMP_FILE = "temp_file"
    NETWORK_SERVER = "network_server"
    NETWORK_CLIENT = "network_client"
    SYSLOG = "syslog"
    TERMINAL_IO = "terminal_io"
    SHARED_LIBRARY = "shared_library"
    UNKNOWN = "unknown"

@dataclass
class Intent:
    """Classified security intent with associated accesses"""
    intent_type: IntentType
    accesses: List['Access']
    confidence: float = 1.0
    selinux_type: Optional[str] = None
    macros: List[str] = field(default_factory=list)
```

- [ ] **Step 5: Write tests for Intent model**

```python
# tests/models/test_intent.py
import pytest
from sepgen.models.intent import Intent, IntentType
from sepgen.models.access import Access, AccessType

def test_create_intent():
    """Test creating an intent"""
    access = Access(
        access_type=AccessType.FILE_READ,
        path="/etc/app.conf",
        syscall="open"
    )
    intent = Intent(
        intent_type=IntentType.CONFIG_FILE,
        accesses=[access],
        confidence=0.95
    )
    assert intent.intent_type == IntentType.CONFIG_FILE
    assert len(intent.accesses) == 1
    assert intent.confidence == 0.95

def test_intent_with_selinux_type():
    """Test intent with SELinux type assigned"""
    access = Access(
        access_type=AccessType.FILE_WRITE,
        path="/var/run/app.pid",
        syscall="open"
    )
    intent = Intent(
        intent_type=IntentType.PID_FILE,
        accesses=[access],
        selinux_type="myapp_var_run_t"
    )
    assert intent.selinux_type == "myapp_var_run_t"
```

- [ ] **Step 6: Write tests for PolicyModule model**

```python
# tests/models/test_policy.py
import pytest
from sepgen.models.policy import (
    PolicyModule, FileContexts, TypeDeclaration,
    AllowRule, MacroCall, FileContextEntry
)

def test_create_policy_module():
    """Test creating a PolicyModule"""
    policy = PolicyModule(name="myapp", version="1.0.0")
    assert policy.name == "myapp"
    assert policy.version == "1.0.0"
    assert len(policy.types) == 0
    assert len(policy.allow_rules) == 0

def test_add_type_to_policy():
    """Test adding types to policy"""
    policy = PolicyModule(name="myapp", version="1.0.0")
    policy.types.append(TypeDeclaration("myapp_t"))
    policy.types.append(TypeDeclaration("myapp_conf_t"))
    assert len(policy.types) == 2
    assert policy.types[0].name == "myapp_t"

def test_create_file_contexts():
    """Test creating FileContexts"""
    contexts = FileContexts()
    contexts.entries.append(FileContextEntry(
        path="/usr/bin/myapp",
        selinux_type="myapp_exec_t"
    ))
    assert len(contexts.entries) == 1
    assert contexts.entries[0].path == "/usr/bin/myapp"
```

- [ ] **Step 7: Implement PolicyModule and FileContexts models**

```python
# sepgen/models/policy.py
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class TypeDeclaration:
    """SELinux type declaration"""
    name: str
    attributes: List[str] = field(default_factory=list)

    def __str__(self):
        return f"type {self.name};"

@dataclass
class AllowRule:
    """SELinux allow rule"""
    source: str
    target: str
    object_class: str
    permissions: List[str]

    def __str__(self):
        perms = " ".join(self.permissions)
        return f"allow {self.source} {self.target}:{self.object_class} {{ {perms} }};"

@dataclass
class MacroCall:
    """Policy macro invocation"""
    name: str
    args: List[str]

    def __str__(self):
        args_str = ", ".join(self.args)
        return f"{self.name}({args_str})"

@dataclass
class PolicyModule:
    """Structured representation of .te policy file"""
    name: str
    version: str
    types: List[TypeDeclaration] = field(default_factory=list)
    allow_rules: List[AllowRule] = field(default_factory=list)
    macro_calls: List[MacroCall] = field(default_factory=list)

    def add_type(self, type_name: str, attributes: List[str] = None):
        """Add a type declaration"""
        self.types.append(TypeDeclaration(type_name, attributes or []))

    def add_macro(self, macro_name: str, args: List[str]):
        """Add a macro call"""
        self.macro_calls.append(MacroCall(macro_name, args))

@dataclass
class FileContextEntry:
    """Single file context entry"""
    path: str
    selinux_type: str
    file_type: str = "all_files"

    def __str__(self):
        return f"{self.path}\t\tgen_context(system_u:object_r:{self.selinux_type},s0)"

@dataclass
class FileContexts:
    """Structured representation of .fc file"""
    entries: List[FileContextEntry] = field(default_factory=list)

    def add_entry(self, path: str, selinux_type: str):
        """Add a file context entry"""
        self.entries.append(FileContextEntry(path, selinux_type))
```

- [ ] **Step 8: Run all tests to verify they pass**

Run: `pytest tests/models/ -v`
Expected: PASS (all model tests)

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml setup.py sepgen/models/ tests/models/
git commit -m "feat: add project setup and core data models"
```

---

### Task 2: Static Analysis - SyscallMapper

**Files:**
- Create: `sepgen/analyzer/__init__.py`
- Create: `sepgen/analyzer/base.py`
- Create: `sepgen/analyzer/syscall_mapper.py`
- Create: `tests/analyzer/test_syscall_mapper.py`

- [ ] **Step 1: Write failing tests for SyscallMapper**

```python
# tests/analyzer/test_syscall_mapper.py
import pytest
from sepgen.analyzer.syscall_mapper import SyscallMapper
from sepgen.models.access import Access, AccessType

def test_map_fopen_to_open():
    """Test mapping fopen() to open syscall"""
    mapper = SyscallMapper()
    access = mapper.map_function_call('fopen', ['"

/etc/app.conf"', '"r"'])

    assert access is not None
    assert access.syscall == "open"
    assert access.path == "/etc/app.conf"
    assert access.access_type == AccessType.FILE_READ

def test_map_fopen_write_mode():
    """Test mapping fopen() with write mode"""
    mapper = SyscallMapper()
    access = mapper.map_function_call('fopen', ['"/var/log/app.log"', '"w"'])

    assert access.access_type == AccessType.FILE_WRITE
    assert access.path == "/var/log/app.log"

def test_map_socket_call():
    """Test mapping socket() call"""
    mapper = SyscallMapper()
    access = mapper.map_function_call('socket', ['AF_INET', 'SOCK_STREAM', '0'])

    assert access.syscall == "socket"
    assert access.access_type == AccessType.SOCKET_CREATE
    assert access.details["domain"] == "AF_INET"

def test_map_bind_call():
    """Test mapping bind() call"""
    mapper = SyscallMapper()
    access = mapper.map_function_call('bind', [])

    assert access.syscall == "bind"
    assert access.access_type == AccessType.SOCKET_BIND
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/analyzer/test_syscall_mapper.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'sepgen.analyzer.syscall_mapper'"

- [ ] **Step 3: Implement BaseAnalyzer interface**

```python
# sepgen/analyzer/__init__.py
"""Static source code analysis"""
from sepgen.analyzer.base import BaseAnalyzer
from sepgen.analyzer.syscall_mapper import SyscallMapper

__all__ = ['BaseAnalyzer', 'SyscallMapper']
```

```python
# sepgen/analyzer/base.py
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List
from sepgen.models.access import Access

class BaseAnalyzer(ABC):
    """Base class for language-specific analyzers"""

    @abstractmethod
    def analyze_file(self, file_path: Path) -> List[Access]:
        """Analyze a source file and return predicted accesses"""
        pass

    @abstractmethod
    def analyze_string(self, code: str) -> List[Access]:
        """Analyze code string and return predicted accesses"""
        pass
```

- [ ] **Step 4: Implement SyscallMapper**

```python
# sepgen/analyzer/syscall_mapper.py
from typing import List, Optional
from sepgen.models.access import Access, AccessType

class SyscallMapper:
    """Map C library function calls to syscalls"""

    # Direct function → syscall mappings
    FUNCTION_TO_SYSCALL = {
        'fopen': 'open',
        'open': 'open',
        'creat': 'creat',
        'socket': 'socket',
        'bind': 'bind',
        'listen': 'listen',
        'connect': 'connect',
        'accept': 'accept',
    }

    def map_function_call(self, func_name: str, args: List[str]) -> Optional[Access]:
        """Map a function call to a system access"""
        if func_name in ['fopen', 'open']:
            return self._map_open_call(func_name, args)
        elif func_name == 'socket':
            return self._map_socket_call(args)
        elif func_name == 'bind':
            return self._map_bind_call(args)

        return None

    def _map_open_call(self, func_name: str, args: List[str]) -> Optional[Access]:
        """Map fopen/open to file access"""
        if not args:
            return None

        # Extract path (remove quotes)
        path = args[0].strip('"')

        # Determine access type from mode
        mode = args[1].strip('"') if len(args) > 1 else 'r'

        if func_name == 'fopen':
            # fopen modes: r, w, a, r+, w+, a+
            if 'w' in mode or 'a' in mode:
                access_type = AccessType.FILE_WRITE
            else:
                access_type = AccessType.FILE_READ
        else:
            # open() flags - default to read
            access_type = AccessType.FILE_READ

        return Access(
            access_type=access_type,
            path=path,
            syscall=self.FUNCTION_TO_SYSCALL[func_name],
            details={"mode": mode}
        )

    def _map_socket_call(self, args: List[str]) -> Access:
        """Map socket() call"""
        domain = args[0] if args else 'AF_INET'
        sock_type = args[1] if len(args) > 1 else 'SOCK_STREAM'

        return Access(
            access_type=AccessType.SOCKET_CREATE,
            path=f"{domain}:{sock_type}",
            syscall="socket",
            details={"domain": domain, "type": sock_type}
        )

    def _map_bind_call(self, args: List[str]) -> Access:
        """Map bind() call - basic placeholder"""
        return Access(
            access_type=AccessType.SOCKET_BIND,
            path="tcp:unknown",
            syscall="bind",
            details={"port": None}
        )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/analyzer/test_syscall_mapper.py -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add sepgen/analyzer/ tests/analyzer/
git commit -m "feat: add syscall mapper for function→syscall translation"
```

---

### Task 3: Static Analysis - C Analyzer

**Files:**
- Create: `sepgen/analyzer/c_analyzer.py`
- Create: `tests/analyzer/test_c_analyzer.py`
- Create: `tests/fixtures/sample_c_program.c`

- [ ] **Step 1: Create test fixture**

```c
// tests/fixtures/sample_c_program.c
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char *argv[]) {
    // Read config file
    FILE *config = fopen("/etc/myapp/config.ini", "r");
    fclose(config);

    // Write PID file
    FILE *pid = fopen("/var/run/myapp.pid", "w");
    fprintf(pid, "%d\n", getpid());
    fclose(pid);

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    // Bind to port
    struct sockaddr_in addr;
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));

    return 0;
}
```

- [ ] **Step 2: Write failing tests for CAnalyzer**

```python
# tests/analyzer/test_c_analyzer.py
import pytest
from pathlib import Path
from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.models.access import AccessType

def test_analyze_fopen_call():
    """Test analyzing fopen() call"""
    analyzer = CAnalyzer()
    code = '''
    int main() {
        FILE *f = fopen("/etc/myapp.conf", "r");
        fclose(f);
        return 0;
    }
    '''

    accesses = analyzer.analyze_string(code)
    file_reads = [a for a in accesses if a.access_type == AccessType.FILE_READ]

    assert len(file_reads) >= 1
    assert any(a.path == "/etc/myapp.conf" for a in file_reads)

def test_analyze_socket_call():
    """Test analyzing socket() call"""
    analyzer = CAnalyzer()
    code = '''
    int main() {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        return 0;
    }
    '''

    accesses = analyzer.analyze_string(code)
    socket_creates = [a for a in accesses if a.access_type == AccessType.SOCKET_CREATE]

    assert len(socket_creates) >= 1

def test_analyze_file():
    """Test analyzing complete C file"""
    analyzer = CAnalyzer()
    fixture = Path(__file__).parent.parent / "fixtures" / "sample_c_program.c"

    accesses = analyzer.analyze_file(fixture)

    # Should find fopen calls
    file_accesses = [a for a in accesses if a.access_type in [AccessType.FILE_READ, AccessType.FILE_WRITE]]
    assert len(file_accesses) >= 2

    # Should find socket call
    socket_accesses = [a for a in accesses if a.access_type == AccessType.SOCKET_CREATE]
    assert len(socket_accesses) >= 1
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/analyzer/test_c_analyzer.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'sepgen.analyzer.c_analyzer'"

- [ ] **Step 4: Implement CAnalyzer**

```python
# sepgen/analyzer/c_analyzer.py
import re
from pathlib import Path
from typing import List
from sepgen.analyzer.base import BaseAnalyzer
from sepgen.analyzer.syscall_mapper import SyscallMapper
from sepgen.models.access import Access

class CAnalyzer(BaseAnalyzer):
    """Static analyzer for C/C++ code using regex patterns"""

    def __init__(self):
        self.mapper = SyscallMapper()

    def analyze_file(self, file_path: Path) -> List[Access]:
        """Analyze a C source file"""
        code = file_path.read_text()
        return self.analyze_string(code)

    def analyze_string(self, code: str) -> List[Access]:
        """Analyze C code string using regex patterns"""
        accesses = []

        # Pattern: fopen("path", "mode")
        fopen_pattern = re.compile(r'fopen\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)')
        for match in fopen_pattern.finditer(code):
            path = match.group(1)
            mode = match.group(2)
            access = self.mapper.map_function_call('fopen', [f'"{path}"', f'"{mode}"'])
            if access:
                accesses.append(access)

        # Pattern: socket(domain, type, protocol)
        socket_pattern = re.compile(r'socket\s*\(\s*([A-Z_]+)\s*,\s*([A-Z_]+)\s*,')
        for match in socket_pattern.finditer(code):
            domain = match.group(1)
            sock_type = match.group(2)
            access = self.mapper.map_function_call('socket', [domain, sock_type])
            if access:
                accesses.append(access)

        # Pattern: bind() - simple detection
        if 'bind(' in code:
            access = self.mapper.map_function_call('bind', [])
            if access:
                accesses.append(access)

        return accesses
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/analyzer/test_c_analyzer.py -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add sepgen/analyzer/c_analyzer.py tests/analyzer/test_c_analyzer.py tests/fixtures/
git commit -m "feat: add C source code analyzer with regex-based parsing"
```

---

### Task 4: Runtime Tracing - Strace Parser

**Files:**
- Create: `sepgen/tracer/__init__.py`
- Create: `sepgen/tracer/strace_parser.py`
- Create: `tests/tracer/test_strace_parser.py`
- Create: `tests/fixtures/strace_output.txt`

- [ ] **Step 1: Create strace output fixture**

```
# tests/fixtures/strace_output.txt
execve("/usr/bin/testapp", ["testapp"], 0x7ffd... /* 24 vars */) = 0
open("/etc/testapp.conf", O_RDONLY) = 3
read(3, "port=8080\n", 4096) = 10
close(3) = 0
open("/var/run/testapp.pid", O_WRONLY|O_CREAT, 0644) = 3
write(3, "12345\n", 6) = 6
close(3) = 0
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
listen(3, 5) = 0
connect(4, {sa_family=AF_UNIX, sun_path="/dev/log"}, 110) = 0
sendto(4, "<30>testapp: started\n", 21, 0, NULL, 0) = 21
open("/nonexistent", O_RDONLY) = -1 ENOENT (No such file or directory)
```

- [ ] **Step 2: Write failing tests for StraceParser**

```python
# tests/tracer/test_strace_parser.py
import pytest
from pathlib import Path
from sepgen.tracer.strace_parser import StraceParser
from sepgen.models.access import AccessType

def test_parse_open_readonly():
    """Test parsing open() with O_RDONLY"""
    parser = StraceParser()
    line = 'open("/etc/myapp.conf", O_RDONLY) = 3'
    accesses = parser.parse_line(line)

    assert len(accesses) == 1
    assert accesses[0].syscall == "open"
    assert accesses[0].path == "/etc/myapp.conf"
    assert accesses[0].access_type == AccessType.FILE_READ

def test_parse_open_write():
    """Test parsing open() with O_WRONLY"""
    parser = StraceParser()
    line = 'open("/var/run/app.pid", O_WRONLY|O_CREAT, 0644) = 3'
    accesses = parser.parse_line(line)

    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.FILE_CREATE

def test_parse_failed_open():
    """Test that failed syscalls are ignored"""
    parser = StraceParser()
    line = 'open("/nonexistent", O_RDONLY) = -1 ENOENT'
    accesses = parser.parse_line(line)

    assert len(accesses) == 0  # Failed syscalls ignored

def test_parse_socket_bind():
    """Test parsing bind() with port"""
    parser = StraceParser()
    line = 'bind(3, {sa_family=AF_INET, sin_port=htons(8080)}, 16) = 0'
    accesses = parser.parse_line(line)

    assert len(accesses) == 1
    assert accesses[0].syscall == "bind"
    assert accesses[0].access_type == AccessType.SOCKET_BIND
    assert accesses[0].details["port"] == 8080

def test_parse_syslog_connection():
    """Test parsing connection to /dev/log"""
    parser = StraceParser()
    line = 'connect(4, {sa_family=AF_UNIX, sun_path="/dev/log"}, 110) = 0'
    accesses = parser.parse_line(line)

    assert len(accesses) == 1
    assert accesses[0].path == "/dev/log"
    assert accesses[0].details.get("is_syslog") == True

def test_parse_file():
    """Test parsing complete strace output file"""
    parser = StraceParser()
    fixture = Path(__file__).parent.parent / "fixtures" / "strace_output.txt"
    accesses = parser.parse_file(fixture)

    assert len(accesses) > 0
    # Should have file opens
    file_accesses = [a for a in accesses if a.access_type in [AccessType.FILE_READ, AccessType.FILE_CREATE]]
    assert len(file_accesses) >= 2
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/tracer/test_strace_parser.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'sepgen.tracer.strace_parser'"

- [ ] **Step 4: Implement StraceParser**

```python
# sepgen/tracer/__init__.py
"""Runtime tracing with strace"""
from sepgen.tracer.strace_parser import StraceParser

__all__ = ['StraceParser']
```

```python
# sepgen/tracer/strace_parser.py
import re
from pathlib import Path
from typing import List
from sepgen.models.access import Access, AccessType

class StraceParser:
    """Parse strace output and extract system accesses"""

    # Regex patterns for syscalls
    OPEN_PATTERN = re.compile(r'open(?:at)?\("([^"]+)",\s*([^)]+)\)\s*=\s*(\d+|-1)')
    SOCKET_PATTERN = re.compile(r'socket\(([^,]+),\s*([^,]+),\s*([^)]+)\)\s*=\s*(\d+)')
    BIND_PATTERN = re.compile(r'bind\(\d+,\s*\{sa_family=([^,]+).*?sin_port=htons\((\d+)\)')
    CONNECT_PATTERN = re.compile(r'connect\(\d+,\s*\{sa_family=([^,]+)(?:.*?sun_path="([^"]+)")?')

    def parse_line(self, line: str) -> List[Access]:
        """Parse a single strace output line"""
        accesses = []

        # Parse open/openat
        match = self.OPEN_PATTERN.search(line)
        if match:
            path = match.group(1)
            flags = match.group(2)
            fd = match.group(3)

            # Skip failed opens
            if fd == '-1':
                return accesses

            # Determine access type from flags
            if 'O_WRONLY' in flags or 'O_RDWR' in flags:
                if 'O_CREAT' in flags:
                    access_type = AccessType.FILE_CREATE
                else:
                    access_type = AccessType.FILE_WRITE
            else:
                access_type = AccessType.FILE_READ

            accesses.append(Access(
                access_type=access_type,
                path=path,
                syscall="open",
                details={"flags": flags}
            ))

        # Parse bind
        match = self.BIND_PATTERN.search(line)
        if match:
            family = match.group(1)
            port = int(match.group(2))

            accesses.append(Access(
                access_type=AccessType.SOCKET_BIND,
                path=f"tcp:{port}",
                syscall="bind",
                details={"port": port, "family": family, "protocol": "tcp"}
            ))

        # Parse socket
        match = self.SOCKET_PATTERN.search(line)
        if match:
            domain = match.group(1)
            sock_type = match.group(2)

            accesses.append(Access(
                access_type=AccessType.SOCKET_CREATE,
                path=f"{domain}:{sock_type}",
                syscall="socket",
                details={"domain": domain, "type": sock_type}
            ))

        # Parse connect (especially for syslog)
        match = self.CONNECT_PATTERN.search(line)
        if match:
            family = match.group(1)
            path = match.group(2)

            if path == "/dev/log":
                accesses.append(Access(
                    access_type=AccessType.SOCKET_CONNECT,
                    path="/dev/log",
                    syscall="connect",
                    details={"family": family, "is_syslog": True}
                ))

        return accesses

    def parse_file(self, path: Path) -> List[Access]:
        """Parse an entire strace output file"""
        accesses = []

        with open(path, 'r') as f:
            for line in f:
                accesses.extend(self.parse_line(line))

        return accesses
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/tracer/test_strace_parser.py -v`
Expected: PASS (6 tests)

- [ ] **Step 6: Commit**

```bash
git add sepgen/tracer/ tests/tracer/ tests/fixtures/strace_output.txt
git commit -m "feat: add strace output parser"
```

---

### Task 5: Runtime Tracing - Process Tracer

**Files:**
- Create: `sepgen/tracer/process_tracer.py`
- Create: `tests/tracer/test_process_tracer.py`

- [ ] **Step 1: Write failing tests for ProcessTracer**

```python
# tests/tracer/test_process_tracer.py
import pytest
from sepgen.tracer.process_tracer import ProcessTracer

def test_build_strace_command_with_binary():
    """Test building strace command for binary"""
    tracer = ProcessTracer()
    cmd = tracer.build_strace_command(binary='/usr/bin/myapp', args='--config /etc/app.conf')

    assert 'strace' in cmd
    assert '-f' in cmd
    assert '/usr/bin/myapp' in cmd
    assert '--config' in cmd

def test_build_strace_command_with_pid():
    """Test building strace command for PID attachment"""
    tracer = ProcessTracer()
    cmd = tracer.build_strace_command(pid=1234)

    assert 'strace' in cmd
    assert '-p' in cmd
    assert '1234' in cmd

def test_build_command_requires_binary_or_pid():
    """Test that either binary or pid is required"""
    tracer = ProcessTracer()
    with pytest.raises(ValueError):
        tracer.build_strace_command()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/tracer/test_process_tracer.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'sepgen.tracer.process_tracer'"

- [ ] **Step 3: Implement ProcessTracer**

```python
# sepgen/tracer/process_tracer.py
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List

class ProcessTracer:
    """Execute and trace processes with strace"""

    def build_strace_command(
        self,
        binary: Optional[str] = None,
        args: str = '',
        pid: Optional[int] = None,
        output_file: Optional[str] = None
    ) -> List[str]:
        """Build strace command line"""
        cmd = ['strace', '-f', '-e', 'trace=file,network,ipc']

        if output_file:
            cmd.extend(['-o', output_file])

        if pid:
            cmd.extend(['-p', str(pid)])
        elif binary:
            cmd.append(binary)
            if args:
                cmd.extend(args.split())
        else:
            raise ValueError("Either binary or pid must be provided")

        return cmd

    def trace(
        self,
        binary: Optional[str] = None,
        args: str = '',
        pid: Optional[int] = None,
        output_file: Optional[Path] = None
    ) -> Path:
        """Trace a process and return path to strace output"""
        if output_file is None:
            # Create temp file
            fd, temp_path = tempfile.mkstemp(suffix='.strace', prefix='sepgen-')
            output_file = Path(temp_path)

        cmd = self.build_strace_command(binary, args, pid, str(output_file))

        # Execute strace (may fail if traced process fails)
        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError:
            # Process failed, but output file may still have useful data
            pass

        return output_file
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/tracer/test_process_tracer.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add sepgen/tracer/process_tracer.py tests/tracer/test_process_tracer.py
git commit -m "feat: add process tracer for strace execution"
```

---

### Task 6: Intent Classification

**Files:**
- Create: `sepgen/intent/__init__.py`
- Create: `sepgen/intent/rules.py`
- Create: `sepgen/intent/classifier.py`
- Create: `tests/intent/test_rules.py`
- Create: `tests/intent/test_classifier.py`

- [ ] **Step 1: Write failing tests for classification rules**

```python
# tests/intent/test_rules.py
import pytest
from sepgen.intent.rules import PidFileRule, ConfigFileRule, SyslogRule, NetworkServerRule
from sepgen.models.access import Access, AccessType
from sepgen.models.intent import IntentType

def test_pid_file_rule_matches():
    """Test PID file rule matches /var/run/*.pid"""
    rule = PidFileRule()
    access = Access(
        access_type=AccessType.FILE_WRITE,
        path="/var/run/myapp.pid",
        syscall="open"
    )

    assert rule.matches(access) == True
    assert rule.get_intent_type() == IntentType.PID_FILE

def test_config_file_rule_matches():
    """Test config file rule matches /etc/**"""
    rule = ConfigFileRule()
    access = Access(
        access_type=AccessType.FILE_READ,
        path="/etc/myapp/config.ini",
        syscall="open"
    )

    assert rule.matches(access) == True
    assert rule.get_intent_type() == IntentType.CONFIG_FILE

def test_syslog_rule_matches():
    """Test syslog rule matches /dev/log"""
    rule = SyslogRule()
    access = Access(
        access_type=AccessType.SOCKET_CONNECT,
        path="/dev/log",
        syscall="connect",
        details={"is_syslog": True}
    )

    assert rule.matches(access) == True
    assert rule.get_intent_type() == IntentType.SYSLOG

def test_network_server_rule_matches():
    """Test network server rule matches bind()"""
    rule = NetworkServerRule()
    access = Access(
        access_type=AccessType.SOCKET_BIND,
        path="tcp:8080",
        syscall="bind"
    )

    assert rule.matches(access) == True
    assert rule.get_intent_type() == IntentType.NETWORK_SERVER
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/intent/test_rules.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'sepgen.intent.rules'"

- [ ] **Step 3: Implement classification rules**

```python
# sepgen/intent/__init__.py
"""Intent classification"""
from sepgen.intent.classifier import IntentClassifier
from sepgen.intent.rules import (
    ClassificationRule, PidFileRule, ConfigFileRule,
    SyslogRule, NetworkServerRule, DEFAULT_RULES
)

__all__ = [
    'IntentClassifier', 'ClassificationRule', 'PidFileRule',
    'ConfigFileRule', 'SyslogRule', 'NetworkServerRule', 'DEFAULT_RULES'
]
```

```python
# sepgen/intent/rules.py
import re
from sepgen.models.access import Access, AccessType
from sepgen.models.intent import IntentType

class ClassificationRule:
    """Base class for classification rules"""

    def matches(self, access: Access) -> bool:
        """Check if this rule matches the access"""
        raise NotImplementedError

    def get_intent_type(self) -> IntentType:
        """Return the intent type for this rule"""
        raise NotImplementedError

    def get_confidence(self) -> float:
        """Return confidence score"""
        return 1.0  # Deterministic rules always return 1.0

class PidFileRule(ClassificationRule):
    """Classify PID file accesses"""

    PID_PATTERNS = [
        re.compile(r'/var/run/.*\.pid$'),
        re.compile(r'/run/.*\.pid$'),
        re.compile(r'\.pid$'),
    ]

    def matches(self, access: Access) -> bool:
        if access.access_type not in [AccessType.FILE_WRITE, AccessType.FILE_CREATE]:
            return False
        return any(pattern.search(access.path) for pattern in self.PID_PATTERNS)

    def get_intent_type(self) -> IntentType:
        return IntentType.PID_FILE

class ConfigFileRule(ClassificationRule):
    """Classify config file accesses"""

    CONFIG_PATTERNS = [
        re.compile(r'/etc/'),
        re.compile(r'\.conf$'),
        re.compile(r'\.ini$'),
        re.compile(r'\.cfg$'),
        re.compile(r'\.yaml$'),
        re.compile(r'\.toml$'),
        re.compile(r'\.json$'),
    ]

    def matches(self, access: Access) -> bool:
        if access.access_type != AccessType.FILE_READ:
            return False
        return any(pattern.search(access.path) for pattern in self.CONFIG_PATTERNS)

    def get_intent_type(self) -> IntentType:
        return IntentType.CONFIG_FILE

class SyslogRule(ClassificationRule):
    """Classify syslog access"""

    def matches(self, access: Access) -> bool:
        return (access.path == "/dev/log" and
                access.details.get("is_syslog", False))

    def get_intent_type(self) -> IntentType:
        return IntentType.SYSLOG

class NetworkServerRule(ClassificationRule):
    """Classify network server operations"""

    def matches(self, access: Access) -> bool:
        return access.access_type == AccessType.SOCKET_BIND

    def get_intent_type(self) -> IntentType:
        return IntentType.NETWORK_SERVER

# Default rule set
DEFAULT_RULES = [
    PidFileRule(),
    ConfigFileRule(),
    SyslogRule(),
    NetworkServerRule(),
]
```

- [ ] **Step 4: Write failing tests for IntentClassifier**

```python
# tests/intent/test_classifier.py
import pytest
from sepgen.intent.classifier import IntentClassifier
from sepgen.models.access import Access, AccessType
from sepgen.models.intent import IntentType

def test_classify_pid_file():
    """Test classifying PID file access"""
    classifier = IntentClassifier()
    access = Access(
        access_type=AccessType.FILE_WRITE,
        path="/var/run/myapp.pid",
        syscall="open"
    )

    intents = classifier.classify([access])
    assert len(intents) == 1
    assert intents[0].intent_type == IntentType.PID_FILE
    assert len(intents[0].accesses) == 1

def test_classify_config_file():
    """Test classifying config file access"""
    classifier = IntentClassifier()
    access = Access(
        access_type=AccessType.FILE_READ,
        path="/etc/myapp/config.ini",
        syscall="open"
    )

    intents = classifier.classify([access])
    assert len(intents) == 1
    assert intents[0].intent_type == IntentType.CONFIG_FILE

def test_classify_multiple_accesses():
    """Test classifying multiple accesses"""
    classifier = IntentClassifier()
    accesses = [
        Access(AccessType.FILE_READ, "/etc/app.conf", "open"),
        Access(AccessType.FILE_WRITE, "/var/run/app.pid", "open"),
        Access(AccessType.SOCKET_CONNECT, "/dev/log", "connect", {"is_syslog": True}),
    ]

    intents = classifier.classify(accesses)
    assert len(intents) == 3

    intent_types = {i.intent_type for i in intents}
    assert IntentType.CONFIG_FILE in intent_types
    assert IntentType.PID_FILE in intent_types
    assert IntentType.SYSLOG in intent_types

def test_classify_unknown_access():
    """Test classifying access with no matching rule"""
    classifier = IntentClassifier()
    access = Access(
        access_type=AccessType.FILE_READ,
        path="/tmp/random_file.txt",
        syscall="open"
    )

    intents = classifier.classify([access])
    assert len(intents) == 1
    assert intents[0].intent_type == IntentType.UNKNOWN
```

- [ ] **Step 5: Implement IntentClassifier**

```python
# sepgen/intent/classifier.py
from typing import List
from sepgen.models.access import Access
from sepgen.models.intent import Intent, IntentType
from sepgen.intent.rules import DEFAULT_RULES

class IntentClassifier:
    """Classify system accesses into security intents"""

    def __init__(self, rules=None):
        self.rules = rules or DEFAULT_RULES

    def classify(self, accesses: List[Access]) -> List[Intent]:
        """Classify a list of accesses into intents"""
        intents = []

        for access in accesses:
            matched = False

            # Try each rule in order (first match wins)
            for rule in self.rules:
                if rule.matches(access):
                    intent = Intent(
                        intent_type=rule.get_intent_type(),
                        accesses=[access],
                        confidence=rule.get_confidence()
                    )
                    intents.append(intent)
                    matched = True
                    break

            # No rule matched - classify as unknown
            if not matched:
                intent = Intent(
                    intent_type=IntentType.UNKNOWN,
                    accesses=[access],
                    confidence=0.5
                )
                intents.append(intent)

        return intents
```

- [ ] **Step 6: Run all tests to verify they pass**

Run: `pytest tests/intent/ -v`
Expected: PASS (all intent tests)

- [ ] **Step 7: Commit**

```bash
git add sepgen/intent/ tests/intent/
git commit -m "feat: add intent classification with rule engine"
```

---

### Task 7: SELinux Integration - Type Generator

**Files:**
- Create: `sepgen/selinux/__init__.py`
- Create: `sepgen/selinux/type_generator.py`
- Create: `tests/selinux/test_type_generator.py`

- [ ] **Step 1: Write failing tests for TypeGenerator**

```python
# tests/selinux/test_type_generator.py
import pytest
from sepgen.selinux.type_generator import TypeGenerator
from sepgen.models.intent import Intent, IntentType
from sepgen.models.access import Access, AccessType

def test_generate_config_file_type():
    """Test generating type for config file"""
    generator = TypeGenerator()
    intent = Intent(
        intent_type=IntentType.CONFIG_FILE,
        accesses=[Access(AccessType.FILE_READ, "/etc/app.conf", "open")]
    )

    type_name = generator.generate_type_name("myapp", intent)
    assert type_name == "myapp_conf_t"

def test_generate_pid_file_type():
    """Test generating type for PID file"""
    generator = TypeGenerator()
    intent = Intent(
        intent_type=IntentType.PID_FILE,
        accesses=[Access(AccessType.FILE_WRITE, "/var/run/app.pid", "open")]
    )

    type_name = generator.generate_type_name("myapp", intent)
    assert type_name == "myapp_var_run_t"

def test_generate_data_dir_type():
    """Test generating type for data directory"""
    generator = TypeGenerator()
    intent = Intent(
        intent_type=IntentType.DATA_DIR,
        accesses=[Access(AccessType.FILE_WRITE, "/var/myapp/data.txt", "open")]
    )

    type_name = generator.generate_type_name("myapp", intent)
    assert type_name == "myapp_data_t"

def test_unknown_intent_returns_none():
    """Test that unknown intents don't get custom types"""
    generator = TypeGenerator()
    intent = Intent(
        intent_type=IntentType.UNKNOWN,
        accesses=[Access(AccessType.FILE_READ, "/tmp/file.txt", "open")]
    )

    type_name = generator.generate_type_name("myapp", intent)
    assert type_name is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/selinux/test_type_generator.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'sepgen.selinux.type_generator'"

- [ ] **Step 3: Implement TypeGenerator**

```python
# sepgen/selinux/__init__.py
"""SELinux integration utilities"""
from sepgen.selinux.type_generator import TypeGenerator

__all__ = ['TypeGenerator']
```

```python
# sepgen/selinux/type_generator.py
from typing import Optional
from sepgen.models.intent import Intent, IntentType

class TypeGenerator:
    """Generate SELinux type names for intents"""

    def generate_type_name(self, module_name: str, intent: Intent) -> Optional[str]:
        """Generate type name based on intent type"""
        type_map = {
            IntentType.CONFIG_FILE: f"{module_name}_conf_t",
            IntentType.PID_FILE: f"{module_name}_var_run_t",
            IntentType.DATA_DIR: f"{module_name}_data_t",
            IntentType.LOG_FILE: f"{module_name}_log_t",
        }

        return type_map.get(intent.intent_type)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/selinux/test_type_generator.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add sepgen/selinux/ tests/selinux/
git commit -m "feat: add SELinux type name generator"
```

---

### Task 8: SELinux Integration - Macro Lookup

**Files:**
- Create: `sepgen/selinux/macro_lookup.py`
- Create: `tests/selinux/test_macro_lookup.py`

- [ ] **Step 1: Write failing tests for MacroLookup**

```python
# tests/selinux/test_macro_lookup.py
import pytest
from unittest.mock import patch
from sepgen.selinux.macro_lookup import MacroLookup
from sepgen.models.intent import Intent, IntentType
from sepgen.models.access import Access, AccessType

def test_suggest_macro_for_syslog():
    """Test suggesting hardcoded macro for syslog"""
    lookup = MacroLookup()
    intent = Intent(
        intent_type=IntentType.SYSLOG,
        accesses=[Access(AccessType.SOCKET_CONNECT, "/dev/log", "connect")]
    )

    macro = lookup.suggest_macro(intent)
    assert macro == "logging_send_syslog_msg"

def test_suggest_macro_for_pid_file():
    """Test suggesting hardcoded macro for PID file"""
    lookup = MacroLookup()
    intent = Intent(
        intent_type=IntentType.PID_FILE,
        accesses=[Access(AccessType.FILE_WRITE, "/var/run/app.pid", "open")]
    )

    macro = lookup.suggest_macro(intent)
    assert macro == "files_pid_filetrans"

def test_suggest_macro_for_config_file():
    """Test suggesting hardcoded macro for config file"""
    lookup = MacroLookup()
    intent = Intent(
        intent_type=IntentType.CONFIG_FILE,
        accesses=[Access(AccessType.FILE_READ, "/etc/app.conf", "open")]
    )

    macro = lookup.suggest_macro(intent)
    assert macro == "read_files_pattern"

def test_suggest_macro_for_unknown_intent():
    """Test that unknown intents return None from hardcoded map"""
    lookup = MacroLookup()
    intent = Intent(
        intent_type=IntentType.UNKNOWN,
        accesses=[Access(AccessType.FILE_READ, "/tmp/file.txt", "open")]
    )

    macro = lookup.suggest_macro(intent)
    # Should return None since UNKNOWN is not in hardcoded map
    # (semacro fallback not mocked in this test)
    assert macro is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/selinux/test_macro_lookup.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'sepgen.selinux.macro_lookup'"

- [ ] **Step 3: Implement MacroLookup with hybrid approach**

```python
# sepgen/selinux/macro_lookup.py
from typing import Optional
from sepgen.models.intent import Intent, IntentType

class MacroLookup:
    """Hybrid macro lookup: hardcoded mappings + semacro fallback"""

    # Hardcoded mappings for common patterns (fast path)
    KNOWN_MAPPINGS = {
        IntentType.SYSLOG: "logging_send_syslog_msg",
        IntentType.PID_FILE: "files_pid_filetrans",
        IntentType.CONFIG_FILE: "read_files_pattern",
        IntentType.LOG_FILE: "logging_log_file",
        IntentType.NETWORK_SERVER: "corenet_tcp_bind_generic_node",
        IntentType.DATA_DIR: "manage_files_pattern",
    }

    def __init__(self):
        self.semacro_available = self._check_semacro()

    def _check_semacro(self) -> bool:
        """Check if semacro is available"""
        try:
            import semacro
            return True
        except ImportError:
            return False

    def suggest_macro(self, intent: Intent) -> Optional[str]:
        """Suggest macro for intent - hardcoded first, semacro fallback"""
        # Fast path: check hardcoded mappings
        if intent.intent_type in self.KNOWN_MAPPINGS:
            return self.KNOWN_MAPPINGS[intent.intent_type]

        # Fallback: query semacro if available
        if self.semacro_available:
            return self._query_semacro(intent)

        return None

    def _query_semacro(self, intent: Intent) -> Optional[str]:
        """Query semacro for macro suggestions"""
        try:
            from semacro import search_macros
            results = search_macros(intent_type=intent.intent_type.value)
            return results[0] if results else None
        except Exception:
            return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/selinux/test_macro_lookup.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add sepgen/selinux/macro_lookup.py tests/selinux/test_macro_lookup.py
git commit -m "feat: add hybrid macro lookup with hardcoded + semacro fallback"
```

---

### Task 9: Policy Generation - TEGenerator

**Files:**
- Create: `sepgen/generator/__init__.py`
- Create: `sepgen/generator/te_generator.py`
- Create: `tests/generator/test_te_generator.py`

- [ ] **Step 1: Write failing tests for TEGenerator**

```python
# tests/generator/test_te_generator.py
import pytest
from sepgen.generator.te_generator import TEGenerator
from sepgen.models.intent import Intent, IntentType
from sepgen.models.access import Access, AccessType
from sepgen.models.policy import PolicyModule

def test_generate_basic_policy():
    """Test generating basic PolicyModule"""
    generator = TEGenerator(module_name="myapp")
    intents = [
        Intent(
            intent_type=IntentType.CONFIG_FILE,
            accesses=[Access(AccessType.FILE_READ, "/etc/myapp.conf", "open")]
        ),
    ]

    policy = generator.generate(intents)

    assert isinstance(policy, PolicyModule)
    assert policy.name == "myapp"
    assert policy.version == "1.0.0"
    # Should have base types
    type_names = [t.name for t in policy.types]
    assert "myapp_t" in type_names
    assert "myapp_exec_t" in type_names

def test_generate_with_custom_types():
    """Test that custom types are generated for intents"""
    generator = TEGenerator(module_name="myapp")
    intents = [
        Intent(
            intent_type=IntentType.CONFIG_FILE,
            accesses=[Access(AccessType.FILE_READ, "/etc/myapp.conf", "open")]
        ),
        Intent(
            intent_type=IntentType.PID_FILE,
            accesses=[Access(AccessType.FILE_WRITE, "/var/run/myapp.pid", "open")]
        ),
    ]

    policy = generator.generate(intents)

    type_names = [t.name for t in policy.types]
    assert "myapp_conf_t" in type_names
    assert "myapp_var_run_t" in type_names

def test_generate_with_macros():
    """Test that macros are added for intents"""
    generator = TEGenerator(module_name="myapp")
    intents = [
        Intent(
            intent_type=IntentType.SYSLOG,
            accesses=[Access(AccessType.SOCKET_CONNECT, "/dev/log", "connect")]
        ),
    ]

    policy = generator.generate(intents)

    macro_names = [m.name for m in policy.macro_calls]
    assert "logging_send_syslog_msg" in macro_names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/generator/test_te_generator.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'sepgen.generator.te_generator'"

- [ ] **Step 3: Implement TEGenerator**

```python
# sepgen/generator/__init__.py
"""Policy generation"""
from sepgen.generator.te_generator import TEGenerator

__all__ = ['TEGenerator']
```

```python
# sepgen/generator/te_generator.py
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

        # Add base types
        policy.add_type(f"{self.module_name}_t")
        policy.add_type(f"{self.module_name}_exec_t")

        # Add init_daemon_domain macro
        policy.add_macro("init_daemon_domain", [
            f"{self.module_name}_t",
            f"{self.module_name}_exec_t"
        ])

        # Process each intent
        for intent in intents:
            # Generate custom type if appropriate
            custom_type = self.type_generator.generate_type_name(
                self.module_name, intent
            )

            if custom_type:
                policy.add_type(custom_type)
                # Also add files_type attribute for file types
                if intent.intent_type.value in ['config_file', 'pid_file', 'data_dir', 'log_file']:
                    policy.add_macro("files_type", [custom_type])

                # Store type on intent for FC generation
                intent.selinux_type = custom_type

            # Lookup and add appropriate macro
            macro = self.macro_lookup.suggest_macro(intent)
            if macro:
                if custom_type and intent.intent_type.value in ['config_file', 'data_dir']:
                    # For file access patterns, pass both domain and type
                    policy.add_macro(macro, [
                        f"{self.module_name}_t",
                        custom_type,
                        custom_type
                    ])
                else:
                    # For other macros, just pass domain
                    policy.add_macro(macro, [f"{self.module_name}_t"])

        return policy
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/generator/test_te_generator.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add sepgen/generator/ tests/generator/
git commit -m "feat: add TE policy generator producing PolicyModule objects"
```

---

### Task 10: Policy Generation - FCGenerator

**Files:**
- Create: `sepgen/generator/fc_generator.py`
- Create: `tests/generator/test_fc_generator.py`

- [ ] **Step 1: Write failing tests for FCGenerator**

```python
# tests/generator/test_fc_generator.py
import pytest
from sepgen.generator.fc_generator import FCGenerator
from sepgen.models.intent import Intent, IntentType
from sepgen.models.access import Access, AccessType
from sepgen.models.policy import FileContexts

def test_generate_basic_fc():
    """Test generating basic FileContexts"""
    generator = FCGenerator(module_name="myapp", exec_path="/usr/bin/myapp")
    intents = []

    contexts = generator.generate(intents)

    assert isinstance(contexts, FileContexts)
    # Should have executable entry
    paths = [e.path for e in contexts.entries]
    assert "/usr/bin/myapp" in paths

def test_generate_with_config_file():
    """Test generating FC with config file context"""
    generator = FCGenerator(module_name="myapp")
    intents = [
        Intent(
            intent_type=IntentType.CONFIG_FILE,
            accesses=[Access(AccessType.FILE_READ, "/etc/myapp/config.ini", "open")],
            selinux_type="myapp_conf_t"
        ),
    ]

    contexts = generator.generate(intents)

    # Should have config file entry
    paths = [e.path for e in contexts.entries]
    assert "/etc/myapp/config.ini" in paths

    # Check type is correct
    config_entry = [e for e in contexts.entries if e.path == "/etc/myapp/config.ini"][0]
    assert config_entry.selinux_type == "myapp_conf_t"

def test_generate_multiple_contexts():
    """Test generating FC with multiple file contexts"""
    generator = FCGenerator(module_name="myapp", exec_path="/usr/bin/myapp")
    intents = [
        Intent(
            intent_type=IntentType.CONFIG_FILE,
            accesses=[Access(AccessType.FILE_READ, "/etc/myapp.conf", "open")],
            selinux_type="myapp_conf_t"
        ),
        Intent(
            intent_type=IntentType.PID_FILE,
            accesses=[Access(AccessType.FILE_WRITE, "/var/run/myapp.pid", "open")],
            selinux_type="myapp_var_run_t"
        ),
    ]

    contexts = generator.generate(intents)

    assert len(contexts.entries) >= 3  # exec + 2 files
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/generator/test_fc_generator.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'sepgen.generator.fc_generator'"

- [ ] **Step 3: Implement FCGenerator**

```python
# sepgen/generator/fc_generator.py
from typing import List, Optional
from sepgen.models.intent import Intent
from sepgen.models.policy import FileContexts

class FCGenerator:
    """Generate FileContexts objects from classified intents"""

    def __init__(self, module_name: str, exec_path: Optional[str] = None):
        self.module_name = module_name
        self.exec_path = exec_path

    def generate(self, intents: List[Intent]) -> FileContexts:
        """Generate FileContexts object (not string)"""
        contexts = FileContexts()

        # Add executable context if provided
        if self.exec_path:
            contexts.add_entry(self.exec_path, f"{self.module_name}_exec_t")

        # Extract file paths from intents
        for intent in intents:
            if not intent.selinux_type:
                continue

            for access in intent.accesses:
                # Only add file/directory accesses
                if access.path.startswith('/'):
                    contexts.add_entry(access.path, intent.selinux_type)

        return contexts
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/generator/test_fc_generator.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add sepgen/generator/fc_generator.py tests/generator/test_fc_generator.py
git commit -m "feat: add FC file context generator producing FileContexts objects"
```

---

### Task 11: Serialization - TEWriter and FCWriter

**Files:**
- Create: `sepgen/generator/te_writer.py`
- Create: `sepgen/generator/fc_writer.py`
- Create: `tests/generator/test_writers.py`

- [ ] **Step 1: Write failing tests for serializers**

```python
# tests/generator/test_writers.py
import pytest
from pathlib import Path
from sepgen.generator.te_writer import TEWriter
from sepgen.generator.fc_writer import FCWriter
from sepgen.models.policy import PolicyModule, FileContexts, TypeDeclaration, MacroCall

def test_te_writer_basic(tmp_path):
    """Test writing basic PolicyModule to .te file"""
    policy = PolicyModule(name="myapp", version="1.0.0")
    policy.types.append(TypeDeclaration("myapp_t"))
    policy.types.append(TypeDeclaration("myapp_exec_t"))
    policy.macro_calls.append(MacroCall("init_daemon_domain", ["myapp_t", "myapp_exec_t"]))

    output_path = tmp_path / "myapp.te"
    writer = TEWriter()
    writer.write(policy, output_path)

    assert output_path.exists()
    content = output_path.read_text()

    assert "policy_module(myapp, 1.0.0)" in content
    assert "type myapp_t;" in content
    assert "init_daemon_domain(myapp_t, myapp_exec_t)" in content

def test_fc_writer_basic(tmp_path):
    """Test writing basic FileContexts to .fc file"""
    contexts = FileContexts()
    contexts.add_entry("/usr/bin/myapp", "myapp_exec_t")
    contexts.add_entry("/etc/myapp.conf", "myapp_conf_t")

    output_path = tmp_path / "myapp.fc"
    writer = FCWriter()
    writer.write(contexts, output_path)

    assert output_path.exists()
    content = output_path.read_text()

    assert "/usr/bin/myapp" in content
    assert "myapp_exec_t" in content
    assert "/etc/myapp.conf" in content
    assert "gen_context" in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/generator/test_writers.py -v`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Implement TEWriter**

```python
# sepgen/generator/te_writer.py
from pathlib import Path
from sepgen.models.policy import PolicyModule

class TEWriter:
    """Serialize PolicyModule to .te file format"""

    def write(self, policy: PolicyModule, output_path: Path) -> None:
        """Generate .te file from PolicyModule object"""
        lines = []

        # Header
        lines.append(f"policy_module({policy.name}, {policy.version})")
        lines.append("")

        # Type declarations section
        lines.append("########################################")
        lines.append("# Declarations")
        lines.append("########################################")
        lines.append("")

        for type_decl in policy.types:
            lines.append(str(type_decl))

        lines.append("")

        # Policy rules section
        lines.append("########################################")
        lines.append("# Policy")
        lines.append("########################################")
        lines.append("")

        for macro in policy.macro_calls:
            lines.append(str(macro))

        for rule in policy.allow_rules:
            lines.append(str(rule))

        # Write to file
        output_path.write_text("\n".join(lines) + "\n")
```

- [ ] **Step 4: Implement FCWriter**

```python
# sepgen/generator/fc_writer.py
from pathlib import Path
from sepgen.models.policy import FileContexts

class FCWriter:
    """Serialize FileContexts to .fc file format"""

    def write(self, contexts: FileContexts, output_path: Path) -> None:
        """Generate .fc file from FileContexts object"""
        lines = []

        # Sort entries for predictable output
        for entry in sorted(contexts.entries, key=lambda e: e.path):
            lines.append(str(entry))

        # Write to file
        output_path.write_text("\n".join(lines) + "\n")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/generator/test_writers.py -v`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add sepgen/generator/te_writer.py sepgen/generator/fc_writer.py tests/generator/test_writers.py
git commit -m "feat: add policy serialization writers for .te and .fc files"
```

---

### Task 12: Merge Layer - PolicyMerger with semacro integration

**Files:**
- Create: `sepgen/merger/__init__.py`
- Create: `sepgen/merger/policy_merger.py`
- Create: `tests/merger/test_policy_merger.py`

- [ ] **Step 1: Write failing tests for PolicyMerger**

```python
# tests/merger/test_policy_merger.py
import pytest
from pathlib import Path
from sepgen.merger.policy_merger import PolicyMerger
from sepgen.models.policy import PolicyModule, TypeDeclaration, MacroCall

def test_detect_existing_policy(tmp_path, monkeypatch):
    """Test detecting existing .te/.fc files"""
    monkeypatch.chdir(tmp_path)

    # Create existing files
    (tmp_path / "myapp.te").write_text("policy_module(myapp, 1.0.0)")
    (tmp_path / "myapp.fc").write_text("/usr/bin/myapp")

    merger = PolicyMerger()
    te_path, fc_path = merger.detect_existing_policy("myapp")

    assert te_path == tmp_path / "myapp.te"
    assert fc_path == tmp_path / "myapp.fc"

def test_detect_no_existing_policy(tmp_path, monkeypatch):
    """Test when no existing policy files exist"""
    monkeypatch.chdir(tmp_path)

    merger = PolicyMerger()
    te_path, fc_path = merger.detect_existing_policy("myapp")

    assert te_path is None
    assert fc_path is None

def test_compare_policies():
    """Test comparing two PolicyModule objects"""
    existing = PolicyModule(name="myapp", version="1.0.0")
    existing.types.append(TypeDeclaration("myapp_t"))
    existing.macro_calls.append(MacroCall("read_files_pattern", ["myapp_t", "myapp_conf_t", "myapp_conf_t"]))

    new = PolicyModule(name="myapp", version="1.0.0")
    new.types.append(TypeDeclaration("myapp_t"))
    new.types.append(TypeDeclaration("myapp_data_t"))  # New type
    new.macro_calls.append(MacroCall("manage_files_pattern", ["myapp_t", "myapp_conf_t", "myapp_conf_t"]))  # Conflict

    merger = PolicyMerger()
    report = merger.compare(existing, new)

    # Should detect matched types
    assert len(report.matched_types) >= 1

    # Should detect new types
    assert "myapp_data_t" in [t.name for t in report.new_types]

    # Should detect macro conflict
    assert len(report.conflicts) >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/merger/test_policy_merger.py -v`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Implement PolicyMerger**

```python
# sepgen/merger/__init__.py
"""Policy merging utilities"""
from sepgen.merger.policy_merger import PolicyMerger, MergeReport

__all__ = ['PolicyMerger', 'MergeReport']
```

```python
# sepgen/merger/policy_merger.py
from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple, Optional, List
from sepgen.models.policy import PolicyModule, TypeDeclaration, MacroCall

@dataclass
class MergeReport:
    """Report of policy comparison"""
    matched_types: List[TypeDeclaration] = field(default_factory=list)
    new_types: List[TypeDeclaration] = field(default_factory=list)
    existing_only_types: List[TypeDeclaration] = field(default_factory=list)
    matched_macros: List[MacroCall] = field(default_factory=list)
    new_macros: List[MacroCall] = field(default_factory=list)
    conflicts: List[dict] = field(default_factory=list)

class PolicyMerger:
    """Handle policy comparison and merging"""

    def detect_existing_policy(self, module_name: str) -> Tuple[Optional[Path], Optional[Path]]:
        """Check if .te and .fc files already exist"""
        te_path = Path(f"{module_name}.te")
        fc_path = Path(f"{module_name}.fc")

        return (
            te_path if te_path.exists() else None,
            fc_path if fc_path.exists() else None
        )

    def load_existing_policy(self, te_path: Path) -> PolicyModule:
        """Parse existing .te file using semacro parser"""
        # For MVP, we'll implement basic parsing
        # In production, this would use semacro.parser
        content = te_path.read_text()

        # Extract module name and version
        import re
        module_match = re.search(r'policy_module\((\w+),\s*([\d.]+)\)', content)
        if module_match:
            name = module_match.group(1)
            version = module_match.group(2)
        else:
            name = "unknown"
            version = "1.0.0"

        policy = PolicyModule(name=name, version=version)

        # Extract types
        for match in re.finditer(r'type (\w+);', content):
            policy.types.append(TypeDeclaration(match.group(1)))

        # Extract macro calls
        for match in re.finditer(r'(\w+)\(([^)]+)\)', content):
            macro_name = match.group(1)
            args = [arg.strip() for arg in match.group(2).split(',')]
            policy.macro_calls.append(MacroCall(macro_name, args))

        return policy

    def compare(self, existing: PolicyModule, new: PolicyModule) -> MergeReport:
        """Compare two policies and identify differences"""
        report = MergeReport()

        # Compare types
        existing_type_names = {t.name for t in existing.types}
        new_type_names = {t.name for t in new.types}

        matched = existing_type_names & new_type_names
        report.matched_types = [t for t in new.types if t.name in matched]
        report.new_types = [t for t in new.types if t.name not in existing_type_names]
        report.existing_only_types = [t for t in existing.types if t.name not in new_type_names]

        # Compare macros (detect conflicts)
        existing_macros = {(m.name, tuple(m.args)): m for m in existing.macro_calls}
        new_macros = {(m.name, tuple(m.args)): m for m in new.macro_calls}

        # Find conflicts: same macro name but different args
        for new_key, new_macro in new_macros.items():
            macro_name = new_key[0]
            # Look for same macro name with different args
            for existing_key, existing_macro in existing_macros.items():
                if existing_key[0] == macro_name and existing_key != new_key:
                    report.conflicts.append({
                        'type': 'macro',
                        'name': macro_name,
                        'existing': existing_macro,
                        'new': new_macro
                    })
                    break

        # Matched macros (exact match)
        matched_macro_keys = set(existing_macros.keys()) & set(new_macros.keys())
        report.matched_macros = [new_macros[k] for k in matched_macro_keys]

        # New macros
        new_macro_keys = set(new_macros.keys()) - set(existing_macros.keys())
        report.new_macros = [new_macros[k] for k in new_macro_keys]

        return report

    def merge(
        self,
        existing: PolicyModule,
        new: PolicyModule,
        strategy: str = "trace-wins",
        auto_approve: bool = False
    ) -> PolicyModule:
        """Merge policies according to strategy"""
        report = self.compare(existing, new)

        # Start with existing policy
        merged = PolicyModule(name=existing.name, version=existing.version)
        merged.types = existing.types.copy()
        merged.macro_calls = existing.macro_calls.copy()
        merged.allow_rules = existing.allow_rules.copy()

        # Add new types
        for new_type in report.new_types:
            merged.types.append(new_type)

        # Handle conflicts
        if strategy == "trace-wins":
            if auto_approve or not report.conflicts:
                # Auto-resolve: replace with new (trace) version
                for conflict in report.conflicts:
                    # Remove old macro
                    merged.macro_calls = [
                        m for m in merged.macro_calls
                        if not (m.name == conflict['existing'].name)
                    ]
                    # Add new macro
                    merged.macro_calls.append(conflict['new'])
            else:
                # Interactive resolution would go here
                # For now, just log conflicts
                pass

        # Add new macros (non-conflicting)
        for new_macro in report.new_macros:
            merged.macro_calls.append(new_macro)

        return merged
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/merger/test_policy_merger.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add sepgen/merger/ tests/merger/
git commit -m "feat: add policy merger with comparison and conflict detection"
```

---

### Task 13: CLI Integration - analyze command

**Files:**
- Create: `sepgen/__main__.py`
- Create: `sepgen/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write failing test for CLI structure**

```python
# tests/test_cli.py
import pytest
from sepgen.cli import create_parser

def test_cli_has_analyze_command():
    """Test that analyze subcommand exists"""
    parser = create_parser()
    args = parser.parse_args(['analyze', '/path/to/source'])

    assert args.command == 'analyze'
    assert args.source_path == '/path/to/source'

def test_cli_has_trace_command():
    """Test that trace subcommand exists"""
    parser = create_parser()
    args = parser.parse_args(['trace', '/usr/bin/app'])

    assert args.command == 'trace'
    assert args.binary == '/usr/bin/app'

def test_cli_verbosity_flags():
    """Test that -v and -vv flags work"""
    parser = create_parser()

    args = parser.parse_args(['trace', '/usr/bin/app', '-v'])
    assert args.verbose >= 1

    args = parser.parse_args(['trace', '/usr/bin/app', '-vv'])
    assert args.verbose >= 2

def test_cli_auto_merge_flag():
    """Test that -y flag works"""
    parser = create_parser()
    args = parser.parse_args(['trace', '/usr/bin/app', '-y'])

    assert args.auto_merge == True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Implement basic CLI structure**

```python
# sepgen/__main__.py
import sys
from sepgen.cli import main

if __name__ == '__main__':
    sys.exit(main())
```

```python
# sepgen/cli.py
import argparse
from pathlib import Path
from typing import Optional

def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser"""
    parser = argparse.ArgumentParser(
        prog='sepgen',
        description='SELinux policy generator with static analysis and runtime tracing'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # analyze subcommand
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Generate policy from static source code analysis'
    )
    analyze_parser.add_argument(
        'source_path',
        help='Path to source code directory or file'
    )
    analyze_parser.add_argument(
        '--name',
        help='Policy module name (default: derived from source)',
        default=None
    )
    analyze_parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='Increase verbosity (-v for verbose, -vv for debug)'
    )

    # trace subcommand
    trace_parser = subparsers.add_parser(
        'trace',
        help='Generate policy from strace runtime tracing'
    )
    trace_parser.add_argument(
        'binary',
        help='Path to binary to trace'
    )
    trace_parser.add_argument(
        '--args',
        help='Arguments to pass to the binary',
        default=''
    )
    trace_parser.add_argument(
        '--pid',
        type=int,
        help='Attach to existing process ID',
        default=None
    )
    trace_parser.add_argument(
        '-y', '--auto-merge',
        action='store_true',
        help='Auto-approve merge conflicts (trace wins)'
    )
    trace_parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='Increase verbosity (-v for verbose, -vv for debug)'
    )

    return parser

def main(argv: Optional[list[str]] = None) -> int:
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'analyze':
        return run_analyze(args)
    elif args.command == 'trace':
        return run_trace(args)

    return 0

def run_analyze(args) -> int:
    """Execute analyze command"""
    print(f"Analyzing source: {args.source_path}")
    # Implementation will be added in next step
    return 0

def run_trace(args) -> int:
    """Execute trace command"""
    print(f"Tracing binary: {args.binary}")
    # Implementation will be added in next step
    return 0
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Write integration test for analyze workflow**

```python
# tests/test_cli.py - add to existing file

def test_analyze_workflow(tmp_path, monkeypatch):
    """Test complete analyze workflow"""
    from sepgen.cli import main

    monkeypatch.chdir(tmp_path)

    # Create test C file
    c_file = tmp_path / "test.c"
    c_file.write_text('''
    #include <stdio.h>
    int main() {
        fopen("/etc/test.conf", "r");
        return 0;
    }
    ''')

    # Run analyze
    result = main(['analyze', str(c_file), '--name', 'testapp'])

    assert result == 0
    # Should create .te and .fc files
    assert (tmp_path / "testapp.te").exists()
    assert (tmp_path / "testapp.fc").exists()

    # Verify content
    te_content = (tmp_path / "testapp.te").read_text()
    assert "policy_module(testapp," in te_content
    assert "type testapp_t;" in te_content
```

- [ ] **Step 6: Implement analyze workflow**

```python
# sepgen/cli.py - replace run_analyze function

def run_analyze(args) -> int:
    """Execute analyze command"""
    from sepgen.analyzer.c_analyzer import CAnalyzer
    from sepgen.intent.classifier import IntentClassifier
    from sepgen.generator.te_generator import TEGenerator
    from sepgen.generator.fc_generator import FCGenerator
    from sepgen.generator.te_writer import TEWriter
    from sepgen.generator.fc_writer import FCWriter

    source_path = Path(args.source_path)
    module_name = args.name or source_path.stem

    # Progress indicator
    print(f"[1/3] Analyzing source... ", end='', flush=True)

    # Analyze source code
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_file(source_path)

    print(f"✓")
    print(f"[2/3] Classifying intents... ", end='', flush=True)

    # Classify intents
    classifier = IntentClassifier()
    intents = classifier.classify(accesses)

    print(f"✓")

    if args.verbose >= 1:
        for intent in intents:
            print(f"  • {intent.intent_type.value}: {intent.accesses[0].path}")

    print(f"[3/3] Generating policy... ", end='', flush=True)

    # Generate policy objects
    te_gen = TEGenerator(module_name)
    policy = te_gen.generate(intents)

    fc_gen = FCGenerator(module_name)
    contexts = fc_gen.generate(intents)

    # Write to files
    te_writer = TEWriter()
    fc_writer = FCWriter()

    te_path = Path(f"{module_name}.te")
    fc_path = Path(f"{module_name}.fc")

    te_writer.write(policy, te_path)
    fc_writer.write(contexts, fc_path)

    print(f"✓")
    print(f"Generated: {te_path} ({len(policy.types)} types), {fc_path} ({len(contexts.entries)} entries)")

    return 0
```

- [ ] **Step 7: Run integration test to verify it passes**

Run: `pytest tests/test_cli.py::test_analyze_workflow -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add sepgen/__main__.py sepgen/cli.py tests/test_cli.py
git commit -m "feat: add CLI with analyze command integration"
```

---

### Task 14: CLI Integration - trace command with auto-merge

**Files:**
- Modify: `sepgen/cli.py`
- Create: `tests/test_cli_trace.py`

- [ ] **Step 1: Write integration test for trace workflow**

```python
# tests/test_cli_trace.py
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from sepgen.cli import main

def test_trace_workflow_no_existing_policy(tmp_path, monkeypatch):
    """Test trace workflow when no existing policy exists"""
    monkeypatch.chdir(tmp_path)

    # Mock strace execution
    with patch('sepgen.tracer.process_tracer.subprocess.run'):
        # Mock strace output file
        strace_output = tmp_path / "test.strace"
        strace_output.write_text('open("/etc/test.conf", O_RDONLY) = 3\n')

        with patch('sepgen.tracer.process_tracer.ProcessTracer.trace', return_value=strace_output):
            result = main(['trace', '/usr/bin/test', '--name', 'testapp'])

            assert result == 0
            assert (tmp_path / "testapp.te").exists()
            assert (tmp_path / "testapp.fc").exists()

def test_trace_workflow_with_existing_policy(tmp_path, monkeypatch):
    """Test trace workflow with existing policy (merge scenario)"""
    monkeypatch.chdir(tmp_path)

    # Create existing policy
    (tmp_path / "testapp.te").write_text('''policy_module(testapp, 1.0.0)
type testapp_t;
type testapp_exec_t;
''')
    (tmp_path / "testapp.fc").write_text('/usr/bin/test')

    # Mock strace
    strace_output = tmp_path / "test.strace"
    strace_output.write_text('open("/etc/test.conf", O_RDONLY) = 3\n')

    with patch('sepgen.tracer.process_tracer.subprocess.run'):
        with patch('sepgen.tracer.process_tracer.ProcessTracer.trace', return_value=strace_output):
            # Should detect existing policy
            with patch('builtins.input', return_value='Y'):  # Auto-approve merge
                result = main(['trace', '/usr/bin/test', '--name', 'testapp'])

                assert result == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli_trace.py -v`
Expected: FAIL (run_trace not fully implemented)

- [ ] **Step 3: Implement trace workflow with merge detection**

```python
# sepgen/cli.py - replace run_trace function

def run_trace(args) -> int:
    """Execute trace command"""
    from sepgen.tracer.process_tracer import ProcessTracer
    from sepgen.tracer.strace_parser import StraceParser
    from sepgen.intent.classifier import IntentClassifier
    from sepgen.generator.te_generator import TEGenerator
    from sepgen.generator.fc_generator import FCGenerator
    from sepgen.generator.te_writer import TEWriter
    from sepgen.generator.fc_writer import FCWriter
    from sepgen.merger.policy_merger import PolicyMerger

    binary_path = Path(args.binary)
    module_name = getattr(args, 'name', None) or binary_path.stem

    # Check for existing policy
    merger = PolicyMerger()
    existing_te, existing_fc = merger.detect_existing_policy(module_name)

    if existing_te:
        print(f"\nFound existing policy: {existing_te}")

    # Progress indicator
    print(f"[1/4] Tracing process... ", end='', flush=True)

    # Trace the process
    tracer = ProcessTracer()
    strace_file = tracer.trace(
        binary=args.binary if not args.pid else None,
        args=args.args,
        pid=args.pid
    )

    print(f"✓")
    print(f"[2/4] Parsing syscalls... ", end='', flush=True)

    # Parse strace output
    parser = StraceParser()
    accesses = parser.parse_file(strace_file)

    print(f"✓")
    print(f"[3/4] Classifying intents... ", end='', flush=True)

    # Classify intents
    classifier = IntentClassifier()
    intents = classifier.classify(accesses)

    print(f"✓")

    if args.verbose >= 1:
        for intent in intents:
            print(f"  • {intent.intent_type.value}: {intent.accesses[0].path}")

    print(f"[4/4] Generating policy... ", end='', flush=True)

    # Generate new policy objects
    te_gen = TEGenerator(module_name)
    new_policy = te_gen.generate(intents)

    fc_gen = FCGenerator(module_name, exec_path=args.binary)
    new_contexts = fc_gen.generate(intents)

    # Handle merge if existing policy found
    if existing_te:
        print(f"✓")
        print("\nComparing with runtime trace...")

        # Load and compare
        existing_policy = merger.load_existing_policy(existing_te)
        report = merger.compare(existing_policy, new_policy)

        print(f"\nComparison:")
        print(f"  Static analysis: {len(existing_policy.types)} types")
        print(f"  Runtime trace:   {len(new_policy.types)} types")
        print(f"  Matched:        {len(report.matched_types)} types")

        if report.conflicts:
            print(f"\nConflicts found: {len(report.conflicts)}")
            for conflict in report.conflicts:
                print(f"  • {conflict['name']}")
                print(f"    Existing: {conflict['existing']}")
                print(f"    Trace:    {conflict['new']}")

        # Auto-merge or prompt
        if args.auto_merge:
            print("\nMerging policies (auto-approved)... ", end='', flush=True)
            final_policy = merger.merge(existing_policy, new_policy, auto_approve=True)
            print("✓")
        else:
            response = input("\nMerge with trace results? [Y/n/diff] ").strip().lower()
            if response in ['y', '']:
                final_policy = merger.merge(existing_policy, new_policy, auto_approve=True)
            else:
                print("Skipping merge.")
                return 0

        # Backup existing files
        backup_te = Path(f"{module_name}.te.backup")
        backup_fc = Path(f"{module_name}.fc.backup")
        existing_te.rename(backup_te)
        if existing_fc:
            existing_fc.rename(backup_fc)

        print(f"Backup saved: {backup_te}")
    else:
        final_policy = new_policy
        print(f"✓")

    # Write policy files
    te_writer = TEWriter()
    fc_writer = FCWriter()

    te_path = Path(f"{module_name}.te")
    fc_path = Path(f"{module_name}.fc")

    te_writer.write(final_policy, te_path)
    fc_writer.write(new_contexts, fc_path)

    print(f"\nGenerated: {te_path} ({len(final_policy.types)} types), {fc_path} ({len(new_contexts.entries)} entries)")

    return 0
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli_trace.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add sepgen/cli.py tests/test_cli_trace.py
git commit -m "feat: add trace command with auto-merge detection"
```

---

### Task 15: End-to-End Integration Test

**Files:**
- Create: `tests/integration/test_e2e.py`

- [ ] **Step 1: Write end-to-end integration test**

```python
# tests/integration/test_e2e.py
import pytest
from pathlib import Path
from sepgen.cli import main

def test_e2e_analyze_then_trace(tmp_path, monkeypatch):
    """Test full workflow: analyze → trace → merge"""
    monkeypatch.chdir(tmp_path)

    # Create test C program
    c_file = tmp_path / "myapp.c"
    c_file.write_text('''
    #include <stdio.h>
    int main() {
        FILE *f = fopen("/etc/myapp.conf", "r");
        fclose(f);
        return 0;
    }
    ''')

    # Step 1: Analyze source
    result = main(['analyze', str(c_file), '--name', 'myapp'])
    assert result == 0
    assert (tmp_path / "myapp.te").exists()

    # Verify initial policy
    te_content = (tmp_path / "myapp.te").read_text()
    assert "myapp_conf_t" in te_content

    # Step 2: Trace (simulated with mock)
    from unittest.mock import patch

    strace_output = tmp_path / "test.strace"
    strace_output.write_text('''
open("/etc/myapp.conf", O_RDONLY) = 3
open("/var/run/myapp.pid", O_WRONLY|O_CREAT, 0644) = 4
''')

    with patch('sepgen.tracer.process_tracer.subprocess.run'):
        with patch('sepgen.tracer.process_tracer.ProcessTracer.trace', return_value=strace_output):
            with patch('builtins.input', return_value='Y'):  # Auto-approve merge
                result = main(['trace', '/usr/bin/myapp', '--name', 'myapp'])

                assert result == 0

    # Verify merged policy includes both intents
    te_content = (tmp_path / "myapp.te").read_text()
    assert "myapp_conf_t" in te_content  # From analyze
    assert "myapp_var_run_t" in te_content  # From trace

    # Verify backup was created
    assert (tmp_path / "myapp.te.backup").exists()
```

- [ ] **Step 2: Run test to verify it passes**

Run: `pytest tests/integration/test_e2e.py -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration/
git commit -m "test: add end-to-end integration test"
```

---

### Task 16: Documentation

**Files:**
- Modify: `README.md`
- Create: `docs/architecture.md`

- [ ] **Step 1: Update README with installation and usage**

Add to README.md:
- Installation section with pip install
- Quick start guide
- Examples of analyze and trace commands
- Reference to design document

- [ ] **Step 2: Create architecture documentation**

Create `docs/architecture.md` linking to design spec and implementation details

- [ ] **Step 3: Commit documentation**

```bash
git add README.md docs/architecture.md
git commit -m "docs: update README and add architecture documentation"
```

---

## Review and Execution

**Plan complete!** This implementation provides:

✅ **Core Functionality:**
- Dual-mode operation (analyze + trace)
- Intent classification with deterministic rules
- Object-based policy generation
- Auto-merge with trace-wins strategy
- Macro lookup (hybrid: hardcoded + semacro)
- Complete .te and .fc generation

✅ **Testing:**
- Unit tests for all components
- Integration tests for CLI workflows
- End-to-end test covering analyze → trace → merge

✅ **Architecture:**
- Clean separation of concerns
- Extensible interfaces for future enhancements
- Object-based policy model
- Proper error handling foundations

🚧 **Future Enhancements (documented in design spec):**
- Tree-sitter AST parsing
- Interactive tracing mode
- Multi-session management
- Validation mode
- Error collector with summary
- Verbosity system (partially implemented)
- .if interface generation

---

## Success Criteria

Implementation is complete when:
1. ✅ `sepgen analyze <source>` generates .te and .fc files
2. ✅ `sepgen trace <binary>` generates .te and .fc files
3. ✅ Second run detects existing policy and offers merge
4. ✅ `-y` flag auto-approves merge
5. ✅ Generated policy uses macros (not raw rules)
6. ✅ Generated policy includes custom types
7. ✅ All unit tests pass
8. ✅ Integration tests pass
9. ✅ End-to-end test passes

