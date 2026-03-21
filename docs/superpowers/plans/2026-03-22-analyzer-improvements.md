# Analyzer Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve C analyzer coverage from 8-10% to 60-80% based on mcstransd analysis findings

**Architecture:** Enhance regex-based static analysis with function detection, #define resolution, multi-file support, and intelligent path classification

**Tech Stack:** Python 3.9+, regex, existing sepgen architecture

**Analysis Reference:** `testing/mcstrans/ANALYSIS_REPORT.md`
**Design Document:** `docs/superpowers/specs/2026-03-21-sepgen-design.md` (v1.2 — updated to reflect these improvements)

**Naming conventions (aligned with existing code):**
- Analyzer method: `analyze_string()` (not `analyze_source`)
- File unlink type: `AccessType.FILE_UNLINK` (already exists, not `FILE_DELETE`)
- AllowRule field: `object_class` (not `class_name`)
- Rule base class: `ClassificationRule` (not `IntentRule`)
- Policy helpers: `policy.add_type()`, `policy.add_macro()` (not direct `.append()` on internal lists)

**Milestone Commits:**
- After P0 tasks → "feat: add P0 analyzer improvements (critical detection)"
- After P1 tasks → "feat: add P1 analyzer improvements (significant coverage)"
- After P2 tasks → "feat: add P2 analyzer improvements (full refinement)"

---

## P0: Critical High-Impact Improvements

### Task 1: Detect syslog() and openlog() Calls

**Files:**
- Modify: `sepgen/analyzer/c_analyzer.py`
- Modify: `sepgen/models/access.py` (add SYSLOG access type if needed)
- Modify: `sepgen/intent/rules.py` (add SyslogRule if not exists)
- Create: `tests/analyzer/test_syslog_detection.py`

- [ ] **Step 1: Write failing test for syslog detection**

```python
def test_detect_openlog():
    code = '''
    #include <syslog.h>
    int main() {
        openlog("myapp", LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO, "Started");
    }
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    syslog_accesses = [a for a in accesses if a.access_type == AccessType.SYSLOG]
    # Deduplicated: one per distinct function name (openlog + syslog = 2)
    assert len(syslog_accesses) == 2
    funcs = {a.details["function"] for a in syslog_accesses}
    assert funcs == {"openlog", "syslog"}
    assert syslog_accesses[0].syscall == "connect"
    assert "/dev/log" in syslog_accesses[0].path

def test_syslog_maps_to_logging_macro():
    classifier = IntentClassifier()
    intents = classifier.classify([Access(AccessType.SYSLOG, "/dev/log", "connect", {})])
    assert len(intents) == 1
    assert intents[0].intent_type == IntentType.SYSLOG
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/analyzer/test_syslog_detection.py -v`
Expected: FAIL (syslog not detected)

- [ ] **Step 3: Add syslog patterns to CAnalyzer**

In `sepgen/analyzer/c_analyzer.py`:

```python
SYSLOG_PATTERN = re.compile(r'\b(syslog|openlog|vsyslog)\s*\(')

def _detect_syslog(self, code: str) -> List[Access]:
    """Detect syslog/openlog calls — deduplicated.

    A program may call syslog() dozens of times but only one
    logging_send_syslog_msg() macro is needed. Emit one Access
    per distinct function name found (openlog, syslog, vsyslog).
    """
    seen_functions = set()
    accesses = []
    for match in self.SYSLOG_PATTERN.finditer(code):
        func = match.group(1)
        if func in seen_functions:
            continue
        seen_functions.add(func)
        accesses.append(Access(
            access_type=AccessType.SYSLOG,
            path="/dev/log",
            syscall="connect",
            details={"function": func},
            source_line=code[:match.start()].count('\n') + 1
        ))
    return accesses
```

- [ ] **Step 4: Update SyslogRule in intent classifier**

In `sepgen/intent/rules.py`, update the existing `SyslogRule` to also match by `AccessType.SYSLOG` (currently it only matches `path == "/dev/log"` with `is_syslog` detail):

```python
class SyslogRule(ClassificationRule):
    def matches(self, access: Access) -> bool:
        if access.access_type == AccessType.SYSLOG:
            return True
        return (access.path == "/dev/log" and
                access.details.get("is_syslog", False))

    def get_intent_type(self) -> IntentType:
        return IntentType.SYSLOG
```

- [ ] **Step 5: Run test to verify pass**

Run: `pytest tests/analyzer/test_syslog_detection.py -v`
Expected: PASS

- [ ] **Step 6: Test against mcstransd source**

Run: `sepgen analyze testing/mcstrans/src/mcstransd.c --name setrans -v | grep syslog`
Expected: See "logging_send_syslog_msg(setrans_t)" in output

- [ ] **Step 7: Commit**

```bash
git add sepgen/analyzer/c_analyzer.py sepgen/intent/rules.py sepgen/models/access.py tests/analyzer/test_syslog_detection.py
git commit -m "feat: detect syslog/openlog calls for logging_send_syslog_msg macro"
```

---

### Task 2: Detect listen() and accept() Calls

**Files:**
- Modify: `sepgen/analyzer/c_analyzer.py`
- Modify: `sepgen/intent/classifier.py`
- Create: `tests/analyzer/test_socket_server_detection.py`

- [ ] **Step 1: Write failing test for socket server detection**

```python
def test_detect_socket_server_pattern():
    code = '''
    int sock = socket(PF_UNIX, SOCK_STREAM, 0);
    bind(sock, ...);
    listen(sock, 5);
    int client = accept(sock, NULL, NULL);
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    listen_calls = [a for a in accesses if "listen" in a.syscall]
    accept_calls = [a for a in accesses if "accept" in a.syscall]
    assert len(listen_calls) == 1
    assert len(accept_calls) == 1
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/analyzer/test_socket_server_detection.py::test_detect_socket_server_pattern -v`
Expected: FAIL

- [ ] **Step 3: Add listen/accept patterns**

```python
LISTEN_PATTERN = re.compile(r'\blisten\s*\(')
ACCEPT_PATTERN = re.compile(r'\baccept\s*\(')

def _detect_listen(self, code: str) -> List[Access]:
    accesses = []
    for match in self.LISTEN_PATTERN.finditer(code):
        accesses.append(Access(
            access_type=AccessType.SOCKET_LISTEN,
            path="",
            syscall="listen",
            details={},
            source_line=code[:match.start()].count('\n') + 1
        ))
    return accesses

def _detect_accept(self, code: str) -> List[Access]:
    accesses = []
    for match in self.ACCEPT_PATTERN.finditer(code):
        accesses.append(Access(
            access_type=AccessType.SOCKET_ACCEPT,
            path="",
            syscall="accept",
            details={},
            source_line=code[:match.start()].count('\n') + 1
        ))
    return accesses
```

- [ ] **Step 4: Run test to verify pass**

Run: `pytest tests/analyzer/test_socket_server_detection.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add sepgen/analyzer/c_analyzer.py tests/analyzer/test_socket_server_detection.py
git commit -m "feat: detect listen() and accept() calls for socket server patterns"
```

---

### Task 3: Resolve #define String Constants

**Files:**
- Create: `sepgen/analyzer/preprocessor.py`
- Modify: `sepgen/analyzer/c_analyzer.py`
- Create: `tests/analyzer/test_define_resolution.py`

- [ ] **Step 1: Write failing test**

```python
def test_resolve_define_in_fopen():
    code = '''
    #define CONFIG_FILE "/etc/myapp.conf"
    #define SOCKET_PATH "/var/run/setrans/.setrans-unix"

    void init() {
        FILE *f = fopen(CONFIG_FILE, "r");
        sock = socket(PF_UNIX, SOCK_STREAM, 0);
        bind(sock, SOCKET_PATH, ...);
    }
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    file_accesses = [a for a in accesses if a.access_type == AccessType.FILE_READ]
    assert len(file_accesses) == 1
    assert file_accesses[0].path == "/etc/myapp.conf"

    socket_accesses = [a for a in accesses if "bind" in a.syscall]
    assert socket_accesses[0].path == "/var/run/setrans/.setrans-unix"
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/analyzer/test_define_resolution.py -v`
Expected: FAIL (defines not resolved)

- [ ] **Step 3: Create preprocessor module**

In `sepgen/analyzer/preprocessor.py`:

```python
import re
from typing import Dict

class Preprocessor:
    DEFINE_PATTERN = re.compile(r'#define\s+(\w+)\s+"([^"]+)"')

    def __init__(self):
        self.defines: Dict[str, str] = {}

    def extract_defines(self, code: str) -> Dict[str, str]:
        """Extract all #define string constants"""
        defines = {}
        for match in self.DEFINE_PATTERN.finditer(code):
            macro_name = match.group(1)
            value = match.group(2)
            defines[macro_name] = value
        return defines

    def expand_macros(self, text: str, defines: Dict[str, str]) -> str:
        """Replace macro names with their values"""
        for macro, value in defines.items():
            # Match macro as whole word
            pattern = r'\b' + re.escape(macro) + r'\b'
            text = re.sub(pattern, f'"{value}"', text)
        return text
```

- [ ] **Step 4: Integrate preprocessor into CAnalyzer**

Update `analyze_string()` to run preprocessing before detection:

```python
def analyze_string(self, code: str) -> List[Access]:
    # Extract defines first
    defines = self.preprocessor.extract_defines(code)

    # Expand macros in code
    expanded_code = self.preprocessor.expand_macros(code, defines)

    # Now run existing detection on expanded code
    accesses = []
    accesses.extend(self._detect_fopen(expanded_code))
    accesses.extend(self._detect_socket(expanded_code))
    # ... rest of detection
    return accesses
```

- [ ] **Step 5: Run test to verify pass**

Run: `pytest tests/analyzer/test_define_resolution.py -v`
Expected: PASS

- [ ] **Step 6: Test with mcstransd**

Run: `sepgen analyze testing/mcstrans/src/mcstransd.c --name setrans -v | grep setrans-unix`
Expected: See `/var/run/setrans/.setrans-unix` in output

- [ ] **Step 7: Commit**

```bash
git add sepgen/analyzer/preprocessor.py sepgen/analyzer/c_analyzer.py tests/analyzer/test_define_resolution.py
git commit -m "feat: resolve #define string constants for path detection"
```

---

### Task 4: Detect unlink(), chmod(), and open() Calls

**Files:**
- Modify: `sepgen/analyzer/c_analyzer.py`
- Modify: `sepgen/models/access.py` (add FILE_SETATTR; FILE_UNLINK already exists)
- Create: `tests/analyzer/test_file_manipulation.py`

- [ ] **Step 1: Write failing test**

```python
def test_detect_unlink():
    code = 'unlink("/tmp/socket");'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.FILE_UNLINK
    assert accesses[0].path == "/tmp/socket"
    assert accesses[0].syscall == "unlink"

def test_detect_chmod():
    code = 'chmod("/etc/myapp.conf", 0644);'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.FILE_SETATTR
    assert accesses[0].path == "/etc/myapp.conf"
```

- [ ] **Step 2: Run test**

Run: `pytest tests/analyzer/test_file_manipulation.py -v`
Expected: FAIL

- [ ] **Step 3: Add patterns**

```python
UNLINK_PATTERN = re.compile(r'\bunlink\s*\(\s*"([^"]+)"\s*\)')
CHMOD_PATTERN = re.compile(r'\bchmod\s*\(\s*"([^"]+)"')
CHOWN_PATTERN = re.compile(r'\bchown\s*\(\s*"([^"]+)"')
OPEN_PATTERN = re.compile(r'\bopen\s*\(\s*"([^"]+)"\s*,\s*([^)]+)\)')

def _detect_unlink(self, code: str) -> List[Access]:
    accesses = []
    for match in self.UNLINK_PATTERN.finditer(code):
        accesses.append(Access(
            access_type=AccessType.FILE_UNLINK,
            path=match.group(1),
            syscall="unlink",
            details={},
            source_line=code[:match.start()].count('\n') + 1
        ))
    return accesses

def _detect_chmod(self, code: str) -> List[Access]:
    accesses = []
    for match in self.CHMOD_PATTERN.finditer(code):
        accesses.append(Access(
            access_type=AccessType.FILE_SETATTR,
            path=match.group(1),
            syscall="chmod",
            details={},
            source_line=code[:match.start()].count('\n') + 1
        ))
    return accesses

def _detect_open(self, code: str) -> List[Access]:
    """Detect C-level open() calls (distinct from fopen).

    Parses flags like O_RDONLY, O_WRONLY, O_RDWR, O_CREAT to
    determine FILE_READ vs FILE_WRITE vs FILE_CREATE.
    """
    accesses = []
    for match in self.OPEN_PATTERN.finditer(code):
        path = match.group(1)
        flags = match.group(2)
        if "O_WRONLY" in flags or "O_RDWR" in flags:
            access_type = AccessType.FILE_WRITE
        elif "O_CREAT" in flags:
            access_type = AccessType.FILE_CREATE
        else:
            access_type = AccessType.FILE_READ
        accesses.append(Access(
            access_type=access_type,
            path=path,
            syscall="open",
            details={"flags": flags.strip()},
            source_line=code[:match.start()].count('\n') + 1
        ))
    return accesses
```

Add a test for `open()`:

```python
def test_detect_open():
    code = '''
    int fd = open("/etc/myapp.conf", O_RDONLY);
    int fd2 = open("/var/log/myapp.log", O_WRONLY | O_CREAT, 0644);
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    reads = [a for a in accesses if a.access_type == AccessType.FILE_READ]
    writes = [a for a in accesses if a.access_type == AccessType.FILE_WRITE]
    assert len(reads) == 1
    assert reads[0].path == "/etc/myapp.conf"
    assert len(writes) == 1
    assert writes[0].path == "/var/log/myapp.log"
```

- [ ] **Step 4: Run test to verify pass**

Run: `pytest tests/analyzer/test_file_manipulation.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add sepgen/analyzer/c_analyzer.py sepgen/models/access.py tests/analyzer/test_file_manipulation.py
git commit -m "feat: detect unlink(), chmod(), and open() calls for file operations"
```

---

### Task 5: Distinguish PF_UNIX vs AF_INET Sockets

**Files:**
- Modify: `sepgen/analyzer/c_analyzer.py`
- Modify: `sepgen/intent/rules.py`
- Modify: `sepgen/selinux/macro_lookup.py`
- Create: `tests/analyzer/test_socket_types.py`

- [ ] **Step 1: Write failing test**

```python
def test_unix_socket_vs_tcp():
    unix_code = 'socket(PF_UNIX, SOCK_STREAM, 0); bind(sock, ...);'
    tcp_code = 'socket(AF_INET, SOCK_STREAM, 0); bind(sock, ...);'

    analyzer = CAnalyzer()
    unix_accesses = analyzer.analyze_string(unix_code)
    tcp_accesses = analyzer.analyze_string(tcp_code)

    classifier = IntentClassifier()
    unix_intents = classifier.classify(unix_accesses)
    tcp_intents = classifier.classify(tcp_accesses)

    # Unix socket should classify as UNIX_SOCKET_SERVER, not NETWORK_SERVER
    unix_bind = [i for i in unix_intents if i.intent_type != IntentType.UNKNOWN]
    assert any(i.intent_type == IntentType.UNIX_SOCKET_SERVER for i in unix_bind)

    # TCP socket should classify as NETWORK_SERVER
    tcp_bind = [i for i in tcp_intents if i.intent_type != IntentType.UNKNOWN]
    assert any(i.intent_type == IntentType.NETWORK_SERVER for i in tcp_bind)
```

- [ ] **Step 2: Run test**

Run: `pytest tests/analyzer/test_socket_types.py -v`
Expected: FAIL (both treated as TCP)

- [ ] **Step 3: Track socket domain in Access details and propagate to bind**

Update `_detect_socket` to store the domain, and update `_detect_bind` to use the last-seen socket domain:

```python
SOCKET_PATTERN = re.compile(r'\bsocket\s*\(\s*(PF_UNIX|PF_INET|AF_UNIX|AF_INET|PF_INET6|AF_INET6)')

def _detect_socket(self, code: str) -> List[Access]:
    accesses = []
    for match in self.SOCKET_PATTERN.finditer(code):
        domain = match.group(1)
        self._last_socket_domain = domain
        accesses.append(Access(
            access_type=AccessType.SOCKET_CREATE,
            path=f"{domain}:SOCK_STREAM",
            syscall="socket",
            details={"domain": domain},
            source_line=code[:match.start()].count('\n') + 1
        ))
    return accesses
```

Update `_detect_bind` to carry the domain forward:

```python
def _detect_bind(self, code: str) -> List[Access]:
    accesses = []
    if 'bind(' in code:
        domain = getattr(self, '_last_socket_domain', None)
        accesses.append(Access(
            access_type=AccessType.SOCKET_BIND,
            path="",
            syscall="bind",
            details={"domain": domain},
        ))
    return accesses
```

- [ ] **Step 4: Update NetworkServerRule and add UnixSocketRule**

In `sepgen/intent/rules.py`, update `NetworkServerRule` to only match inet sockets and add a new `UnixSocketRule`:

```python
class UnixSocketRule(ClassificationRule):
    """Classify Unix domain socket server operations"""
    def matches(self, access: Access) -> bool:
        if access.access_type != AccessType.SOCKET_BIND:
            return False
        return access.details.get("domain") in ["AF_UNIX", "PF_UNIX"]

    def get_intent_type(self) -> IntentType:
        return IntentType.UNIX_SOCKET_SERVER

class NetworkServerRule(ClassificationRule):
    """Classify TCP/UDP network server operations"""
    def matches(self, access: Access) -> bool:
        if access.access_type != AccessType.SOCKET_BIND:
            return False
        domain = access.details.get("domain")
        if domain:
            return domain in ["AF_INET", "PF_INET", "AF_INET6", "PF_INET6"]
        return True  # fallback: no domain info assumes inet

    def get_intent_type(self) -> IntentType:
        return IntentType.NETWORK_SERVER
```

Add `UnixSocketRule()` before `NetworkServerRule()` in DEFAULT_RULES so Unix sockets match first.

Note: `UNIX_SOCKET_SERVER` intents produce `self:unix_stream_socket` allow rules in TEGenerator, not macro calls. The `MacroLookup.suggest_macro()` returns `None` for this intent type.

- [ ] **Step 5: Run test**

Run: `pytest tests/analyzer/test_socket_types.py -v`
Expected: PASS

- [ ] **Step 6: Test with mcstransd**

Run: `sepgen analyze testing/mcstrans/src/mcstransd.c --name setrans -v | grep -E "(unix|tcp)"`
Expected: See unix_stream_socket, NOT corenet_tcp_bind

- [ ] **Step 7: Commit**

```bash
git add sepgen/analyzer/c_analyzer.py sepgen/intent/rules.py tests/analyzer/test_socket_types.py
git commit -m "fix: distinguish PF_UNIX vs AF_INET sockets for correct rule generation"
```

---

### Task 6: Multi-File Directory Analysis

**Files:**
- Modify: `sepgen/cli.py` (change analyze to accept directory)
- Modify: `sepgen/analyzer/c_analyzer.py`
- Create: `tests/integration/test_multi_file_analysis.py`

- [ ] **Step 1: Write failing test**

```python
def test_analyze_directory(tmp_path):
    # Create multi-file project
    (tmp_path / "main.c").write_text('int main() { fopen("/etc/app.conf", "r"); }')
    (tmp_path / "network.c").write_text('void server() { socket(AF_INET, SOCK_STREAM, 0); }')
    (tmp_path / "logging.c").write_text('void log_msg() { syslog(LOG_INFO, "test"); }')

    analyzer = CAnalyzer()
    accesses = analyzer.analyze_directory(tmp_path)

    # Should aggregate all accesses
    assert len(accesses) >= 3
    access_types = [a.access_type for a in accesses]
    assert AccessType.FILE_READ in access_types
    assert AccessType.SOCKET_CREATE in access_types
    assert AccessType.SYSLOG in access_types
```

- [ ] **Step 2: Run test**

Run: `pytest tests/integration/test_multi_file_analysis.py -v`
Expected: FAIL (analyze_directory doesn't exist)

- [ ] **Step 3: Add analyze_directory method**

```python
def analyze_directory(self, dir_path: Path) -> List[Access]:
    """Analyze all .c files in directory"""
    accesses = []
    for c_file in dir_path.rglob("*.c"):
        try:
            file_accesses = self.analyze_file(c_file)
            accesses.extend(file_accesses)
        except Exception as e:
            logger.warning(f"Failed to analyze {c_file}: {e}")
    return accesses
```

- [ ] **Step 4: Update CLI run_analyze to accept directory**

In `sepgen/cli.py`, update `run_analyze()` to handle both files and directories:

```python
def run_analyze(args) -> int:
    source_path = Path(args.source_path)
    module_name = args.name or source_path.stem

    analyzer = CAnalyzer()
    if source_path.is_dir():
        accesses = analyzer.analyze_directory(source_path)
    else:
        accesses = analyzer.analyze_file(source_path)

    # Rest of pipeline unchanged...
```

- [ ] **Step 5: Run test**

Run: `pytest tests/integration/test_multi_file_analysis.py -v`
Expected: PASS

- [ ] **Step 6: Test with mcstrans directory**

Run: `sepgen analyze testing/mcstrans/src/ --name setrans -v`
Expected: Analyze all 4 .c files (mcstransd.c, mcstrans.c, mcscolor.c, mls_level.c), show aggregated results

- [ ] **Step 7: Commit P0 milestone**

```bash
git add sepgen/analyzer/c_analyzer.py sepgen/cli.py tests/integration/test_multi_file_analysis.py
git commit -m "feat: add P0 analyzer improvements (critical detection)

- Detect syslog/openlog calls → logging_send_syslog_msg
- Detect listen/accept calls for socket servers
- Resolve #define string constants
- Detect unlink/chmod file manipulation
- Distinguish PF_UNIX vs AF_INET sockets
- Multi-file directory analysis

Coverage improvement: ~8% → ~35% (estimated)"
```

---

## P1: Significant Improvement Tasks

### Task 7: Parse #include Headers for Capability Inference

**Files:**
- Create: `sepgen/analyzer/include_analyzer.py`
- Modify: `sepgen/analyzer/c_analyzer.py`
- Create: `tests/analyzer/test_include_analysis.py`

- [ ] **Step 1: Write failing test**

```python
def test_infer_from_includes():
    code = '''
    #include <syslog.h>
    #include <sys/socket.h>
    #include <sys/capability.h>
    '''
    analyzer = IncludeAnalyzer()
    capabilities = analyzer.infer_capabilities(code)

    assert "syslog" in capabilities
    assert "socket" in capabilities
    assert "capability" in capabilities
```

- [ ] **Step 2: Run test**

Run: `pytest tests/analyzer/test_include_analysis.py -v`
Expected: FAIL

- [ ] **Step 3: Create IncludeAnalyzer**

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
        includes = self.INCLUDE_PATTERN.findall(code)
        capabilities = []
        for inc in includes:
            if inc in self.CAPABILITY_MAP:
                capabilities.extend(self.CAPABILITY_MAP[inc])
        return capabilities
```

- [ ] **Step 4: Run test**

Run: `pytest tests/analyzer/test_include_analysis.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add sepgen/analyzer/include_analyzer.py tests/analyzer/test_include_analysis.py
git commit -m "feat: infer capabilities from #include headers"
```

---

### Task 8: Detect setrlimit() and cap_*() Calls

**Files:**
- Modify: `sepgen/analyzer/c_analyzer.py`
- Modify: `sepgen/models/access.py` (add CAPABILITY, PROCESS_CONTROL)
- Modify: `sepgen/intent/rules.py`
- Create: `tests/analyzer/test_capability_detection.py`

- [ ] **Step 1: Write failing test**

```python
def test_detect_setrlimit():
    code = 'setrlimit(RLIMIT_NOFILE, &rl);'
    accesses = CAnalyzer().analyze_string(code)

    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.PROCESS_CONTROL
    assert "setrlimit" in accesses[0].syscall

def test_detect_cap_calls():
    code = '''
    cap_t caps = cap_init();
    cap_set_proc(caps);
    '''
    accesses = CAnalyzer().analyze_string(code)

    cap_accesses = [a for a in accesses if a.access_type == AccessType.CAPABILITY]
    assert len(cap_accesses) == 2
```

- [ ] **Step 2: Run test**

Run: `pytest tests/analyzer/test_capability_detection.py -v`
Expected: FAIL

- [ ] **Step 3: Add detection patterns**

```python
SETRLIMIT_PATTERN = re.compile(r'\bsetrlimit\s*\(')
CAP_PATTERN = re.compile(r'\b(cap_init|cap_set_proc|cap_get_proc|cap_set_flag)\s*\(')

def _detect_setrlimit(self, code: str) -> List[Access]:
    accesses = []
    for match in self.SETRLIMIT_PATTERN.finditer(code):
        accesses.append(Access(
            access_type=AccessType.PROCESS_CONTROL,
            path="",
            syscall="setrlimit",
            details={"capability": "sys_resource"},
            source_line=code[:match.start()].count('\n') + 1
        ))
    return accesses

def _detect_capabilities(self, code: str) -> List[Access]:
    accesses = []
    for match in self.CAP_PATTERN.finditer(code):
        accesses.append(Access(
            access_type=AccessType.CAPABILITY,
            path="",
            syscall=match.group(1),
            details={},
            source_line=code[:match.start()].count('\n') + 1
        ))
    return accesses
```

- [ ] **Step 4: Add SelfCapabilityRule**

In `sepgen/intent/rules.py`:

```python
class SelfCapabilityRule(ClassificationRule):
    """Classify capability and process control operations"""
    def matches(self, access: Access) -> bool:
        return access.access_type in [AccessType.CAPABILITY, AccessType.PROCESS_CONTROL]

    def get_intent_type(self) -> IntentType:
        return IntentType.SELF_CAPABILITY
```

Add `SelfCapabilityRule()` to `DEFAULT_RULES`. The actual `self:capability` allow rules are generated by `TEGenerator` based on the `access.details["capability"]` field, not by the rule itself.

- [ ] **Step 5: Run test**

Run: `pytest tests/analyzer/test_capability_detection.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add sepgen/analyzer/c_analyzer.py sepgen/models/access.py sepgen/intent/rules.py tests/analyzer/test_capability_detection.py
git commit -m "feat: detect setrlimit() and cap_*() for self:capability rules"
```

---

### Task 9: Generate /var/run/ Types and Transitions

**Files:**
- Modify: `sepgen/selinux/type_generator.py`
- Modify: `sepgen/generator/te_generator.py`
- Create: `tests/generator/test_var_run_types.py`

- [ ] **Step 1: Write failing test**

```python
def test_generate_var_run_type():
    intents = [
        Intent(IntentType.PID_FILE, [Access(AccessType.FILE_WRITE, "/var/run/myapp.pid", "open", {})])
    ]

    generator = TEGenerator("myapp")
    policy = generator.generate(intents)

    # Should create myapp_var_run_t type
    types = [t.name for t in policy.types]
    assert "myapp_var_run_t" in types

    macros = [m.name for m in policy.macro_calls]

    # Should add files_pid_file() type declaration macro
    assert "files_pid_file" in macros

    # Should add files_pid_filetrans() for auto-labeling
    assert "files_pid_filetrans" in macros

    # Should add manage_*_pattern macros so the domain can actually use the type
    assert "manage_dirs_pattern" in macros
    assert "manage_files_pattern" in macros

def test_generate_var_run_with_socket():
    """Unix socket files under /var/run need manage_sock_files_pattern"""
    intents = [
        Intent(IntentType.UNIX_SOCKET_SERVER,
               [Access(AccessType.SOCKET_BIND, "/var/run/myapp/.myapp-unix", "bind",
                       {"domain": "PF_UNIX"})],
               selinux_type="myapp_var_run_t")
    ]

    generator = TEGenerator("myapp")
    policy = generator.generate(intents)

    macros = [m.name for m in policy.macro_calls]
    assert "manage_sock_files_pattern" in macros
```

- [ ] **Step 2: Run test**

Run: `pytest tests/generator/test_var_run_types.py -v`
Expected: FAIL

- [ ] **Step 3: Update TypeGenerator**

```python
def generate_type_name(self, module_name: str, intent: Intent) -> Optional[str]:
    # Check if path is under /var/run or /run
    path = intent.accesses[0].path if intent.accesses else ""

    if path.startswith(("/var/run/", "/run/")):
        return f"{module_name}_var_run_t"

    # Existing logic...
```

- [ ] **Step 4: Update TEGenerator to add var_run_t declaration and manage macros**

```python
var_run_type = None
has_unix_socket = False

for intent in intents:
    if intent.selinux_type and "_var_run_t" in intent.selinux_type:
        var_run_type = intent.selinux_type
    if intent.intent_type == IntentType.UNIX_SOCKET_SERVER:
        has_unix_socket = True

if var_run_type:
    # Type declaration macro
    policy.add_macro("files_pid_file", [var_run_type])
    # Transition macro for auto-labeling new files in /var/run
    policy.add_macro("files_pid_filetrans", [
        f"{self.module_name}_t", var_run_type, "{{ file dir }}"
    ])
    # Manage macros — grant the domain permission to use its runtime dir
    policy.add_macro("manage_dirs_pattern", [
        f"{self.module_name}_t", var_run_type, var_run_type
    ])
    policy.add_macro("manage_files_pattern", [
        f"{self.module_name}_t", var_run_type, var_run_type
    ])
    if has_unix_socket:
        policy.add_macro("manage_sock_files_pattern", [
            f"{self.module_name}_t", var_run_type, var_run_type
        ])
```

- [ ] **Step 5: Run test**

Run: `pytest tests/generator/test_var_run_types.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add sepgen/selinux/type_generator.py sepgen/generator/te_generator.py tests/generator/test_var_run_types.py
git commit -m "feat: generate _var_run_t types for /var/run paths with file transitions"
```

---

### Task 10: Detect daemon() Call

**Files:**
- Modify: `sepgen/analyzer/c_analyzer.py`
- Modify: `sepgen/intent/rules.py`
- Create: `tests/analyzer/test_daemon_detection.py`

- [ ] **Step 1: Write failing test**

```python
def test_detect_daemon_call():
    code = 'daemon(0, 0);'
    accesses = CAnalyzer().analyze_string(code)

    daemon_access = [a for a in accesses if "daemon" in a.syscall]
    assert len(daemon_access) == 1

    intents = IntentClassifier().classify(accesses)
    # Should confirm init_daemon_domain is appropriate
    assert intents[0].intent_type == IntentType.DAEMON_PROCESS
```

- [ ] **Step 2: Run test**

Run: `pytest tests/analyzer/test_daemon_detection.py -v`
Expected: FAIL

- [ ] **Step 3: Add daemon pattern**

```python
DAEMON_PATTERN = re.compile(r'\bdaemon\s*\(')

def _detect_daemon(self, code: str) -> List[Access]:
    accesses = []
    for match in self.DAEMON_PATTERN.finditer(code):
        accesses.append(Access(
            access_type=AccessType.DAEMON,
            path="",
            syscall="daemon",
            details={},
            source_line=code[:match.start()].count('\n') + 1
        ))
    return accesses
```

- [ ] **Step 4: Run test**

Run: `pytest tests/analyzer/test_daemon_detection.py -v`
Expected: PASS

- [ ] **Step 5: Commit P1 milestone**

```bash
git add sepgen/analyzer/c_analyzer.py sepgen/intent/rules.py tests/analyzer/test_daemon_detection.py
git commit -m "feat: add P1 analyzer improvements (significant coverage)

- Parse #include headers for capability inference
- Detect setrlimit() and cap_*() calls → self:capability rules
- Generate _var_run_t types with file transitions
- Detect daemon() call for process type confirmation

Coverage improvement: ~35% → ~55% (estimated)"
```

---

## P2: Refinement Tasks

### Task 11: Variable Path Tracking (Data-Flow Analysis)

**Files:**
- Create: `sepgen/analyzer/dataflow.py`
- Modify: `sepgen/analyzer/c_analyzer.py`
- Create: `tests/analyzer/test_variable_tracking.py`

- [ ] **Step 1: Write failing test**

```python
def test_track_variable_paths():
    code = '''
    const char *config_file = "/etc/myapp.conf";
    FILE *f = fopen(config_file, "r");
    '''
    accesses = CAnalyzer().analyze_string(code)

    file_accesses = [a for a in accesses if a.access_type == AccessType.FILE_READ]
    assert len(file_accesses) == 1
    assert file_accesses[0].path == "/etc/myapp.conf"
```

- [ ] **Step 2: Run test**

Run: `pytest tests/analyzer/test_variable_tracking.py -v`
Expected: FAIL (variable not tracked)

- [ ] **Step 3: Create basic DataFlowAnalyzer**

```python
class DataFlowAnalyzer:
    VAR_ASSIGN_PATTERN = re.compile(r'(?:const\s+)?char\s*\*\s*(\w+)\s*=\s*"([^"]+)"')

    def __init__(self):
        self.string_vars: Dict[str, str] = {}

    def extract_string_assignments(self, code: str) -> Dict[str, str]:
        """Extract string variable assignments"""
        assignments = {}
        for match in self.VAR_ASSIGN_PATTERN.finditer(code):
            var_name = match.group(1)
            value = match.group(2)
            assignments[var_name] = value
        return assignments

    def resolve_variable(self, var_name: str) -> Optional[str]:
        """Resolve variable to its string value"""
        return self.string_vars.get(var_name)
```

- [ ] **Step 4: Update CAnalyzer to use dataflow**

Update `analyze_string()` to extract variable assignments before running detection:

```python
def analyze_string(self, code: str) -> List[Access]:
    # (after preprocessor expansion)
    # Extract variable assignments
    self.dataflow.string_vars = self.dataflow.extract_string_assignments(code)

    # Detection patterns now use self.dataflow to resolve variable args
    # fopen(var_name, "mode") → resolve var_name to path
```

- [ ] **Step 5: Update _detect_fopen to use dataflow**

```python
FOPEN_VAR_PATTERN = re.compile(r'\bfopen\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)')

def _detect_fopen(self, code: str, dataflow: DataFlowAnalyzer) -> List[Access]:
    accesses = []

    # Literal paths (existing)
    for match in self.FOPEN_LITERAL_PATTERN.finditer(code):
        # ... existing code

    # Variable paths (new)
    for match in self.FOPEN_VAR_PATTERN.finditer(code):
        var_name = match.group(1)
        mode = match.group(2)
        path = dataflow.resolve_variable(var_name)
        if path:
            accesses.append(Access(
                access_type=self._mode_to_access_type(mode),
                path=path,
                syscall="open",
                details={"mode": mode},
                source_line=code[:match.start()].count('\n') + 1
            ))

    return accesses
```

- [ ] **Step 6: Run test**

Run: `pytest tests/analyzer/test_variable_tracking.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add sepgen/analyzer/dataflow.py sepgen/analyzer/c_analyzer.py tests/analyzer/test_variable_tracking.py
git commit -m "feat: add variable path tracking for fopen(var, mode)"
```

---

### Task 12: Generate File Context Entries from Detected Paths

**Files:**
- Modify: `sepgen/generator/fc_generator.py`
- Create: `tests/generator/test_fc_from_analysis.py`

- [ ] **Step 1: Write failing test**

```python
def test_generate_fc_from_analyzed_paths():
    intents = [
        Intent(IntentType.CONFIG_FILE,
               [Access(AccessType.FILE_READ, "/etc/myapp.conf", "open", {})],
               selinux_type="myapp_conf_t"),
        Intent(IntentType.PID_FILE,
               [Access(AccessType.FILE_WRITE, "/var/run/myapp.pid", "open", {})],
               selinux_type="myapp_var_run_t"),
    ]

    generator = FCGenerator("myapp")
    contexts = generator.generate(intents, exec_path="/usr/bin/myapp")

    paths = [e.path for e in contexts.entries]
    assert "/usr/bin/myapp" in paths
    assert "/etc/myapp.conf" in paths
    assert "/var/run/myapp.pid" in paths

    # Check types
    conf_entry = [e for e in contexts.entries if e.path == "/etc/myapp.conf"][0]
    assert conf_entry.type == "myapp_conf_t"
```

- [ ] **Step 2: Run test**

Run: `pytest tests/generator/test_fc_from_analysis.py -v`
Expected: FAIL (file contexts not generated from intents)

- [ ] **Step 3: Update FCGenerator**

The existing `FCGenerator.generate(intents)` already iterates intents but skips non-absolute paths. Ensure the method generates entries for all absolute paths from classified intents (this should largely work already if `selinux_type` is set on intents with resolved paths):

```python
def generate(self, intents: List[Intent]) -> FileContexts:
    contexts = FileContexts()

    # Add executable context
    if self.exec_path:
        contexts.add_entry(self.exec_path, f"{self.module_name}_exec_t")

    # Add paths from classified intents
    for intent in intents:
        if not intent.selinux_type:
            continue
        for access in intent.accesses:
            if access.path and access.path.startswith("/"):
                contexts.add_entry(access.path, intent.selinux_type)

    return contexts
```

The key improvement is that with Preprocessor and DataFlowAnalyzer, more intents now have resolved absolute paths (e.g., from `#define` constants), so more `.fc` entries are generated.

- [ ] **Step 4: Add directory regex pattern generation for /var/run paths**

Paths under `/var/run/` or `/run/` that represent directories should generate regex patterns (e.g., `/run/setrans(/.*)?`) rather than just the literal file path. This matches how real `.fc` files label entire directory trees:

```python
def _path_to_fc_regex(self, path: str, selinux_type: str) -> str:
    """Convert a file path to an appropriate .fc regex.

    For /var/run/app/file → also generate /run/app(/.*)? for the parent dir.
    """
    if "_var_run_t" in selinux_type:
        # Extract the directory portion (e.g., /var/run/setrans/)
        parts = Path(path).parts
        for i, part in enumerate(parts):
            if part in ("run", "var"):
                # Find the app-specific directory
                if i + 1 < len(parts) and parts[i+1] != "run":
                    dir_path = "/".join(parts[:i+2])
                    return f"{dir_path}(/.*)?"
                elif i + 2 < len(parts):
                    dir_path = "/".join(parts[:i+3])
                    return f"{dir_path}(/.*)?"
    return re.escape(path).replace(r"\.", "\\.")
```

Add test:

```python
def test_var_run_generates_regex_pattern():
    intents = [
        Intent(IntentType.PID_FILE,
               [Access(AccessType.FILE_WRITE, "/var/run/setrans/.setrans-unix", "bind", {})],
               selinux_type="setrans_var_run_t"),
    ]
    generator = FCGenerator("setrans")
    contexts = generator.generate(intents)

    # Should have regex pattern for directory, not just the literal file
    entries = [str(e) for e in contexts.entries]
    assert any("/run/setrans(/.*)?" in e for e in entries)
```

- [ ] **Step 5: Run test**

Run: `pytest tests/generator/test_fc_from_analysis.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add sepgen/generator/fc_generator.py tests/generator/test_fc_from_analysis.py
git commit -m "feat: generate .fc entries with regex patterns for runtime directories"
```

---

### Task 13: Generate self: Allow Rules

**Files:**
- Modify: `sepgen/generator/te_generator.py`
- Modify: `sepgen/models/policy.py`
- Create: `tests/generator/test_self_rules.py`

- [ ] **Step 1: Write failing test**

```python
def test_generate_self_capability_rules():
    intents = [
        Intent(IntentType.SELF_CAPABILITY,
               [Access(AccessType.PROCESS_CONTROL, "", "setrlimit", {"capability": "sys_resource"})]),
        Intent(IntentType.UNIX_SOCKET_SERVER,
               [Access(AccessType.SOCKET_CREATE, "", "socket", {"domain": "PF_UNIX"})]),
    ]

    generator = TEGenerator("myapp")
    policy = generator.generate(intents)

    self_rules = [r for r in policy.allow_rules if r.target == "self"]
    assert len(self_rules) >= 3  # capability + process + socket

    # Check self:capability rule
    cap_rules = [r for r in self_rules if r.object_class == "capability"]
    assert len(cap_rules) == 1
    assert "sys_resource" in cap_rules[0].permissions

    # Check self:process rule (companion to capability)
    proc_rules = [r for r in self_rules if r.object_class == "process"]
    assert len(proc_rules) == 1
    assert "setrlimit" in proc_rules[0].permissions

    # Check self:unix_stream_socket rule
    socket_rules = [r for r in self_rules if "socket" in r.object_class]
    assert len(socket_rules) >= 1

def test_generate_self_process_from_cap_calls():
    intents = [
        Intent(IntentType.SELF_CAPABILITY,
               [Access(AccessType.CAPABILITY, "", "cap_set_proc", {})]),
    ]

    generator = TEGenerator("myapp")
    policy = generator.generate(intents)

    self_rules = [r for r in policy.allow_rules if r.target == "self"]
    proc_rules = [r for r in self_rules if r.object_class == "process"]
    assert len(proc_rules) == 1
    assert "getcap" in proc_rules[0].permissions
    assert "setcap" in proc_rules[0].permissions
```

- [ ] **Step 2: Run test**

Run: `pytest tests/generator/test_self_rules.py -v`
Expected: FAIL

- [ ] **Step 3: Add AllowRule generation logic**

```python
def generate(self, intents: List[Intent]) -> PolicyModule:
    policy = PolicyModule(name=self.module_name, version="1.0.0")

    # ... existing type generation

    # Generate self: rules
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

        elif intent.intent_type == IntentType.UNIX_SOCKET_SERVER:
            policy.allow_rules.append(AllowRule(
                source=f"{self.module_name}_t",
                target="self",
                object_class="unix_stream_socket",
                permissions=["create", "bind", "listen", "accept"]
            ))

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

    return policy
```

- [ ] **Step 4: Run test**

Run: `pytest tests/generator/test_self_rules.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add sepgen/generator/te_generator.py sepgen/models/policy.py tests/generator/test_self_rules.py
git commit -m "feat: generate self: allow rules for capabilities and sockets"
```

---

### Task 14: Service File Detection

**Files:**
- Create: `sepgen/analyzer/service_detector.py`
- Modify: `sepgen/cli.py`
- Create: `tests/analyzer/test_service_detection.py`

- [ ] **Step 1: Write failing test**

```python
def test_detect_systemd_service(tmp_path):
    # Create service file
    (tmp_path / "myapp.service").write_text('''
    [Unit]
    Description=My App

    [Service]
    ExecStart=/usr/bin/myapp
    ''')

    detector = ServiceDetector()
    service_info = detector.detect_service_files(tmp_path)

    assert service_info.has_systemd_service
    assert service_info.exec_path == "/usr/bin/myapp"

def test_detect_init_script(tmp_path):
    (tmp_path / "myapp.init").write_text('#!/bin/bash\n# init script')

    detector = ServiceDetector()
    service_info = detector.detect_service_files(tmp_path)

    assert service_info.has_init_script
    assert service_info.needs_initrc_exec_t
```

- [ ] **Step 2: Run test**

Run: `pytest tests/analyzer/test_service_detection.py -v`
Expected: FAIL

- [ ] **Step 3: Create ServiceDetector**

```python
@dataclass
class ServiceInfo:
    has_systemd_service: bool = False
    has_init_script: bool = False
    exec_path: Optional[str] = None
    needs_initrc_exec_t: bool = False

class ServiceDetector:
    EXEC_START_PATTERN = re.compile(r'ExecStart=([^\s]+)')

    def detect_service_files(self, project_dir: Path) -> ServiceInfo:
        info = ServiceInfo()

        # Look for .service files
        for service_file in project_dir.rglob("*.service"):
            info.has_systemd_service = True
            content = service_file.read_text()
            match = self.EXEC_START_PATTERN.search(content)
            if match:
                info.exec_path = match.group(1)

        # Look for init scripts
        for init_file in project_dir.rglob("*.init"):
            info.has_init_script = True
            info.needs_initrc_exec_t = True

        return info
```

- [ ] **Step 4: Integrate with CLI and generators**

In `sepgen/cli.py`, update `run_analyze()` to use ServiceInfo:

```python
def run_analyze(args) -> int:
    source_path = Path(args.source_path)
    module_name = args.name or source_path.stem

    # Detect service files
    service_detector = ServiceDetector()
    project_dir = source_path if source_path.is_dir() else source_path.parent
    service_info = service_detector.detect_service_files(project_dir)

    # Use exec_path from service file if found
    exec_path = service_info.exec_path or f"/usr/bin/{module_name}"

    # ... analyze, classify, generate as before ...

    # Pass service_info to TEGenerator for initrc type
    te_gen = TEGenerator(module_name)
    policy = te_gen.generate(intents, service_info=service_info)

    # Pass exec_path to FCGenerator
    fc_gen = FCGenerator(module_name, exec_path=exec_path)
    contexts = fc_gen.generate(intents, service_info=service_info)
```

- [ ] **Step 5: Update TEGenerator to add initrc type from ServiceInfo**

```python
def generate(self, intents, service_info=None):
    policy = PolicyModule(...)
    # ... existing base types and intent processing ...

    # If init script found, add initrc type
    if service_info and service_info.needs_initrc_exec_t:
        initrc_type = f"{self.module_name}_initrc_exec_t"
        policy.add_type(initrc_type)
        policy.add_macro("init_script_file", [initrc_type])

    return policy
```

- [ ] **Step 6: Update FCGenerator to add initrc/exec file contexts**

```python
def generate(self, intents, service_info=None):
    contexts = FileContexts()

    if self.exec_path:
        contexts.add_entry(self.exec_path, f"{self.module_name}_exec_t")

    if service_info and service_info.has_init_script:
        contexts.add_entry(
            f"/etc/rc.d/init.d/{self.module_name}",
            f"{self.module_name}_initrc_exec_t"
        )

    # ... existing intent-based .fc entries ...
    return contexts
```

- [ ] **Step 7: Write test for initrc generation**

```python
def test_initrc_type_generation(tmp_path):
    (tmp_path / "myapp.init").write_text('#!/bin/bash')
    detector = ServiceDetector()
    info = detector.detect_service_files(tmp_path)

    te_gen = TEGenerator("myapp")
    policy = te_gen.generate([], service_info=info)

    types = [t.name for t in policy.types]
    assert "myapp_initrc_exec_t" in types

    macros = [m.name for m in policy.macro_calls]
    assert "init_script_file" in macros

    fc_gen = FCGenerator("myapp", exec_path="/usr/bin/myapp")
    contexts = fc_gen.generate([], service_info=info)

    paths = [e.path for e in contexts.entries]
    assert "/etc/rc.d/init.d/myapp" in paths
```

- [ ] **Step 8: Run test**

Run: `pytest tests/analyzer/test_service_detection.py -v`
Expected: PASS

- [ ] **Step 9: Commit P2 milestone**

```bash
git add sepgen/analyzer/service_detector.py sepgen/analyzer/dataflow.py sepgen/generator/fc_generator.py sepgen/generator/te_generator.py sepgen/cli.py tests/
git commit -m "feat: add P2 analyzer improvements (full refinement)

- Variable path tracking with basic data-flow analysis
- Generate .fc entries from detected file paths
- Generate self: allow rules for capabilities and sockets
- Detect service files for exec path and initrc types

Coverage improvement: ~55% → ~70% (estimated)

Complete analyzer improvement plan implemented."
```

---

### Task 15: Integration Test with mcstransd

**Files:**
- Create: `tests/integration/test_mcstransd_coverage.py`
- Create: `testing/mcstrans/COVERAGE_COMPARISON.md`

- [ ] **Step 1: Write comprehensive integration test**

```python
def test_mcstransd_coverage():
    """Test improved analyzer against mcstransd source"""
    result = subprocess.run(
        ["sepgen", "analyze", "testing/mcstrans/src/", "--name", "setrans", "-v"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0
    output = result.stdout

    # P0 improvements
    assert "logging_send_syslog_msg" in output  # syslog detection
    assert "unix_stream_socket" in output  # Unix socket distinction
    assert "/var/run/setrans/.setrans-unix" in output  # #define resolution

    # P1 improvements
    assert "self:capability sys_resource" in output  # setrlimit detection
    assert "setrans_var_run_t" in output  # /var/run type

    # P2 improvements
    # Check .fc file was generated
    fc_path = Path("setrans.fc")
    assert fc_path.exists()
    fc_content = fc_path.read_text()
    assert "/var/run/setrans" in fc_content

def test_coverage_metrics():
    """Calculate coverage improvement"""
    # Parse generated policy
    te_path = Path("setrans.te")
    te_content = te_path.read_text()

    # Count types (should be 3-4 vs original 2)
    types = re.findall(r'^type (\w+);', te_content, re.MULTILINE)
    assert len(types) >= 3

    # Count macros (should be 8-12 vs original 2)
    macros = re.findall(r'^[\w_]+\(', te_content, re.MULTILINE)
    assert len(macros) >= 8

    # Count file contexts (should be 3-4 vs original 0)
    fc_path = Path("setrans.fc")
    fc_lines = fc_path.read_text().strip().split('\n')
    assert len(fc_lines) >= 3
```

- [ ] **Step 2: Run test**

Run: `pytest tests/integration/test_mcstransd_coverage.py -v`
Expected: PASS (with improved coverage)

- [ ] **Step 3: Generate coverage comparison report**

```bash
sepgen analyze testing/mcstrans/src/ --name setrans -v > testing/mcstrans/improved_output.txt
```

Write comparison to `testing/mcstrans/COVERAGE_COMPARISON.md`:

```markdown
# Coverage Comparison: Before vs After Improvements

## Before (Initial Implementation)
- Types: 2
- Macros: 1 correct, 1 incorrect
- File contexts: 0
- Coverage: ~8-10%

## After (P0+P1+P2 Improvements)
- Types: 3-4
- Macros: 8-12
- File contexts: 3-4
- Coverage: ~60-70% (estimated)

## Detailed Improvements
[Compare line-by-line what changed]
```

- [ ] **Step 4: Commit final test**

```bash
git add tests/integration/test_mcstransd_coverage.py testing/mcstrans/COVERAGE_COMPARISON.md
git commit -m "test: add end-to-end coverage test with mcstransd

Validates all P0+P1+P2 improvements against real-world daemon."
```

---

## Execution Summary

After completing all tasks, you will have:

**P0 (Critical):**
- ✅ Syslog detection
- ✅ Socket server patterns (listen/accept)
- ✅ #define resolution
- ✅ File manipulation (unlink/chmod)
- ✅ Unix vs TCP socket distinction
- ✅ Multi-file analysis

**P1 (Significant):**
- ✅ Include header inference
- ✅ Capability detection (setrlimit/cap_*)
- ✅ /var/run type generation
- ✅ Daemon detection

**P2 (Refinement):**
- ✅ Variable path tracking
- ✅ File context generation
- ✅ Self: allow rules
- ✅ Service file detection

**Expected outcome:** Coverage improvement from ~8% to ~60-70% on real-world applications.
