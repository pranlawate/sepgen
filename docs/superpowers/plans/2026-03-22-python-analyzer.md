# Implementation Plan: Python Source Analyzer

**Date:** 2026-03-22
**Goal:** Analyze Python source code to generate SELinux policy predictions,
complementing trace mode for Python applications like snapm.

---

## Context

Python apps can't use the C/C++ analyzer (regex on fopen/socket/etc.).
Trace mode works but requires running the app first. A Python analyzer
predicts policy from source before execution, catching:
- subprocess.run/Popen commands (exec needs)
- open()/os.open()/Path.read_text() file paths
- dbus.SystemBus() D-Bus client access
- os.setuid/setgid/chroot capability needs
- syslog module usage
- String constant paths (/etc/*, /var/*, /proc/*)

## Approach: AST + regex hybrid

Python's `ast` module parses source reliably. Use AST for:
- subprocess calls with command lists
- open() with path and mode arguments
- os.open() with path and flags
- Variable tracking for path constants

Use regex for:
- Import detection (dbus, syslog, socket)
- Simple literal path extraction

## Tasks

### Task 1: PythonAnalyzer skeleton
- **New file:** `sepgen/analyzer/python_analyzer.py`
- Class `PythonAnalyzer` with `analyze_file(path)` and `analyze_directory(dir)`
- Scans `*.py` files, skipping `test*` directories
- Returns `List[Access]` (same as CAnalyzer)

### Task 2: Subprocess command detection
- Parse `subprocess.run([cmd, ...])`, `subprocess.call(...)`,
  `subprocess.Popen(...)`, `subprocess.check_call(...)`
- Extract first element of command list as executable name
- Emit PROCESS_EXEC with path = executable path/name
- Handle: `["blkid", ...]`, `[_LVM_CMD, ...]`, string variables

### Task 3: File open detection
- `open("path", "r/w/a")` → FILE_READ / FILE_WRITE
- `os.open(path, flags)` → FILE_READ / FILE_WRITE / FILE_CREATE
- `Path(path).read_text()` → FILE_READ
- `Path(path).write_text()` → FILE_WRITE
- Track string constant assignments for variable resolution

### Task 4: D-Bus client detection
- `import dbus` or `from dbus import SystemBus`
- `dbus.SystemBus()` / `dbus.SessionBus()` calls
- `import dasbus` / `from dasbus.connection import SystemMessageBus`
- Emit DBUS_CLIENT intent (reuse existing)

### Task 5: Syslog and capability detection
- `import syslog` → SYSLOG
- `logging.handlers.SysLogHandler` → SYSLOG
- `os.setuid()` → CAPABILITY(setuid)
- `os.setgid()` → CAPABILITY(setgid)
- `os.chroot()` → CAPABILITY(sys_chroot)
- `os.kill()` → CAPABILITY(kill)

### Task 6: Path constant extraction
- Scan for string literals matching /etc/*, /var/*, /proc/*, /sys/*, /run/*
- Track module-level constant assignments: `_PATH = "/etc/snapm"`
- Emit FILE_READ for /etc paths, FILE_WRITE for /var/run paths

### Task 7: Wire into ProjectScanner
- Detect Python projects (has *.py files, no *.c files, or has setup.py/pyproject.toml)
- Use PythonAnalyzer instead of CAnalyzer for Python projects
- Or use both for mixed-language projects

### Task 8: Test with snapm
- Run analyze on snapm source
- Compare with trace-only results
- Verify that analyze catches subprocess commands trace showed

## Execution order

1. Task 1 (skeleton)
2. Tasks 2, 3 (core: subprocess + file open — biggest value)
3. Tasks 4, 5 (dbus + capabilities)
4. Task 6 (path constants)
5. Tasks 7, 8 (integration + validation)

## Validation

Compare against snapm trace results:
- subprocess: blkid, lvm, dmsetup, lvs should be detected
- paths: /proc/mounts, /proc/devices, /etc/snapm, /run/snapm should be detected
- dbus: dbus.SystemBus() should trigger dbus_system_bus_client
