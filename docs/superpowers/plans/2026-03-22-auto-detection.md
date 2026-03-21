# Auto-Detection Improvements — Implementation Plan

**Goal:** Eliminate the need for `--exec-path` by auto-detecting binary install paths, and adopt sepolicy's comprehensive symbol-to-permission mappings for richer policy generation.

**Motivation:** Studying `sepolicy generate` (in `selinux/python/sepolicy/sepolicy/generate.py`) revealed two key patterns:
1. sepolicy maps ~70+ ELF symbols to capabilities and process permissions via `nm -D`. We can apply the same mapping table to function names found in source code.
2. sepolicy uses a structured `DEFAULT_DIRS` path-prefix routing system. We can adopt this for cleaner intent classification.

**Baseline:** sepgen v1.3 — 100% of statically-detectable mcstransd policy, but requires `--exec-path` for `.fc` generation.

**Target:** sepgen v1.4 — zero required flags for the common case (`sepgen analyze ./src/ --name app` produces complete `.te` + `.fc`).

---

## Task 1: Makefile parser for exec path and install targets (P0)

**Problem:** `--exec-path` is currently required for `.fc` generation. The exec path is always present in the project's Makefile (`SBINDIR`, `BINDIR`, `PROG`, `install:` target).

**New file:** `sepgen/analyzer/makefile_parser.py`

**Design:**

```python
@dataclass
class BuildInfo:
    prog_name: Optional[str] = None      # PROG = mcstransd
    sbin_dir: str = "/usr/sbin"           # SBINDIR ?= /sbin
    bin_dir: str = "/usr/bin"             # BINDIR ?= /usr/bin
    init_script: Optional[str] = None     # INITSCRIPT = mcstrans

    @property
    def exec_path(self) -> Optional[str]:
        if self.prog_name:
            return f"{self.sbin_dir}/{self.prog_name}"
        return None

class MakefileParser:
    def parse(self, project_dir: Path) -> BuildInfo:
        """Find and parse Makefile in project tree for install paths."""
```

**Patterns to extract:**
- `PROG = mcstransd` or `PROG := mcstransd`
- `SBINDIR ?= /sbin` / `BINDIR ?= /usr/bin` / `PREFIX ?= /usr`
- `INITSCRIPT = mcstrans`
- `install:` target with `$(DESTDIR)$(SBINDIR)` references

**Fallback chain** (in CLI):
1. `--exec-path` flag (explicit override)
2. `.service` file `ExecStart=` (already implemented)
3. Makefile `SBINDIR/PROG` (this task)
4. Convention: `/usr/sbin/<module_name>` for daemons

**Test:** `tests/analyzer/test_makefile_parser.py`

---

## Task 2: Broader ServiceDetector search scope (P0)

**Problem:** When analyzing `testing/mcstrans/src/`, the ServiceDetector only searches `source_path.parent` (= `testing/mcstrans/`). But the `.service` file is inside `src/` alongside the `.c` files. The original project has it at `selinux/mcstrans/src/mcstrans.service`.

**File:** `sepgen/analyzer/service_detector.py`

**Change:** Search both the given directory AND its parent (up to 2 levels) for `.service` and `.init` files. Also search within the source directory itself.

**Updated logic:**
```python
def detect_service_files(self, project_dir: Path) -> ServiceInfo:
    search_dirs = [project_dir]
    if project_dir.parent != project_dir:
        search_dirs.append(project_dir.parent)
    for search_dir in search_dirs:
        for service_file in search_dir.rglob("*.service"):
            ...
```

**Test:** Update `tests/analyzer/test_service_detection.py`

---

## Task 3: Unified project scanner (P1)

**Problem:** CLI currently calls `CAnalyzer`, `ServiceDetector` separately, and now will also need `MakefileParser`. These should be orchestrated by a single component.

**New file:** `sepgen/analyzer/project_scanner.py`

**Design:**

```python
@dataclass
class ProjectInfo:
    """Aggregated project metadata from all scanners."""
    accesses: List[Access]              # From CAnalyzer
    service_info: ServiceInfo           # From ServiceDetector
    build_info: BuildInfo               # From MakefileParser
    exec_path: Optional[str] = None     # Resolved exec path

class ProjectScanner:
    def scan(self, source_path: Path, module_name: str) -> ProjectInfo:
        """Run all analyzers and resolve exec_path via fallback chain."""
```

The fallback chain for `exec_path`:
1. `.service` file `ExecStart=`
2. Makefile `SBINDIR/PROG`
3. Convention `/usr/sbin/<module_name>`

**CLI simplification:** `run_analyze` delegates to `ProjectScanner.scan()` instead of calling each component manually.

**Test:** `tests/analyzer/test_project_scanner.py`

---

## Task 4: Adopt sepolicy's symbol-to-permission mappings (P1)

**Problem:** Our C analyzer detects ~15 function patterns. sepolicy maps ~70+ symbols to capabilities and process permissions. We should adopt this mapping for source-level function detection.

**File:** `sepgen/analyzer/c_analyzer.py`

**Change:** Add a `SYMBOL_MAP` dict (derived from sepolicy's `self.symbols`) that maps C function name prefixes to `Access` objects. Scan source code for these function calls.

**Key new mappings (from sepolicy):**

| Function prefix | Maps to |
|----------------|---------|
| `setgid`, `setegid`, `setresgid`, `setregid` | `capability('setgid')` |
| `setuid`, `seteuid`, `setreuid`, `setresuid` | `capability('setuid')` |
| `chown` | `capability('chown')` |
| `chroot` | `capability('sys_chroot')` |
| `mount`, `unshare` | `capability('sys_admin')` |
| `mknod` | `capability('mknod')` |
| `fork` | `process('fork')` |
| `kill` | `process('signal_perms')` |
| `dbus_` | `use_dbus` flag |
| `pam_` | `use_pam` flag |
| `gethostby`, `getaddrinfo` | `use_resolve` flag |
| `getpwnam`, `getpwuid` | `use_uid` flag (auth_use_nsswitch) |

**Approach:** Create a `SymbolScanner` class with the mapping table. For each entry, compile a regex `r'\b<prefix>\w*\s*\('` and scan source. Emit appropriate `Access` objects.

**Test:** `tests/analyzer/test_symbol_scanner.py`

---

## Task 5: Path-prefix routing for intent classification (P2)

**Problem:** Our classification rules are individual classes (VarRunRule, PidFileRule, ConfigFileRule). sepolicy uses a `DEFAULT_DIRS` prefix table that cleanly maps path prefixes to template modules. We should adopt this pattern.

**File:** `sepgen/intent/rules.py`

**Change:** Add a `PathPrefixRule` that uses a table-driven approach:

```python
PATH_PREFIX_MAP = {
    "/var/run/": IntentType.PID_FILE,
    "/run/": IntentType.PID_FILE,
    "/etc/": IntentType.CONFIG_FILE,
    "/var/lib/": IntentType.DATA_DIR,
    "/var/log/": IntentType.LOG_FILE,
    "/tmp/": IntentType.TEMP_FILE,
    "/var/cache/": IntentType.CACHE_DIR,
}
```

This replaces `VarRunRule`, `PidFileRule`, `ConfigFileRule` with a single table-driven rule. The existing specific rules become fallbacks for non-path-based classification.

**New IntentTypes needed:** `CACHE_DIR`, `LOG_FILE` (if not already present), `TEMP_FILE`.

**Test:** `tests/intent/test_path_prefix_rule.py`

---

## Task 6: Copy testing fixtures with full project structure (P0)

**Problem:** Our `testing/mcstrans/src/` only has `.c` and `.h` files. The Makefile and `.service` file are missing, so auto-detection can't work without `--exec-path`.

**Change:** Copy `mcstrans.service`, `mcstrans.init` (if exists), and `Makefile` from the original selinux tree into `testing/mcstrans/src/` so auto-detection has the data it needs.

**No code change** — just update the test fixture.

---

## Execution Order

1. **Task 6** — Copy test fixtures (unblocks testing)
2. **Task 2** — Broader ServiceDetector search (quick fix)
3. **Task 1** — MakefileParser (new component)
4. **Task 3** — ProjectScanner (orchestrator + CLI simplification)
5. **Task 4** — Symbol-to-permission mappings (enrichment)
6. **Task 5** — Path-prefix routing (refactor)

After each task: run tests, verify mcstransd works without `--exec-path`.

---

## Validation

After all tasks:
```bash
# Should produce complete .te + .fc without --exec-path
sepgen analyze testing/mcstrans/src/ --name setrans -vv
```

Expected: identical output to current `--exec-path /usr/sbin/mcstransd` run.
