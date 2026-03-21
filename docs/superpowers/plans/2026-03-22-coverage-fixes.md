# Coverage Fixes Implementation Plan

**Goal:** Fix 5 specific gaps identified by mcstransd comparison to reach ~100% of statically-detectable policy elements

**Baseline:** 23% overall coverage (67% of reachable elements)
**Target:** ~100% of reachable elements (~50% overall, remainder requires runtime tracing)

**Reference:** `testing/mcstrans/ANALYSIS_REPORT.md`, `testing/mcstrans/reference-policy/setrans.te`

---

## Fix 1: Cross-file syslog deduplication

**Problem:** `analyze_directory` calls `analyze_file` per file, each running `_detect_syslog` with its own `seen_functions` set. Result: 4x `logging_send_syslog_msg` instead of 1.

**Files:** `sepgen/analyzer/c_analyzer.py`

**Change:** After aggregating all accesses in `analyze_directory`, deduplicate SYSLOG accesses — keep only the first per function name.

**Test:** Update `tests/analyzer/test_directory_analysis.py` to verify syslog dedup across files.

---

## Fix 2: VarRunRule — classify unlink/chmod on /var/run/ paths

**Problem:** `PidFileRule` only matches `FILE_WRITE`/`FILE_CREATE` on `.pid` paths. The `unlink("/var/run/setrans/.setrans-unix")` and `chmod` on `/var/run/` paths fall through to UNKNOWN.

**Files:** `sepgen/intent/rules.py`

**Change:** Create `VarRunRule` that matches `FILE_UNLINK`, `FILE_SETATTR`, `FILE_WRITE`, or `FILE_CREATE` on any `/var/run/` or `/run/` path (not just `.pid`). Place it before `PidFileRule` in `DEFAULT_RULES`. Map to `IntentType.PID_FILE` (which triggers `_var_run_t` type generation).

**Test:** `tests/intent/test_var_run_rule.py`

---

## Fix 3: Infer bind path from preceding unlink on Unix sockets

**Problem:** `bind(sock, &addr, len)` can't extract the path since it's in a struct. But the C idiom `unlink(path); ... bind(...)` is standard — the unlink path IS the socket path.

**Files:** `sepgen/analyzer/c_analyzer.py`

**Change:** In `analyze_string`, after all detection runs, do a post-processing pass: if a `FILE_UNLINK` access has a `/var/run/` path and there's a `SOCKET_BIND` with `domain=PF_UNIX` and empty path, copy the unlink path to the bind access.

**Test:** `tests/analyzer/test_bind_path_inference.py`

---

## Fix 4: CLI --exec-path argument

**Problem:** `.fc` file is empty because no exec_path is provided to `FCGenerator` in the analyze command.

**Files:** `sepgen/cli.py`

**Change:** Add `--exec-path` argument to the analyze subparser. Pass it to `FCGenerator`. Also integrate `ServiceDetector` — if exec_path not provided, try to infer from `.service` files.

**Test:** `tests/test_cli.py` (update existing)

---

## Fix 5: Wire IncludeAnalyzer signal_perms into TEGenerator

**Problem:** `IncludeAnalyzer` detects `signal.h` → `signal_perms` but the result isn't used. Reference has `self:process { setrlimit getcap setcap signal_perms }`.

**Files:** `sepgen/analyzer/c_analyzer.py`, `sepgen/generator/te_generator.py`

**Change:**
1. Run `IncludeAnalyzer` in `analyze_string`, store inferred capabilities as supplementary accesses or metadata.
2. In `TEGenerator`, when building `self:process` permissions, also include `signal_perms` if the include analysis indicates `signal.h`.

Simpler approach: Add `signal_perms` detection directly — detect `#include <signal.h>` and emit a synthetic `PROCESS_CONTROL` access with `details={"process_perm": "signal_perms"}`. In TEGenerator, collect these into process_perms.

**Test:** `tests/analyzer/test_signal_perms.py`

---

## Execution Order

1. Fix 1 (syslog dedup) — standalone, no deps
2. Fix 2 (VarRunRule) — standalone, unlocks var_run_t cascade
3. Fix 3 (bind path) — depends on Fix 2 for full effect
4. Fix 4 (--exec-path) — standalone CLI change
5. Fix 5 (signal_perms) — standalone
6. Re-run mcstransd and verify coverage
