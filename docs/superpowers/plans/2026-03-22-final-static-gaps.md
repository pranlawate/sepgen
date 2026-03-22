# Implementation Plan: Final Static Analysis Gaps

**Date:** 2026-03-22
**Depends on:** Tier A gaps (completed)
**Goal:** Close the last 2 achievable static analysis gaps

---

## Task 1: Device path string literal scanner
- **File:** `sepgen/analyzer/c_analyzer.py`
- Detect `"/dev/urandom"` and `"/dev/random"` as string literals anywhere
  in preprocessed code (not just in fopen/open patterns)
- Emit AccessType.FILE_READ with the device path
- Existing DeviceAccessRule classifies → DEV_RANDOM → dev_read_urand()
- **Validation:** chronyd generates dev_read_urand()

## Task 2: SHM/IPC intent classification and TE generation
- **Files:** `sepgen/models/intent.py`, `sepgen/intent/rules.py`,
  `sepgen/generator/te_generator.py`
- New IntentType.SHM_ACCESS
- New ShmRule: matches IPC_SYSV or IPC_POSIX with ipc_type=shm
- TE: allow self:shm create_shm_perms
- **Validation:** chronyd generates allow self:shm create_shm_perms
