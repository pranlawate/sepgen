# Implementation Plan: Refine Command

**Date:** 2026-03-22
**Goal:** Add `sepgen refine` command that reads AVC denials and suggests
policy additions using avc-parser and semacro.

---

## Context

After analyze + trace, the generated policy may still be missing some
permissions discovered at runtime in enforcing mode. The refine command
reads AVC denial messages and suggests additions.

## Architecture

```
audit.log / ausearch output
    → avc-parser --json (subprocess)
    → per denial: source_type, target_type, tclass, permissions
    → semacro which source target perms --class tclass (subprocess)
    → collect macro recommendations
    → output: suggested policy lines or update existing .te
```

## Tasks

### Task 1: Refine CLI subcommand
- Add `refine` subcommand to CLI
- Arguments: `--module NAME`, `--audit-log PATH` (default: /var/log/audit/audit.log)
- Optional: `--auto` flag to auto-apply suggestions

### Task 2: AVC denial reader
- New file: `sepgen/refiner/denial_reader.py`
- Call `avc-parser --file PATH --json` via subprocess
- Parse JSON output into structured denial objects
- Filter denials by module name (source context type)

### Task 3: Macro suggestion engine
- New file: `sepgen/refiner/macro_suggester.py`
- For each denial: call `semacro which source target perms --class tclass`
- Parse output to extract macro name and interface file
- Fall back to raw `allow` rule if no macro found

### Task 4: Policy updater
- Read existing .te file
- Append new macros/rules from suggestions
- Deduplicate against existing policy
- Write updated .te (or show diff for review)

### Task 5: Test with earlyoom on VM
- Install analyze+trace policy (missing domain_read_all if trace-only)
- Run earlyoom, collect denials
- Run `sepgen refine` to fill gaps
- Verify zero denials after refinement

## Integration with avc-parser and semacro

Both tools are called via subprocess (safest integration):
- `avc-parser --file audit.log --json` → JSON with unique_denials
- `semacro which source_t target_t perms --class tclass` → macro suggestions

This keeps the tools loosely coupled and independently upgradeable.
