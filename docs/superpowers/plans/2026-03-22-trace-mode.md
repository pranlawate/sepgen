# Implementation Plan: Trace Mode

**Date:** 2026-03-22
**Depends on:** Static analysis complete
**Goal:** Make `sepgen trace` fully functional with comprehensive strace parsing

---

## Current state

The trace pipeline is already wired end-to-end in cli.py:
1. ProcessTracer.trace() → runs strace, produces output file
2. StraceParser.parse_file() → parses output into Access objects
3. IntentClassifier.classify() → same engine as analyze
4. TEGenerator/FCGenerator → generates policy
5. PolicyMerger → compares/merges with existing analyze-generated policy

**Bottleneck:** StraceParser only parses 4 syscalls (open, socket, bind INET,
connect /dev/log). Needs ~15 more for comprehensive coverage.

## Phase 1: StraceParser Enhancement (develop locally, unit-test)

### Task 1: FD tracking for socket correlation
- Track fd → (domain, sock_type) mapping from socket() calls
- When bind() is parsed, look up fd to get domain and sock_type
- This connects socket(AF_INET, SOCK_DGRAM) → bind(fd) correctly

### Task 2: Unix socket bind parsing
- Current BIND_PATTERN only matches INET (needs sin_port)
- Add pattern for: `bind(fd, {sa_family=AF_UNIX, sun_path="/path"}, len)`
- Emit SOCKET_BIND with domain=AF_UNIX, path from sun_path

### Task 3: Additional syscall patterns
- `unlink("path")` → FILE_UNLINK
- `chmod("path", mode)` / `fchmod(fd, mode)` → FILE_SETATTR
- `listen(fd, backlog)` → SOCKET_LISTEN
- `execve("path", [...])` → PROCESS_EXEC
- `shmget(key, size, flags)` / `shm_open("name", ...)` → IPC_SYSV/IPC_POSIX
- `semget(...)` / `sem_open(...)` → IPC_SYSV/IPC_POSIX
- `msgget(...)` / `mq_open(...)` → IPC_SYSV/IPC_POSIX
- `setrlimit(resource, ...)` → PROCESS_CONTROL

### Task 4: Netlink and special sockets
- `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)` → NETLINK_SOCKET
- Parse netlink protocol (NETLINK_ROUTE, NETLINK_KOBJECT_UEVENT, etc.)
  into details for potential future classification

### Task 5: Capability-related syscalls
- `prctl(PR_CAPBSET_READ, CAP_xxx)` → CAPABILITY
- `capget(...)` → detect capability checks
- Add `trace=process` to strace options in ProcessTracer

### Task 6: Deduplication
- Same path+syscall combination can appear thousands of times in trace
- Deduplicate before intent classification (same as analyze pipeline)

### Task 7: Expanded test fixture
- Update tests/fixtures/strace_output.txt with real strace output
- Add test cases for each new syscall pattern
- Test FD tracking across socket→bind pairs

## Phase 2: ProcessTracer Improvements (needs VM)

### Task 8: Error handling
- Check if strace is installed
- Handle permission denied (suggest sudo)
- Handle binary not found
- Timeout support for long-running daemons

### Task 9: Duration/signal support
- `--duration N` flag to trace for N seconds then SIGINT
- `--pid PID` attach to running process
- Graceful cleanup on Ctrl-C

## Phase 3: Integration Testing on VM

### Task 10: Compile and trace testprog on VM
- Build testprog from source on VM
- Run `sepgen trace /path/to/testprog`
- Compare trace-generated policy with analyze-generated policy
- Verify merge flow works

### Task 11: Trace a real daemon
- Trace chronyd or vsftpd on VM (already installed or installable)
- Compare trace output with analyze output
- Verify that trace fills the gaps documented in trace-mode-scope.md

## Execution order

1. Tasks 1-7 (StraceParser + tests — all local, no VM needed)
2. Tasks 8-9 (ProcessTracer — test on VM)
3. Tasks 10-11 (Integration testing on VM)
