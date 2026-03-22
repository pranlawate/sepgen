# Trace Mode Scope: Gaps Not Achievable with Static Analysis

**Date:** 2026-03-22
**Status:** Final — validated against 6 test apps (testprog, testprog-net,
mcstransd, chronyd, dbus, vsftpd) with zero remaining static analysis gaps.

**Purpose:** Reference for `sepgen trace` implementation — these are policy
elements that cannot be derived from source code analysis alone.

---

## Static analysis final coverage

Before listing what trace mode needs to address, here's what static analysis
achieves across the 6 test apps:

| Capability | Coverage |
|-----------|----------|
| Types generated | Base types, conf_t, var_run_t, data_t, log_t, tmp_t, port_t, initrc_exec_t |
| Macros generated | init_daemon_domain, files_config_file, files_pid_file/filetrans, manage_*_pattern, logging_*, can_exec, corecmd_search_bin, corenet_tcp_*, corenet_udp_*, selinux_compute_access_vector, seutil_read_config, kernel_read_system_state, dev_read_urand, dev_read_sysfs, init_script_file |
| self: rules | capability (setuid, setgid, chown, kill, sys_chroot, sys_time, sys_resource, net_bind_service, net_raw, ipc_lock, audit_write, dac_override), process (setrlimit, getcap, setcap, signal_perms), unix_stream_socket, unix_dgram_socket, tcp_socket, udp_socket, netlink_selinux_socket, shm |
| .fc entries | exec_t, var_run_t, data_t, log_t, initrc_exec_t (with /var/run + /run aliases) |
| Detection patterns | 25+ regex patterns, 40+ symbol mappings, CAP_* macros, cap_from_text, wrapper socket detection, device path scanning, systemd directory directives, CapabilityBoundingSet, directive-path + KEY=VALUE + XML config parsing |

---

## 1. Variable-based syscall arguments

Static regex analysis cannot resolve arguments passed through variables,
expressions, or function parameters. Tree-sitter AST parsing with data-flow
tracking would partially address this, but full resolution requires runtime
observation.

| Gap | App | Source pattern |
|-----|-----|---------------|
| `self:udp_socket create_socket_perms` | chronyd | `socket(domain, type \| get_open_flags(flags), 0)` — domain and type are parameters |
| UDP `corenet_udp_*` macros | chronyd | Same variable-based socket calls |
| Missing socket binds (domain=None) | chronyd | 7 bind() calls with no resolvable socket domain |
| `self:netlink_route_socket` | chronyc | Created via library internals, not explicit in source |

**What trace reveals:** Actual `socket(2)` syscall arguments visible in strace
output as resolved integers (e.g., `socket(AF_INET, SOCK_DGRAM, 0) = 5`).

## 2. Kernel-initiated or implicit operations

Operations performed by the kernel on behalf of the process, or implicit in
library behavior, with no corresponding source code pattern.

| Gap | App | Why not in source |
|-----|-----|-------------------|
| `self:netlink_selinux_socket` | dbus | Kernel creates for SELinux AVC notifications |
| `self:fifo_file rw_fifo_file_perms` | dbus, chronyd, vsftpd | Pipe handling is implicit in glibc/shell |
| `self:fd use` | dbus | File descriptor inheritance from init |
| `dev_read_rand()` (as distinct from urand) | chronyd | `/dev/random` vs `/dev/urandom` depends on runtime config |
| `auth_use_nsswitch()` | dbus, chronyd, vsftpd | NSS resolution via getpwnam/getgrnam — glibc internal |
| `dev_rw_realtime_clock()` | chronyd | `/dev/ptp*` path built dynamically from kernel ioctl |
| `self:key manage_key_perms` | vsftpd | Kernel keyring operations — no explicit C API call |

**What trace reveals:** strace captures kernel-initiated syscalls, inherited
file descriptors, and glibc-internal operations that have no source code
representation.

## 3. Build system / packaging artifacts

Paths and types that come from distribution packaging, not upstream source.

| Gap | App | Why not in source |
|-----|-----|-------------------|
| `/etc/dbus-1` config path | dbus | Uses `@SYSCONFDIR_FROM_PKGDATADIR@` CMake template variable |
| `/var/lib/dbus` data path | dbus | Uses `@EXPANDED_LOCALSTATEDIR@` CMake template variable |
| `/etc/vsftpd.conf` → `ftpd_etc_t` | vsftpd | Config path not hardcoded in C source |
| `dbusd_unit_file_t` | dbus | systemd unit file type — packaging artifact |
| `ftpd_unit_file_t` | vsftpd | systemd unit file type — packaging artifact |
| Named port types (`corenet_udp_bind_ntp_port`) | chronyd | Port number → named type is a policy convention |
| `chronyd_keys_t` for `/etc/chrony.keys` | chronyd | Key file path is configurable, not hardcoded |
| `ftpd_keytab_t` | vsftpd | Kerberos keytab path — deployment specific |
| `ftpd_lock_t` | vsftpd | Lock file path from runtime convention |
| Exec path in `/usr/bin` vs `/usr/sbin` | vsftpd | Makefile says `/usr/sbin`, distro installs to `/usr/bin` |

**What trace reveals:** Actual file paths accessed at runtime, resolved from
config files, environment variables, and distro-specific conventions.

## 4. Capability details not in source

Capabilities required at runtime but not expressed as CAP_* macros or
cap_from_text() calls in the source code.

| Gap | App | Reference policy |
|-----|-----|-----------------|
| `dac_read_search` | dbus, chronyd, vsftpd | Runtime: reading files owned by other users |
| `dac_override` | chronyd, vsftpd | Runtime: writing files regardless of DAC permissions |
| `setpcap` | dbus | Runtime: dropping capabilities for child processes |
| `sys_nice` | chronyd, vsftpd | Only in reference, not in source CAP_* macros |
| `fowner` | chronyd, vsftpd | Only in reference, not in source CAP_* macros |
| `fsetid` | chronyd, vsftpd | Only in reference, not in source CAP_* macros |
| `net_admin` | chronyd | Only in reference, not in source CAP_* macros |
| `sys_admin` | vsftpd | Only in reference, not in source CAP_* macros |
| `ipc_lock` | vsftpd | In reference but not detected via CAP_* in source |
| `capability2 block_suspend` | dbus, chronyd | Rare capability class, no standard C API |

**What trace reveals:** `prctl(PR_CAPBSET_READ)`, `capget()` syscalls show
actual capability checks. Also `audit.log` denials reveal missing caps.

## 5. Multi-domain / role-based policy

Architecture decisions about domain separation that cannot be inferred from
a single source tree scan.

| Gap | App | What it is |
|-----|-----|-----------|
| `chronyc_t` / `chronyc_exec_t` | chronyd | Separate client tool domain |
| `chronyd_restricted_t` | chronyd | Restricted mode daemon domain |
| `session_bus_type` / `system_bus_type` | dbus | Attribute-based domain grouping |
| `rpm_script_t` / `rpmdb_t` | rpm | Script and database domains |
| `ftpdctl_t` / `sftpd_t` / `anon_sftpd_t` | vsftpd | Control tool, SFTP, and anonymous FTP domains |
| `attribute_role`, `roleattribute` | dbus | RBAC integration |

**What trace reveals:** Tracing multiple binaries and observing domain
transitions via `execve()` and SELinux context changes.

## 6. Policy-level constructs

SELinux-specific constructs with no source code equivalent.

| Gap | App | What it is |
|-----|-----|-----------|
| `dontaudit` rules | all | Suppress audit messages — prediction impossible |
| `optional_policy()` blocks | all | Cross-module dependencies at policy build time |
| `gen_tunable()` | vsftpd | Conditional policy based on booleans (ftpd_anon_write, ftpd_full_access, etc.) |
| `mls_*` / `mcs_*` rules | dbus, mcstransd | MLS/MCS sensitivity levels — deployment decision |
| `domain_read_all_domains_state()` | dbus | Introspecting other domains — runtime behavior |
| `typealias` | dbus, rpm | Backward compatibility names |
| `ifdef(distro_*)` blocks | rpm, dbus | Distribution-specific policy branches |

**What trace reveals:** These cannot be fully derived from trace either.
They require policy design decisions. However, trace data helps identify
which `optional_policy` blocks and tunables are actually needed.

## 7. Runtime-discovered paths and access patterns

Paths and operations only observable when the application runs.

| Gap | App | What trace would reveal |
|-----|-----|------------------------|
| glibc NSS resolution paths | all | `/etc/nsswitch.conf`, `/var/lib/sss/`, LDAP |
| Dynamic library loading | all | `ld.so` cache, `/lib64/*.so` |
| Temp file creation patterns | chronyd, vsftpd | Actual `/tmp/` usage only at runtime |
| `tmpfs` file operations | dbus, chronyd | POSIX shared memory via `/dev/shm` |
| Config-driven socket paths | chronyd | NTP server/client socket paths from `chrony.conf` |
| Config-driven data paths | vsftpd | `xferlog_file=/var/log/xferlog` from vsftpd.conf |
| D-Bus activation paths | dbus | Service files activated at runtime |
| FTP data transfer paths | vsftpd | Anonymous/local user home directories |
| Device node access (`/dev/ptp*`) | chronyd | PTP clock device discovered at runtime |
| Inherited file descriptors | all | FDs from init/systemd |
| Lock files | vsftpd | `/run/lock/subsys/*.ftpd` — runtime convention |

---

## Test applications for trace mode validation

| App | Type | Key trace-only elements to validate |
|-----|------|-----------------------------------|
| testprog | Lab daemon | Baseline — config paths, PID file, syslog at runtime |
| testprog-net | Lab TCP daemon | TCP socket args resolved, actual port binding |
| mcstransd | SELinux daemon | Netlink socket from kernel, SELinux context operations |
| chronyd | NTP daemon | UDP sockets with real args, /dev/ptp*, config-driven paths |
| dbus | IPC broker | Netlink selinux socket, config paths, multi-domain transitions |
| vsftpd | FTP daemon | chroot at runtime, config-driven paths, lock files, tunables |

---

## How trace mode addresses these

`sepgen trace` uses `strace -f -e trace=file,network,ipc,process` to
observe actual syscalls. This reveals:

1. Resolved variable arguments (actual socket domains, types, paths)
2. Kernel-initiated operations (netlink, AVC)
3. Runtime config-driven paths (from chrony.conf, vsftpd.conf, dbus config)
4. glibc internal operations (NSS, dynamic linking)
5. Inherited resources from init/systemd
6. Actual capability checks via prctl/capget
7. File lock and temp file patterns

The trace pipeline feeds into the same Intent Classification engine,
producing additional Access objects that merge with static analysis results.
The merge strategy is "trace wins on conflicts" — trace data is more
authoritative for runtime behavior.

### Recommended trace workflow

```bash
# Step 1: Generate initial policy from source
sepgen analyze ./src/ --name myapp

# Step 2: Build and install the application
make && sudo make install

# Step 3: Trace to catch runtime-only accesses
sepgen trace /usr/sbin/myapp -y

# Result: merged policy with both static and runtime coverage
```
