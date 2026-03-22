# Trace Mode Scope: Gaps Not Achievable with Static Analysis

**Date:** 2026-03-22
**Purpose:** Reference for `sepgen trace` implementation — these are policy
elements that cannot be derived from source code analysis alone.

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

## 2. Kernel-initiated or implicit operations

Operations performed by the kernel on behalf of the process, or implicit in
library behavior, with no corresponding source code pattern.

| Gap | App | Why not in source |
|-----|-----|-------------------|
| `self:netlink_selinux_socket` | dbus | Kernel creates for SELinux AVC notifications |
| `self:fifo_file rw_fifo_file_perms` | dbus, chronyd | Pipe handling is implicit in glibc/shell |
| `self:fd use` | dbus | File descriptor inheritance from init |
| `dev_read_rand()` (as distinct from urand) | chronyd | `/dev/random` vs `/dev/urandom` depends on runtime config |
| `auth_use_nsswitch()` | dbus, chronyd | NSS resolution via getpwnam/getgrnam — glibc internal |
| `dev_rw_realtime_clock()` | chronyd | `/dev/ptp*` path built dynamically from kernel ioctl |

## 3. Build system / packaging artifacts

Paths and types that come from distribution packaging, not upstream source.

| Gap | App | Why not in source |
|-----|-----|-------------------|
| `/etc/dbus-1` config path | dbus | Uses `@SYSCONFDIR_FROM_PKGDATADIR@` CMake template variable |
| `/var/lib/dbus` data path | dbus | Uses `@EXPANDED_LOCALSTATEDIR@` template variable |
| `dbusd_unit_file_t` | dbus | systemd unit file type — packaging artifact |
| `debuginfo_exec_t` | rpm | Distro-specific entry point |
| Named port types (`corenet_udp_bind_ntp_port`) | chronyd | Port number → named type is a policy convention |
| `chronyd_keys_t` for `/etc/chrony.keys` | chronyd | Key file path is configurable, not hardcoded |

## 4. Capability details not in source

Capabilities required at runtime but not expressed as CAP_* macros or
cap_from_text() calls in the source code.

| Gap | App | Reference policy |
|-----|-----|-----------------|
| `dac_read_search` | dbus, chronyd | Runtime: reading files owned by other users |
| `setpcap` | dbus | Runtime: dropping capabilities for child processes |
| `sys_nice` | chronyd | Only in reference, not in source CAP_* macros |
| `chown` | chronyd | Only in reference, not in source CAP_* macros |
| `fsetid` | chronyd | Only in reference, not in source CAP_* macros |
| `net_admin` | chronyd | Only in reference, not in source CAP_* macros |
| `capability2 block_suspend` | dbus, chronyd | Rare capability class, no standard C API |

## 5. Multi-domain / role-based policy

Architecture decisions about domain separation that cannot be inferred from
a single source tree scan.

| Gap | App | What it is |
|-----|-----|-----------|
| `chronyc_t` / `chronyc_exec_t` | chronyd | Separate client tool domain |
| `chronyd_restricted_t` | chronyd | Restricted mode daemon domain |
| `session_bus_type` / `system_bus_type` | dbus | Attribute-based domain grouping |
| `rpm_script_t` / `rpmdb_t` | rpm | Script and database domains |
| `attribute_role`, `roleattribute` | dbus | RBAC integration |

## 6. Policy-level constructs

SELinux-specific constructs with no source code equivalent.

| Gap | App | What it is |
|-----|-----|-----------|
| `dontaudit` rules | all | Suppress audit messages — prediction impossible |
| `optional_policy()` blocks | all | Cross-module dependencies at policy build time |
| `mls_*` / `mcs_*` rules | dbus, mcstransd | MLS/MCS sensitivity levels — deployment decision |
| `domain_read_all_domains_state()` | dbus | Introspecting other domains — runtime behavior |
| `typealias` | dbus, rpm | Backward compatibility names |
| `ifdef(distro_*)` blocks | rpm, dbus | Distribution-specific policy branches |

## 7. Runtime-discovered paths and access patterns

Paths and operations only observable when the application runs.

| Gap | App | What trace would reveal |
|-----|-----|------------------------|
| glibc NSS resolution paths | all | `/etc/nsswitch.conf`, `/var/lib/sss/`, LDAP |
| Dynamic library loading | all | `ld.so` cache, `/lib64/*.so` |
| Temp file creation patterns | chronyd | Actual `/tmp/` usage only at runtime |
| `tmpfs` file operations | dbus, chronyd | POSIX shared memory via `/dev/shm` |
| Config-driven socket paths | chronyd | NTP server/client socket paths from `chrony.conf` |
| D-Bus activation paths | dbus | Service files activated at runtime |
| Device node access (`/dev/ptp*`) | chronyd | PTP clock device discovered at runtime |
| Inherited file descriptors | all | FDs from init/systemd |

---

## How trace mode addresses these

`sepgen trace` uses `strace -f -e trace=file,network,ipc,process` to
observe actual syscalls. This reveals:

1. Resolved variable arguments (actual socket domains, types, paths)
2. Kernel-initiated operations (netlink, AVC)
3. Runtime config-driven paths (from chrony.conf, dbus config)
4. glibc internal operations (NSS, dynamic linking)
5. Inherited resources from init/systemd
6. Actual capability checks via prctl/capget

The trace pipeline feeds into the same Intent Classification engine,
producing additional Access objects that merge with static analysis results.
The merge strategy is "trace wins on conflicts" — trace data is more
authoritative for runtime behavior.
