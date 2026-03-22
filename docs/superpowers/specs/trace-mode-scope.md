# Trace Mode Scope: Gaps Not Achievable with Static Analysis

**Date:** 2026-03-22
**Status:** Final — validated against 7 test apps (testprog, testprog-net,
mcstransd, chronyd, dbus, vsftpd, libvirt) with zero remaining static
analysis gaps.

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
| `self:netlink_route_socket` | chronyc, libvirt | Created via library internals (virnetlink.c uses AF_NETLINK but via wrapper) |
| `self:tun_socket` | libvirt | TUN/TAP device interaction via ioctl, not socket() |
| `self:rawip_socket` | libvirt | Raw IP sockets created via variable-based calls |
| `self:packet_socket` | libvirt | AF_PACKET sockets for network bridging |
| `self:netlink_kobject_uevent_socket` | libvirt | NETLINK_KOBJECT_UEVENT in variable-based socket calls |
| `self:netlink_generic_socket` | libvirt | NETLINK_GENERIC in variable-based socket calls |

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
| `dev_rw_kvm()` | libvirt | `/dev/kvm` opened at runtime based on hypervisor availability |
| `dev_rw_vhost()` | libvirt | `/dev/vhost-net`, `/dev/vhost-vsock`, `/dev/vhost-scsi` — device passthrough |
| `dev_rw_loop_control()` | libvirt | `/dev/loop-control` for loop device management |
| `dev_read_cpuid()` | libvirt | `/dev/cpu/0/msr` for CPU feature detection |
| `dev_rw_sev()` | libvirt | `/dev/sev` for AMD SEV encrypted VMs |
| `dev_rw_vfio()` | libvirt | `/dev/vfio/*` for device passthrough |

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
| `/etc/libvirt` config directory | libvirt | Build system (meson) template variables |
| `/var/lib/libvirt` data directory | libvirt | Build system (meson) template variables |
| `/var/log/libvirt` log directory | libvirt | Build system (meson) template variables |
| `/run/libvirt` runtime directory | libvirt | Build system (meson) template variables |
| `virtd_exec_t` for `/usr/bin/libvirtd` | libvirt | Executable name from meson build, not Makefile |

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
| Device passthrough paths | libvirt | `/dev/vfio/*`, `/dev/kvm`, `/dev/sev` — hypervisor-specific |
| VM image paths | libvirt | `/var/lib/libvirt/images/*` — config-driven |
| Network bridge setup | libvirt | `AF_NETLINK` + `NETLINK_ROUTE` for bridge/tap management |
| SELinux VM labeling | libvirt | `setfilecon()`, `setexeccon()` — dynamic context transitions |

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
| libvirt | VM manager | Device nodes (/dev/kvm, /dev/vfio), netlink socket types, multi-domain transitions, MLS labels |

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

### Type architecture philosophy

sepgen generates **template types** that follow a consistent naming pattern
and get any single app confined and running:

| Template type | Purpose |
|--------------|---------|
| `{mod}_t` | Process domain |
| `{mod}_exec_t` | Executable file |
| `{mod}_conf_t` | Config files — only `{mod}_t` reads |
| `{mod}_var_run_t` | PID/socket files — only `{mod}_t` manages |
| `{mod}_data_t` | Application data — only `{mod}_t` manages |
| `{mod}_log_t` | Log files — only `{mod}_t` writes |
| `{mod}_tmp_t` | Temp files — only `{mod}_t` uses |
| `{mod}_port_t` | Network port — only `{mod}_t` binds |
| `{mod}_initrc_exec_t` | Init script |

These template types are sufficient for **single-app confinement**. Custom
types beyond this pattern (e.g., `rpm_var_lib_t` as distinct from generic
`var_lib_t`) exist to enforce **cross-domain isolation** — when one app's
data must be protected from other confined domains. For example:

- `rpm_var_lib_t` exists because yum/dnf (which transitions to `rpm_t`)
  needs access but other apps should not touch the RPM database
- `httpd_var_lib_t` exists because CGI scripts run in a different domain
  than the web server itself
- `virt_image_t` exists because VM guest images need different permissions
  than the libvirt daemon's own data

These cross-domain design decisions emerge during the **refine** phase,
not during initial policy generation.

### Complete policy development workflow

```
sepgen analyze ./src/ --name myapp     # 1. Static analysis (60-80%)
    ↓
make && sudo make install              # 2. Build and install
    ↓
sepgen trace /usr/sbin/myapp -y        # 3. Runtime trace (→ 85-90%)
    ↓
sudo semodule -i myapp.pp              # 4. Install policy
    ↓
# Test in enforcing mode               # 5. Enforcing test
    ↓
avc-parser /var/log/audit/audit.log    # 6. Analyze denials
    ↓
sepgen refine myapp.te                 # 7. Update policy from denials
    ↓                                  #    (future command)
semacro which <access pattern>         # 8. Find right macros
    ↓
# Reinstall → re-test → done          # 9. Iterate until clean
```

**Phase 1 (analyze)** generates template types from source code — gets the
app confined with correct file contexts, macros, and self: rules.

**Phase 2 (trace)** fills in runtime-only accesses — resolved socket args,
glibc internals, config-driven paths, device access. Merges with Phase 1.

**Phase 3 (refine)** handles what neither analyze nor trace can predict —
cross-domain access needs, `dontaudit` rules, optional policy blocks, and
custom types for inter-app isolation. This phase uses `avc-parser` to
understand denial patterns and `semacro` to find the right macros.

Most apps will be fully functional after Phases 1+2. Phase 3 is for
production hardening and integration with the broader system policy.
