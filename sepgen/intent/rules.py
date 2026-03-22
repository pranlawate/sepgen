import re
from sepgen.models.access import Access, AccessType
from sepgen.models.intent import IntentType


class ClassificationRule:
    """Base class for classification rules"""

    def matches(self, access: Access) -> bool:
        raise NotImplementedError

    def get_intent_type(self) -> IntentType:
        raise NotImplementedError

    def get_confidence(self) -> float:
        return 1.0


class VarRunRule(ClassificationRule):
    """Classify any file operation on /var/run/ or /run/ paths as PID_FILE.

    This catches unlink(), chmod(), fopen(), open() etc. on runtime state
    directories, ensuring _var_run_t type generation even when there is
    no explicit .pid file.
    """

    VAR_RUN_PATTERNS = [
        re.compile(r'^/var/run/'),
        re.compile(r'^/run/'),
    ]

    MATCHING_TYPES = [
        AccessType.FILE_UNLINK,
        AccessType.FILE_SETATTR,
        AccessType.FILE_WRITE,
        AccessType.FILE_CREATE,
        AccessType.FILE_READ,
    ]

    def matches(self, access: Access) -> bool:
        if access.access_type not in self.MATCHING_TYPES:
            return False
        return any(pattern.search(access.path) for pattern in self.VAR_RUN_PATTERNS)

    def get_intent_type(self) -> IntentType:
        return IntentType.PID_FILE


class PathPrefixRule(ClassificationRule):
    """Route file accesses by well-known path prefixes.

    Uses a table-driven approach inspired by sepolicy generate's
    path-based routing for log, tmp, data, and lib directories.
    """

    PREFIX_TABLE = [
        ("/var/log/", IntentType.LOG_FILE),
        ("/var/tmp/", IntentType.TEMP_FILE),
        ("/tmp/", IntentType.TEMP_FILE),
        ("/var/lib/", IntentType.DATA_DIR),
        ("/var/cache/", IntentType.DATA_DIR),
    ]

    FILE_TYPES = [
        AccessType.FILE_READ,
        AccessType.FILE_WRITE,
        AccessType.FILE_CREATE,
        AccessType.FILE_UNLINK,
        AccessType.FILE_SETATTR,
        AccessType.DIR_READ,
        AccessType.DIR_WRITE,
    ]

    def __init__(self):
        self._matched_intent = None

    def matches(self, access: Access) -> bool:
        if access.access_type not in self.FILE_TYPES:
            return False
        for prefix, intent_type in self.PREFIX_TABLE:
            if access.path.startswith(prefix):
                self._matched_intent = intent_type
                return True
        return False

    def get_intent_type(self) -> IntentType:
        return self._matched_intent


class PidFileRule(ClassificationRule):
    """Classify PID file accesses"""

    PID_PATTERNS = [
        re.compile(r'/var/run/.*\.pid$'),
        re.compile(r'/run/.*\.pid$'),
        re.compile(r'\.pid$'),
    ]

    def matches(self, access: Access) -> bool:
        if access.access_type not in [AccessType.FILE_WRITE, AccessType.FILE_CREATE]:
            return False
        return any(pattern.search(access.path) for pattern in self.PID_PATTERNS)

    def get_intent_type(self) -> IntentType:
        return IntentType.PID_FILE


class ConfigFileRule(ClassificationRule):
    """Classify config file accesses"""

    CONFIG_PATTERNS = [
        re.compile(r'/etc/'),
        re.compile(r'\.conf$'),
        re.compile(r'\.ini$'),
        re.compile(r'\.cfg$'),
        re.compile(r'\.yaml$'),
        re.compile(r'\.toml$'),
        re.compile(r'\.json$'),
    ]

    def matches(self, access: Access) -> bool:
        if access.access_type != AccessType.FILE_READ:
            return False
        return any(pattern.search(access.path) for pattern in self.CONFIG_PATTERNS)

    def get_intent_type(self) -> IntentType:
        return IntentType.CONFIG_FILE


class SyslogRule(ClassificationRule):
    """Classify syslog access"""

    def matches(self, access: Access) -> bool:
        if access.access_type == AccessType.SYSLOG:
            return True
        return (access.path == "/dev/log" and
                access.details.get("is_syslog", False))

    def get_intent_type(self) -> IntentType:
        return IntentType.SYSLOG


class DaemonProcessRule(ClassificationRule):
    """Classify daemon() calls — confirms init_daemon_domain is correct"""

    def matches(self, access: Access) -> bool:
        return access.access_type == AccessType.DAEMON

    def get_intent_type(self) -> IntentType:
        return IntentType.DAEMON_PROCESS


class SelfCapabilityRule(ClassificationRule):
    """Classify capability and process control operations"""

    def matches(self, access: Access) -> bool:
        return access.access_type in [AccessType.PROCESS_CONTROL, AccessType.CAPABILITY]

    def get_intent_type(self) -> IntentType:
        return IntentType.SELF_CAPABILITY


class UnixSocketRule(ClassificationRule):
    """Classify Unix domain socket server operations"""

    def matches(self, access: Access) -> bool:
        if access.access_type != AccessType.SOCKET_BIND:
            return False
        return access.details.get("domain") in ["AF_UNIX", "PF_UNIX"]

    def get_intent_type(self) -> IntentType:
        return IntentType.UNIX_SOCKET_SERVER


class UdpServerRule(ClassificationRule):
    """Classify UDP network server operations (SOCK_DGRAM + INET bind)"""

    INET_DOMAINS = ["AF_INET", "PF_INET", "AF_INET6", "PF_INET6"]

    def matches(self, access: Access) -> bool:
        if access.access_type != AccessType.SOCKET_BIND:
            return False
        if access.details.get("sock_type") != "SOCK_DGRAM":
            return False
        domain = access.details.get("domain")
        return domain in self.INET_DOMAINS if domain else False

    def get_intent_type(self) -> IntentType:
        return IntentType.UDP_NETWORK_SERVER


class NetworkServerRule(ClassificationRule):
    """Classify TCP network server operations (SOCK_STREAM + INET bind)"""

    INET_DOMAINS = ["AF_INET", "PF_INET", "AF_INET6", "PF_INET6"]

    def matches(self, access: Access) -> bool:
        if access.access_type != AccessType.SOCKET_BIND:
            return False
        sock_type = access.details.get("sock_type")
        if sock_type == "SOCK_DGRAM":
            return False
        domain = access.details.get("domain")
        if domain:
            return domain in self.INET_DOMAINS
        return False

    def get_intent_type(self) -> IntentType:
        return IntentType.NETWORK_SERVER


class ExecBinaryRule(ClassificationRule):
    """Classify exec/system/popen calls."""

    def matches(self, access: Access) -> bool:
        return access.access_type == AccessType.PROCESS_EXEC

    def get_intent_type(self) -> IntentType:
        return IntentType.EXEC_BINARY


class KernelStateRule(ClassificationRule):
    """Classify /proc/* reads as kernel state access."""

    def matches(self, access: Access) -> bool:
        if access.access_type not in (AccessType.FILE_READ, AccessType.FILE_WRITE):
            return False
        return access.path.startswith("/proc/")

    def get_intent_type(self) -> IntentType:
        return IntentType.KERNEL_STATE


class SysfsRule(ClassificationRule):
    """Classify /sys/* reads as sysfs access."""

    def matches(self, access: Access) -> bool:
        if access.access_type not in (AccessType.FILE_READ, AccessType.FILE_WRITE):
            return False
        return access.path.startswith("/sys/")

    def get_intent_type(self) -> IntentType:
        return IntentType.SYSFS_READ


class SELinuxApiRule(ClassificationRule):
    """Classify SELinux API calls."""

    def matches(self, access: Access) -> bool:
        return access.access_type == AccessType.SELINUX_API

    def get_intent_type(self) -> IntentType:
        return IntentType.SELINUX_API


class NetlinkSocketRule(ClassificationRule):
    """Classify netlink socket creation."""

    def matches(self, access: Access) -> bool:
        return access.access_type == AccessType.NETLINK_SOCKET

    def get_intent_type(self) -> IntentType:
        return IntentType.NETLINK_SOCKET


class ConfigDataRule(ClassificationRule):
    """Classify write paths extracted from config files as DATA_DIR."""

    def matches(self, access: Access) -> bool:
        if access.access_type != AccessType.FILE_WRITE:
            return False
        return access.details.get("source") == "config_file"

    def get_intent_type(self) -> IntentType:
        return IntentType.DATA_DIR


DEFAULT_RULES = [
    VarRunRule(),
    PathPrefixRule(),
    PidFileRule(),
    KernelStateRule(),
    SysfsRule(),
    ConfigFileRule(),
    SyslogRule(),
    DaemonProcessRule(),
    ExecBinaryRule(),
    SelfCapabilityRule(),
    SELinuxApiRule(),
    NetlinkSocketRule(),
    UnixSocketRule(),
    UdpServerRule(),
    NetworkServerRule(),
    ConfigDataRule(),
]
