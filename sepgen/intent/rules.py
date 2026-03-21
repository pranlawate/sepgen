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


class NetworkServerRule(ClassificationRule):
    """Classify TCP/UDP network server operations"""

    def matches(self, access: Access) -> bool:
        if access.access_type != AccessType.SOCKET_BIND:
            return False
        domain = access.details.get("domain")
        if domain:
            return domain in ["AF_INET", "PF_INET", "AF_INET6", "PF_INET6"]
        return True

    def get_intent_type(self) -> IntentType:
        return IntentType.NETWORK_SERVER


DEFAULT_RULES = [
    PidFileRule(),
    ConfigFileRule(),
    SyslogRule(),
    DaemonProcessRule(),
    SelfCapabilityRule(),
    UnixSocketRule(),
    NetworkServerRule(),
]
