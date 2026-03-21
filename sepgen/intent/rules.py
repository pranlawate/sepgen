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
        return (access.path == "/dev/log" and
                access.details.get("is_syslog", False))

    def get_intent_type(self) -> IntentType:
        return IntentType.SYSLOG


class NetworkServerRule(ClassificationRule):
    """Classify network server operations"""

    def matches(self, access: Access) -> bool:
        return access.access_type == AccessType.SOCKET_BIND

    def get_intent_type(self) -> IntentType:
        return IntentType.NETWORK_SERVER


DEFAULT_RULES = [
    PidFileRule(),
    ConfigFileRule(),
    SyslogRule(),
    NetworkServerRule(),
]
