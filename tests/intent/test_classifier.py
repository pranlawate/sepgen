import pytest
from sepgen.intent.classifier import IntentClassifier
from sepgen.models.access import Access, AccessType
from sepgen.models.intent import IntentType


def test_classify_pid_file():
    classifier = IntentClassifier()
    access = Access(access_type=AccessType.FILE_WRITE, path="/var/run/myapp.pid", syscall="open")
    intents = classifier.classify([access])
    assert len(intents) == 1
    assert intents[0].intent_type == IntentType.PID_FILE
    assert len(intents[0].accesses) == 1


def test_classify_config_file():
    classifier = IntentClassifier()
    access = Access(access_type=AccessType.FILE_READ, path="/etc/myapp/config.ini", syscall="open")
    intents = classifier.classify([access])
    assert len(intents) == 1
    assert intents[0].intent_type == IntentType.CONFIG_FILE


def test_classify_multiple_accesses():
    classifier = IntentClassifier()
    accesses = [
        Access(AccessType.FILE_READ, "/etc/app.conf", "open"),
        Access(AccessType.FILE_WRITE, "/var/run/app.pid", "open"),
        Access(AccessType.SOCKET_CONNECT, "/dev/log", "connect", {"is_syslog": True}),
    ]
    intents = classifier.classify(accesses)
    assert len(intents) == 3
    intent_types = {i.intent_type for i in intents}
    assert IntentType.CONFIG_FILE in intent_types
    assert IntentType.PID_FILE in intent_types
    assert IntentType.SYSLOG in intent_types


def test_classify_unknown_access():
    classifier = IntentClassifier()
    access = Access(access_type=AccessType.FILE_READ, path="/tmp/random_file.txt", syscall="open")
    intents = classifier.classify([access])
    assert len(intents) == 1
    assert intents[0].intent_type == IntentType.TEMP_FILE
