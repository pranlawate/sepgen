from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.intent.classifier import IntentClassifier
from sepgen.models.access import Access, AccessType
from sepgen.models.intent import IntentType


def test_detect_daemon_call():
    code = 'daemon(0, 0);'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    daemon_accesses = [a for a in accesses if a.access_type == AccessType.DAEMON]
    assert len(daemon_accesses) == 1
    assert daemon_accesses[0].syscall == "daemon"


def test_daemon_classifies_as_daemon_process():
    classifier = IntentClassifier()
    accesses = [Access(AccessType.DAEMON, "", "daemon", {})]
    intents = classifier.classify(accesses)

    daemon_intents = [i for i in intents if i.intent_type == IntentType.DAEMON_PROCESS]
    assert len(daemon_intents) == 1
